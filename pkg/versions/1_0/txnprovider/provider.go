/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnprovider

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/log"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/model"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/txnprovider/models"
)

var logger = log.New("sidetree-core-txnhandler")

// DCAS interface to access content addressable storage.
type DCAS interface {
	Read(key string) ([]byte, error)
}

type decompressionProvider interface {
	Decompress(alg string, data []byte) ([]byte, error)
}

type sourceURIFormatter func(casURI, source string) (string, error)

type options struct {
	formatCASURIForSource sourceURIFormatter
}

// Opt is an OperationProvider option.
type Opt func(ops *options)

// WithSourceCASURIFormatter sets the formatter to use when converting an alternate source to a
// CAS URI.
func WithSourceCASURIFormatter(formatter sourceURIFormatter) Opt {
	return func(ops *options) {
		ops.formatCASURIForSource = formatter
	}
}

// OperationProvider is an operation provider.
type OperationProvider struct {
	*options

	protocol.Protocol
	parser OperationParser
	cas    DCAS
	dp     decompressionProvider
}

// OperationParser defines the functions for parsing operations.
type OperationParser interface {
	ParseOperation(namespace string, operationRequest []byte, batch bool) (*model.Operation, error)
	ValidateSuffixData(suffixData *model.SuffixDataModel) error
	ValidateDelta(delta *model.DeltaModel) error
	ParseSignedDataForUpdate(compactJWS string) (*model.UpdateSignedDataModel, error)
	ParseSignedDataForDeactivate(compactJWS string) (*model.DeactivateSignedDataModel, error)
	ParseSignedDataForRecover(compactJWS string) (*model.RecoverSignedDataModel, error)
}

// NewOperationProvider returns a new operation provider.
func NewOperationProvider(p protocol.Protocol, parser OperationParser, cas DCAS,
	dp decompressionProvider, opts ...Opt) *OperationProvider {
	o := &options{
		formatCASURIForSource: func(_, _ string) (string, error) {
			return "", errors.New("CAS URI formatter not defined")
		},
	}

	for _, opt := range opts {
		opt(o)
	}

	return &OperationProvider{
		options:  o,
		Protocol: p,
		parser:   parser,
		cas:      cas,
		dp:       dp,
	}
}

// GetTxnOperations will read batch files(core/provisional index, proof files and chunk file)
// and assemble batch operations from those files.
func (h *OperationProvider) GetTxnOperations(txn *txn.SidetreeTxn) ([]*operation.AnchoredOperation, error) {
	// parse core index file URI and number of operations from anchor string
	anchorData, err := ParseAnchorData(txn.AnchorString)
	if err != nil {
		return nil, err
	}

	cif, err := h.getCoreIndexFile(anchorData.CoreIndexFileURI, txn.AlternateSources...)
	if err != nil {
		return nil, err
	}

	batchFiles, err := h.getBatchFiles(cif, txn.AlternateSources...)
	if err != nil {
		return nil, err
	}

	txnOps, err := h.assembleAnchoredOperations(batchFiles, txn)
	if err != nil {
		return nil, err
	}

	if len(txnOps) != anchorData.NumberOfOperations {
		return nil, fmt.Errorf("number of txn ops[%d] doesn't match anchor string num of ops[%d]", len(txnOps), anchorData.NumberOfOperations)
	}

	return txnOps, nil
}

// batchFiles contains the content of all batch files that are referenced in core index file.
type batchFiles struct {
	CoreIndex        *models.CoreIndexFile
	CoreProof        *models.CoreProofFile
	ProvisionalIndex *models.ProvisionalIndexFile
	ProvisionalProof *models.ProvisionalProofFile
	Chunk            *models.ChunkFile
}

type provisionalFiles struct {
	ProvisionalIndex *models.ProvisionalIndexFile
	ProvisionalProof *models.ProvisionalProofFile
	Chunk            *models.ChunkFile
}

// getBatchFiles retrieves all batch files that are referenced in core index file.
func (h *OperationProvider) getBatchFiles(cif *models.CoreIndexFile, alternateSources ...string) (*batchFiles, error) {
	var err error

	files := &batchFiles{CoreIndex: cif}

	// core proof file will not exist if we have only update operations in the batch
	if cif.CoreProofFileURI != "" {
		files.CoreProof, err = h.getCoreProofFile(cif.CoreProofFileURI, alternateSources...)
		if err != nil {
			return nil, err
		}
	}

	if cif.ProvisionalIndexFileURI != "" {
		provisionalFiles, innerErr := h.getProvisionalFiles(cif.ProvisionalIndexFileURI, alternateSources...)
		if innerErr != nil {
			return nil, innerErr
		}

		files.ProvisionalIndex = provisionalFiles.ProvisionalIndex
		files.ProvisionalProof = provisionalFiles.ProvisionalProof
		files.Chunk = provisionalFiles.Chunk
	}

	// validate batch file counts
	err = validateBatchFileCounts(files)
	if err != nil {
		return nil, err
	}

	logger.Debugf("successfully downloaded and validated all batch files")

	return files, nil
}

func (h *OperationProvider) getProvisionalFiles(provisionalIndexURI string, alternateSources ...string) (*provisionalFiles, error) {
	var err error
	files := &provisionalFiles{}

	files.ProvisionalIndex, err = h.getProvisionalIndexFile(provisionalIndexURI, alternateSources...)
	if err != nil {
		return nil, err
	}

	// provisional proof file will not exist if we don't have any update operations in the batch
	if files.ProvisionalIndex.ProvisionalProofFileURI != "" {
		files.ProvisionalProof, err = h.getProvisionalProofFile(files.ProvisionalIndex.ProvisionalProofFileURI, alternateSources...)
		if err != nil {
			return nil, err
		}
	}

	if len(files.ProvisionalIndex.Chunks) == 0 {
		return nil, errors.Errorf("provisional index file is missing chunk file URI")
	}

	chunkURI := files.ProvisionalIndex.Chunks[0].ChunkFileURI
	files.Chunk, err = h.getChunkFile(chunkURI, alternateSources...)
	if err != nil {
		return nil, err
	}

	return files, nil
}

// validateBatchFileCounts validates that operation numbers match in batch files.
func validateBatchFileCounts(batchFiles *batchFiles) error {
	coreCreateNum := 0
	coreRecoverNum := 0
	coreDeactivateNum := 0

	if batchFiles.CoreIndex.Operations != nil {
		coreCreateNum = len(batchFiles.CoreIndex.Operations.Create)
		coreRecoverNum = len(batchFiles.CoreIndex.Operations.Recover)
		coreDeactivateNum = len(batchFiles.CoreIndex.Operations.Deactivate)
	}

	if batchFiles.CoreIndex.CoreProofFileURI != "" {
		coreProofRecoverNum := len(batchFiles.CoreProof.Operations.Recover)
		coreProofDeactivateNum := len(batchFiles.CoreProof.Operations.Deactivate)

		if coreRecoverNum != coreProofRecoverNum {
			return fmt.Errorf("number of recover ops[%d] in core index doesn't match number of recover ops[%d] in core proof",
				coreRecoverNum, coreProofRecoverNum)
		}

		if coreDeactivateNum != coreProofDeactivateNum {
			return fmt.Errorf("number of deactivate ops[%d] in core index doesn't match number of deactivate ops[%d] in core proof",
				coreDeactivateNum, coreProofDeactivateNum)
		}
	}

	if batchFiles.CoreIndex.ProvisionalIndexFileURI != "" { //nolint:nestif
		provisionalUpdateNum := 0
		if batchFiles.ProvisionalIndex.Operations != nil {
			provisionalUpdateNum = len(batchFiles.ProvisionalIndex.Operations.Update)
		}

		if batchFiles.ProvisionalIndex.ProvisionalProofFileURI != "" {
			provisionalProofUpdateNum := len(batchFiles.ProvisionalProof.Operations.Update)

			if provisionalUpdateNum != provisionalProofUpdateNum {
				return fmt.Errorf("number of update ops[%d] in provisional index doesn't match number of update ops[%d] in provisional proof",
					provisionalUpdateNum, provisionalProofUpdateNum)
			}
		}

		expectedDeltaCount := coreCreateNum + coreRecoverNum + provisionalUpdateNum

		if expectedDeltaCount != len(batchFiles.Chunk.Deltas) {
			return fmt.Errorf("number of create+recover+update operations[%d] doesn't match number of deltas[%d]",
				expectedDeltaCount, len(batchFiles.Chunk.Deltas))
		}
	}

	return nil
}

func createAnchoredOperations(ops []*model.Operation) ([]*operation.AnchoredOperation, error) {
	var anchoredOps []*operation.AnchoredOperation
	for _, op := range ops {
		anchoredOp, err := model.GetAnchoredOperation(op)
		if err != nil {
			return nil, err
		}
		anchoredOps = append(anchoredOps, anchoredOp)
	}

	return anchoredOps, nil
}

func (h *OperationProvider) assembleAnchoredOperations(batchFiles *batchFiles, txn *txn.SidetreeTxn) ([]*operation.AnchoredOperation, error) { //nolint:funlen
	cifOps, err := h.parseCoreIndexOperations(batchFiles.CoreIndex, txn)
	if err != nil {
		return nil, fmt.Errorf("parse core index operations: %s", err.Error())
	}

	logger.Debugf("successfully parsed core index operations: create[%d], recover[%d], deactivate[%d]",
		len(cifOps.Create), len(cifOps.Recover), len(cifOps.Deactivate))

	// add signed data from core proof file to deactivate operations
	for i := range cifOps.Deactivate {
		cifOps.Deactivate[i].SignedData = batchFiles.CoreProof.Operations.Deactivate[i]
	}

	// deactivate operations only
	if batchFiles.CoreIndex.ProvisionalIndexFileURI == "" {
		return createAnchoredOperations(cifOps.Deactivate)
	}

	pifOps := parseProvisionalIndexOperations(batchFiles.ProvisionalIndex)

	logger.Debugf("successfully parsed provisional index operations: update[%d]", len(pifOps.Update))

	// check for duplicate suffixes for this combination core/provisional index files
	txnSuffixes := append(cifOps.Suffixes, pifOps.Suffixes...)
	err = checkForDuplicates(txnSuffixes)
	if err != nil {
		return nil, fmt.Errorf("check for duplicate suffixes in core/provisional index files: %s", err.Error())
	}

	var operations []*model.Operation
	operations = append(operations, cifOps.Create...)

	// add signed data from core proof file
	for i := range cifOps.Recover {
		cifOps.Recover[i].SignedData = batchFiles.CoreProof.Operations.Recover[i]

		// parse signed data to extract anchor origin
		signedDataModel, err := h.parser.ParseSignedDataForRecover(cifOps.Recover[i].SignedData)
		if err != nil {
			return nil, fmt.Errorf("failed to validate signed data for recover[%d]: %s", i, err.Error())
		}

		cifOps.Recover[i].AnchorOrigin = signedDataModel.AnchorOrigin
	}

	operations = append(operations, cifOps.Recover...)

	// add signed data from provisional proof file
	for i := range pifOps.Update {
		pifOps.Update[i].SignedData = batchFiles.ProvisionalProof.Operations.Update[i]
	}

	operations = append(operations, pifOps.Update...)

	if len(operations) != len(batchFiles.Chunk.Deltas) {
		// this should never happen since we are assembling batch files
		return nil, fmt.Errorf("number of create+recover+update operations[%d] doesn't match number of deltas[%d]",
			len(operations), len(batchFiles.Chunk.Deltas))
	}

	for i, delta := range batchFiles.Chunk.Deltas {
		operations[i].Delta = delta
	}

	operations = append(operations, cifOps.Deactivate...)

	return createAnchoredOperations(operations)
}

func checkForDuplicates(values []string) error {
	var duplicates []string

	valuesMap := make(map[string]bool)

	for _, val := range values {
		if _, ok := valuesMap[val]; !ok {
			valuesMap[val] = true
		} else {
			duplicates = append(duplicates, val)
		}
	}

	if len(duplicates) > 0 {
		return fmt.Errorf("duplicate values found %v", duplicates)
	}

	return nil
}

// getCoreIndexFile will download core index file from cas and parse it into core index file model.
func (h *OperationProvider) getCoreIndexFile(uri string, alternateSources ...string) (*models.CoreIndexFile, error) { //nolint:dupl
	content, err := h.readFromCAS(uri, h.MaxCoreIndexFileSize, alternateSources...)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading core index file")
	}

	logger.Debugf("successfully downloaded core index file uri[%s]: %s", uri, string(content))

	cif, err := models.ParseCoreIndexFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for core index file[%s]", uri)
	}

	err = h.validateCoreIndexFile(cif)
	if err != nil {
		return nil, errors.Wrapf(err, "core index file[%s]", uri)
	}

	return cif, nil
}

func (h *OperationProvider) validateCoreIndexFile(cif *models.CoreIndexFile) error {
	recoverNum := 0
	deactivateNum := 0

	if cif.Operations != nil {
		recoverNum = len(cif.Operations.Recover)
		deactivateNum = len(cif.Operations.Deactivate)
	}

	if recoverNum+deactivateNum > 0 && cif.CoreProofFileURI == "" {
		return errors.New("missing core proof file URI")
	}

	if recoverNum+deactivateNum == 0 && len(cif.CoreProofFileURI) > 0 {
		return errors.New("core proof file URI should be empty if there are no recover and/or deactivate operations")
	}

	err := h.validateCoreIndexCASReferences(cif)
	if err != nil {
		return err
	}

	return h.validateCoreIndexOperations(cif.Operations)
}

func (h *OperationProvider) validateCoreIndexCASReferences(cif *models.CoreIndexFile) error {
	if err := h.validateURI(cif.CoreProofFileURI); err != nil {
		return errors.Wrapf(err, "core proof URI")
	}

	if err := h.validateURI(cif.ProvisionalIndexFileURI); err != nil {
		return errors.Wrapf(err, "provisional index URI")
	}

	return nil
}

func (h *OperationProvider) validateCoreIndexOperations(ops *models.CoreOperations) error {
	if ops == nil { // nothing to do
		return nil
	}

	for i, op := range ops.Create {
		err := h.parser.ValidateSuffixData(op.SuffixData)
		if err != nil {
			return fmt.Errorf("failed to validate suffix data for create[%d]: %s", i, err.Error())
		}
	}

	for i, op := range ops.Recover {
		err := h.validateOperationReference(op)
		if err != nil {
			return fmt.Errorf("failed to validate operation reference for recover[%d]: %s", i, err.Error())
		}
	}

	for i, op := range ops.Deactivate {
		err := h.validateOperationReference(op)
		if err != nil {
			return fmt.Errorf("failed to validate operation reference for deactivate[%d]: %s", i, err.Error())
		}
	}

	return nil
}

func (h *OperationProvider) validateOperationReference(op models.OperationReference) error {
	if err := h.validateRequiredMultihash(op.DidSuffix, "did suffix"); err != nil {
		return err
	}

	return h.validateRequiredMultihash(op.RevealValue, "reveal value")
}

func (h *OperationProvider) validateRequiredMultihash(mh, alias string) error {
	if mh == "" {
		return fmt.Errorf("missing %s", alias)
	}

	if len(mh) > int(h.MaxOperationHashLength) {
		return fmt.Errorf("%s length[%d] exceeds maximum hash length[%d]", alias, len(mh), h.MaxOperationHashLength)
	}

	return nil
}

// getCoreProofFile will download core proof file from cas and parse it into core proof file model.
func (h *OperationProvider) getCoreProofFile(uri string, alternateSources ...string) (*models.CoreProofFile, error) { //nolint:dupl
	content, err := h.readFromCAS(uri, h.MaxProofFileSize, alternateSources...)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading core proof file")
	}

	logger.Debugf("successfully downloaded core proof file uri[%s]: %s", uri, string(content))

	cpf, err := models.ParseCoreProofFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for core proof file[%s]", uri)
	}

	err = h.validateCoreProofFile(cpf)
	if err != nil {
		return nil, errors.Wrapf(err, "core proof file[%s]", uri)
	}

	return cpf, nil
}

func (h *OperationProvider) validateCoreProofFile(cpf *models.CoreProofFile) error {
	for i, signedData := range cpf.Operations.Recover {
		_, err := h.parser.ParseSignedDataForRecover(signedData)
		if err != nil {
			return fmt.Errorf("failed to validate signed data for recover[%d]: %s", i, err.Error())
		}
	}

	for i, signedData := range cpf.Operations.Deactivate {
		_, err := h.parser.ParseSignedDataForDeactivate(signedData)
		if err != nil {
			return fmt.Errorf("failed to validate signed data for deactivate[%d]: %s", i, err.Error())
		}
	}

	return nil
}

// getProvisionalProofFile will download provisional proof file from cas and parse it into provisional proof file model.
func (h *OperationProvider) getProvisionalProofFile(uri string, alternateSources ...string) (*models.ProvisionalProofFile, error) { //nolint:dupl
	content, err := h.readFromCAS(uri, h.MaxProofFileSize, alternateSources...)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading provisional proof file")
	}

	logger.Debugf("successfully downloaded provisional proof file uri[%s]: %s", uri, string(content))

	ppf, err := models.ParseProvisionalProofFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for provisional proof file[%s]", uri)
	}

	err = h.validateProvisionalProofFile(ppf)
	if err != nil {
		return nil, errors.Wrapf(err, "provisional proof file[%s]", uri)
	}

	return ppf, nil
}

func (h *OperationProvider) validateProvisionalProofFile(ppf *models.ProvisionalProofFile) error {
	for i, signedData := range ppf.Operations.Update {
		_, err := h.parser.ParseSignedDataForUpdate(signedData)
		if err != nil {
			return fmt.Errorf("failed to validate signed data for update[%d]: %s", i, err.Error())
		}
	}

	return nil
}

// getProvisionalIndexFile will download provisional index file from cas and parse it into provisional index file model.
func (h *OperationProvider) getProvisionalIndexFile(uri string, alternateSources ...string) (*models.ProvisionalIndexFile, error) { //nolint:dupl
	content, err := h.readFromCAS(uri, h.MaxProvisionalIndexFileSize, alternateSources...)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading provisional index file")
	}

	logger.Debugf("successfully downloaded provisional index file uri[%s]: %s", uri, string(content))

	pif, err := models.ParseProvisionalIndexFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for provisional index file[%s]", uri)
	}

	err = h.validateProvisionalIndexFile(pif)
	if err != nil {
		return nil, errors.Wrapf(err, "provisional index file[%s]", uri)
	}

	return pif, nil
}

func (h *OperationProvider) validateProvisionalIndexFile(pif *models.ProvisionalIndexFile) error {
	updateNum := 0

	if pif.Operations != nil {
		updateNum = len(pif.Operations.Update)
	}

	if updateNum > 0 && pif.ProvisionalProofFileURI == "" {
		return errors.New("missing provisional proof file URI")
	}

	if updateNum == 0 && len(pif.ProvisionalProofFileURI) > 0 {
		return errors.New("provisional proof file URI should be empty if there are no update operations")
	}

	err := h.validateProvisionalIndexCASReferences(pif)
	if err != nil {
		return err
	}

	return h.validateProvisionalIndexOperations(pif.Operations)
}

func (h *OperationProvider) validateProvisionalIndexCASReferences(pif *models.ProvisionalIndexFile) error {
	if err := h.validateURI(pif.ProvisionalProofFileURI); err != nil {
		return errors.Wrapf(err, "provisional proof URI")
	}

	if len(pif.Chunks) > 0 {
		if err := h.validateURI(pif.Chunks[0].ChunkFileURI); err != nil {
			return errors.Wrapf(err, "chunk URI")
		}
	}

	return nil
}

func (h *OperationProvider) validateProvisionalIndexOperations(ops *models.ProvisionalOperations) error {
	if ops == nil { // nothing to do
		return nil
	}

	for i, op := range ops.Update {
		err := h.validateOperationReference(op)
		if err != nil {
			return fmt.Errorf("failed to validate operation reference for update[%d]: %s", i, err.Error())
		}
	}

	return nil
}

// getChunkFile will download chunk file from cas and parse it into chunk file model.
func (h *OperationProvider) getChunkFile(uri string, alternateSources ...string) (*models.ChunkFile, error) { //nolint:dupl
	content, err := h.readFromCAS(uri, h.MaxChunkFileSize, alternateSources...)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading chunk file")
	}

	logger.Debugf("successfully downloaded chunk file uri[%s]: %s", uri, string(content))

	cf, err := models.ParseChunkFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for chunk file[%s]", uri)
	}

	err = h.validateChunkFile(cf)
	if err != nil {
		return nil, errors.Wrapf(err, "chunk file[%s]", uri)
	}

	return cf, nil
}

func (h *OperationProvider) validateChunkFile(cf *models.ChunkFile) error {
	for i, delta := range cf.Deltas {
		err := h.parser.ValidateDelta(delta)
		if err != nil {
			return fmt.Errorf("failed to validate delta[%d]: %s", i, err.Error())
		}
	}

	return nil
}

func (h *OperationProvider) readFromCAS(uri string, maxSize uint, alternateSources ...string) ([]byte, error) {
	bytes, err := h.cas.Read(uri)
	if err != nil {
		if len(alternateSources) == 0 {
			return nil, fmt.Errorf("retrieve CAS content at uri[%s]: %w", uri, err)
		}

		logger.Infof("Failed to retrieve CAS content [%s]: %s. Trying alternate sources %s.",
			uri, err, alternateSources)

		b, e := h.readFromAlternateCASSources(uri, alternateSources)
		if e != nil {
			logger.Infof("Failed to retrieve CAS content [%s] from alternate sources %s: %s.",
				uri, alternateSources, err)

			return nil, fmt.Errorf("retrieve CAS content at uri[%s]: %w", uri, err)
		}

		logger.Infof("Successfully retrieved CAS content [%s] from alternate sources %s.",
			uri, alternateSources)

		bytes = b
	}

	if len(bytes) > int(maxSize) {
		return nil, fmt.Errorf("uri[%s]: content size %d exceeded maximum size %d", uri, len(bytes), maxSize)
	}

	content, err := h.dp.Decompress(h.CompressionAlgorithm, bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "decompress CAS uri[%s] using '%s'", uri, h.CompressionAlgorithm)
	}

	maxDecompressedSize := maxSize * h.MaxMemoryDecompressionFactor
	if len(content) > int(maxDecompressedSize) {
		return nil, fmt.Errorf("uri[%s]: decompressed content size %d exceeded maximum decompressed content size %d", uri, len(content), maxDecompressedSize)
	}

	return content, nil
}

// coreOperations contains operations in core index file.
type coreOperations struct {
	Create     []*model.Operation
	Recover    []*model.Operation
	Deactivate []*model.Operation
	Suffixes   []string
}

func (h *OperationProvider) parseCoreIndexOperations(cif *models.CoreIndexFile, txn *txn.SidetreeTxn) (*coreOperations, error) { //nolint:funlen
	if cif.Operations == nil {
		// nothing to do
		return &coreOperations{}, nil
	}

	logger.Debugf("parsing core index file operations for anchor string: %s", txn.AnchorString)

	var suffixes []string

	var createOps []*model.Operation
	for _, op := range cif.Operations.Create {
		suffix, err := model.GetUniqueSuffix(op.SuffixData, h.MultihashAlgorithms)
		if err != nil {
			return nil, err
		}

		create := &model.Operation{
			Type:         operation.TypeCreate,
			UniqueSuffix: suffix,
			SuffixData:   op.SuffixData,
			AnchorOrigin: op.SuffixData.AnchorOrigin,
		}

		suffixes = append(suffixes, suffix)
		createOps = append(createOps, create)
	}

	var recoverOps []*model.Operation
	for _, op := range cif.Operations.Recover {
		recover := &model.Operation{
			Type:         operation.TypeRecover,
			UniqueSuffix: op.DidSuffix,
			RevealValue:  op.RevealValue,
		}

		suffixes = append(suffixes, op.DidSuffix)
		recoverOps = append(recoverOps, recover)
	}

	var deactivateOps []*model.Operation
	for _, op := range cif.Operations.Deactivate {
		deactivate := &model.Operation{
			Type:         operation.TypeDeactivate,
			UniqueSuffix: op.DidSuffix,
			RevealValue:  op.RevealValue,
		}

		suffixes = append(suffixes, op.DidSuffix)
		deactivateOps = append(deactivateOps, deactivate)
	}

	err := checkForDuplicates(suffixes)
	if err != nil {
		return nil, fmt.Errorf("check for duplicate suffixes in core index files: %s", err.Error())
	}

	return &coreOperations{
		Create:     createOps,
		Recover:    recoverOps,
		Deactivate: deactivateOps,
		Suffixes:   suffixes,
	}, nil
}

// provisionalOperations contains parsed operations from provisional index file.
type provisionalOperations struct {
	Update   []*model.Operation
	Suffixes []string
}

func parseProvisionalIndexOperations(pif *models.ProvisionalIndexFile) *provisionalOperations {
	if pif.Operations == nil { // nothing to do
		return &provisionalOperations{}
	}

	var suffixes []string

	var updateOps []*model.Operation
	for _, op := range pif.Operations.Update {
		update := &model.Operation{
			Type:         operation.TypeUpdate,
			UniqueSuffix: op.DidSuffix,
			RevealValue:  op.RevealValue,
		}

		suffixes = append(suffixes, op.DidSuffix)
		updateOps = append(updateOps, update)
	}

	return &provisionalOperations{Update: updateOps, Suffixes: suffixes}
}

func (h *OperationProvider) validateURI(uri string) error {
	if len(uri) > int(h.Protocol.MaxCasURILength) {
		return fmt.Errorf("CAS URI length[%d] exceeds maximum CAS URI length[%d]", len(uri), h.Protocol.MaxCasURILength)
	}

	return nil
}

// readFromAlternateCASSources reads the URI from alternate CAS sources. The URI of the alternate source
// is composed using a provided CAS URI formatter, since the format of the URI is implementation-specific.
func (h *OperationProvider) readFromAlternateCASSources(casURI string, sources []string) ([]byte, error) {
	for _, source := range sources {
		casURIForSource, e := h.formatCASURIForSource(casURI, source)
		if e != nil {
			logger.Infof("Error formatting CAS reference for alternate source [%s]: %s", casURIForSource, e)

			continue
		}

		b, e := h.cas.Read(casURIForSource)
		if e == nil {
			logger.Debugf("Successfully retrieved CAS content from alternate source [%s]", casURIForSource)

			return b, nil
		}

		logger.Infof("Error retrieving CAS content from alternate source [%s]: %s", casURIForSource, e)
	}

	return nil, fmt.Errorf("retrieve CAS content from alternate source failed")
}
