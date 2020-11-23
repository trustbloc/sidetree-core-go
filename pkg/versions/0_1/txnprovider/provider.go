/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnprovider

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/txnprovider/models"
)

var logger = log.New("sidetree-core-txnhandler")

// DCAS interface to access content addressable storage.
type DCAS interface {
	Read(key string) ([]byte, error)
}

type decompressionProvider interface {
	Decompress(alg string, data []byte) ([]byte, error)
}

// OperationProvider is an operation provider.
type OperationProvider struct {
	protocol.Protocol
	parser OperationParser
	cas    DCAS
	dp     decompressionProvider
}

// OperationParser defines the functions for parsing operations.
type OperationParser interface {
	ParseOperation(namespace string, operationBuffer []byte) (*model.Operation, error)
	ValidateSuffixData(suffixData *model.SuffixDataModel) error
	ValidateDelta(delta *model.DeltaModel) error
	ParseSignedDataForUpdate(compactJWS string) (*model.UpdateSignedDataModel, error)
	ParseSignedDataForDeactivate(compactJWS string) (*model.DeactivateSignedDataModel, error)
	ParseSignedDataForRecover(compactJWS string) (*model.RecoverSignedDataModel, error)
}

// NewOperationProvider returns a new operation provider.
func NewOperationProvider(p protocol.Protocol, parser OperationParser, cas DCAS, dp decompressionProvider) *OperationProvider {
	return &OperationProvider{
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

	cif, err := h.getCoreIndexFile(anchorData.CoreIndexFileURI)
	if err != nil {
		return nil, err
	}

	batchFiles, err := h.getBatchFiles(cif)
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
func (h *OperationProvider) getBatchFiles(cif *models.CoreIndexFile) (*batchFiles, error) {
	var err error

	files := &batchFiles{CoreIndex: cif}

	// core proof file will not exist if we have only update operations in the batch
	if cif.CoreProofFileURI != "" {
		files.CoreProof, err = h.getCoreProofFile(cif.CoreProofFileURI)
		if err != nil {
			return nil, err
		}
	}

	if cif.ProvisionalIndexFileURI != "" {
		provisionalFiles, innerErr := h.getProvisionalFiles(cif.ProvisionalIndexFileURI)
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

func (h *OperationProvider) getProvisionalFiles(provisionalIndexURI string) (*provisionalFiles, error) {
	var err error
	files := &provisionalFiles{}

	files.ProvisionalIndex, err = h.getProvisionalIndexFile(provisionalIndexURI)
	if err != nil {
		return nil, err
	}

	// provisional proof file will not exist if we don't have any update operations in the batch
	if files.ProvisionalIndex.ProvisionalProofFileURI != "" {
		files.ProvisionalProof, err = h.getProvisionalProofFile(files.ProvisionalIndex.ProvisionalProofFileURI)
		if err != nil {
			return nil, err
		}
	}

	if len(files.ProvisionalIndex.Chunks) == 0 {
		return nil, errors.Errorf("provisional index file is missing chunk file URI")
	}

	chunkURI := files.ProvisionalIndex.Chunks[0].ChunkFileURI
	files.Chunk, err = h.getChunkFile(chunkURI)
	if err != nil {
		return nil, err
	}

	return files, nil
}

// validateBatchFileCounts validates that operation numbers match in batch files.
func validateBatchFileCounts(batchFiles *batchFiles) error {
	coreCreateNum := len(batchFiles.CoreIndex.Operations.Create)
	coreRecoverNum := len(batchFiles.CoreIndex.Operations.Recover)
	coreDeactivateNum := len(batchFiles.CoreIndex.Operations.Deactivate)

	if batchFiles.CoreIndex.CoreProofFileURI != "" {
		if coreRecoverNum != len(batchFiles.CoreProof.Operations.Recover) {
			return fmt.Errorf("number of recover ops[%d] in core index doesn't match number of recover ops[%d] in core proof",
				coreRecoverNum, len(batchFiles.CoreProof.Operations.Recover))
		}

		if coreDeactivateNum != len(batchFiles.CoreProof.Operations.Deactivate) {
			return fmt.Errorf("number of deactivate ops[%d] in core index doesn't match number of deactivate ops[%d] in core proof",
				coreDeactivateNum, len(batchFiles.CoreProof.Operations.Deactivate))
		}
	}

	if batchFiles.CoreIndex.ProvisionalIndexFileURI != "" {
		provisionalUpdateNum := len(batchFiles.ProvisionalIndex.Operations.Update)

		if batchFiles.ProvisionalIndex.ProvisionalProofFileURI != "" && provisionalUpdateNum != len(batchFiles.ProvisionalProof.Operations.Update) {
			return fmt.Errorf("number of update ops[%d] in provisional index doesn't match number of update ops[%d] in provisional proof",
				provisionalUpdateNum, len(batchFiles.ProvisionalProof.Operations.Update))
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

func (h *OperationProvider) assembleAnchoredOperations(batchFiles *batchFiles, txn *txn.SidetreeTxn) ([]*operation.AnchoredOperation, error) {
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
func (h *OperationProvider) getCoreIndexFile(uri string) (*models.CoreIndexFile, error) { //nolint:dupl
	content, err := h.readFromCAS(uri, h.CompressionAlgorithm, h.MaxCoreIndexFileSize)
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

func (h *OperationProvider) validateCoreIndexFile(cif *models.CoreIndexFile) error { //nolint:gocyclo
	if len(cif.Operations.Recover)+len(cif.Operations.Deactivate) > 0 && cif.CoreProofFileURI == "" {
		return errors.New("missing core proof file URI")
	}

	if len(cif.Operations.Recover)+len(cif.Operations.Deactivate) == 0 && len(cif.CoreProofFileURI) > 0 {
		return errors.New("core proof file URI should be empty if there are no recover and/or deactivate operations")
	}

	for i, op := range cif.Operations.Create {
		err := h.parser.ValidateSuffixData(op.SuffixData)
		if err != nil {
			return fmt.Errorf("failed to validate suffix data for create[%d]: %s", i, err.Error())
		}
	}

	for i, op := range cif.Operations.Recover {
		err := validateOperationReference(op)
		if err != nil {
			return fmt.Errorf("failed to validate signed operation for recover[%d]: %s", i, err.Error())
		}
	}

	for i, op := range cif.Operations.Deactivate {
		err := validateOperationReference(op)
		if err != nil {
			return fmt.Errorf("failed to validate signed operation for deactivate[%d]: %s", i, err.Error())
		}
	}

	return nil
}

func validateOperationReference(op models.OperationReference) error {
	if op.DidSuffix == "" {
		return errors.New("missing did suffix")
	}

	if op.RevealValue == "" {
		return errors.New("missing reveal value")
	}

	return nil
}

// getCoreProofFile will download core proof file from cas and parse it into core proof file model.
func (h *OperationProvider) getCoreProofFile(uri string) (*models.CoreProofFile, error) { //nolint:dupl
	content, err := h.readFromCAS(uri, h.CompressionAlgorithm, h.MaxProofFileSize)
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
func (h *OperationProvider) getProvisionalProofFile(uri string) (*models.ProvisionalProofFile, error) { //nolint:dupl
	content, err := h.readFromCAS(uri, h.CompressionAlgorithm, h.MaxProofFileSize)
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
func (h *OperationProvider) getProvisionalIndexFile(uri string) (*models.ProvisionalIndexFile, error) { //nolint:dupl
	content, err := h.readFromCAS(uri, h.CompressionAlgorithm, h.MaxProvisionalIndexFileSize)
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
	if len(pif.Operations.Update) > 0 && pif.ProvisionalProofFileURI == "" {
		return errors.New("missing provisional proof file URI")
	}

	if len(pif.Operations.Update) == 0 && len(pif.ProvisionalProofFileURI) > 0 {
		return errors.New("provisional proof file URI should be empty if there are no update operations")
	}

	for i, op := range pif.Operations.Update {
		err := validateOperationReference(op)
		if err != nil {
			return fmt.Errorf("failed to validate signed operation for update[%d]: %s", i, err.Error())
		}
	}

	return nil
}

// getChunkFile will download chunk file from cas and parse it into chunk file model.
func (h *OperationProvider) getChunkFile(uri string) (*models.ChunkFile, error) { //nolint:dupl
	content, err := h.readFromCAS(uri, h.CompressionAlgorithm, h.MaxChunkFileSize)
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

func (h *OperationProvider) readFromCAS(uri, alg string, maxSize uint) ([]byte, error) {
	bytes, err := h.cas.Read(uri)
	if err != nil {
		return nil, errors.Wrapf(err, "retrieve CAS content at uri[%s]", uri)
	}

	if len(bytes) > int(maxSize) {
		return nil, fmt.Errorf("uri[%s]: content size %d exceeded maximum size %d", uri, len(bytes), maxSize)
	}

	content, err := h.dp.Decompress(alg, bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "decompress CAS uri[%s] using '%s'", uri, alg)
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

func (h *OperationProvider) parseCoreIndexOperations(cif *models.CoreIndexFile, txn *txn.SidetreeTxn) (*coreOperations, error) {
	logger.Debugf("parsing core index file operations for anchor string: %s", txn.AnchorString)

	var suffixes []string

	var createOps []*model.Operation
	for _, op := range cif.Operations.Create {
		suffix, err := hashing.CalculateModelMultihash(op.SuffixData, h.MultihashAlgorithm)
		if err != nil {
			return nil, err
		}

		create := &model.Operation{
			Type:         operation.TypeCreate,
			UniqueSuffix: suffix,
			SuffixData:   op.SuffixData,
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

func parseProvisionalIndexOperations(mf *models.ProvisionalIndexFile) *provisionalOperations {
	var suffixes []string

	var updateOps []*model.Operation
	for _, op := range mf.Operations.Update {
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
