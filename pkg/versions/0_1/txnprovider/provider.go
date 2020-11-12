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

// GetTxnOperations will read batch files(Chunk, map, anchor) and assemble batch operations from those files.
func (h *OperationProvider) GetTxnOperations(txn *txn.SidetreeTxn) ([]*operation.AnchoredOperation, error) {
	// ParseAnchorData anchor address and number of operations from anchor string
	anchorData, err := ParseAnchorData(txn.AnchorString)
	if err != nil {
		return nil, err
	}

	cif, err := h.getCoreIndexFile(anchorData.AnchorAddress)
	if err != nil {
		return nil, err
	}

	if cif.ProvisionalIndexFileURI == "" {
		// if there's no provisional index file that means that we have only deactivate operations in the batch
		return h.processDeactivateOnly(cif, txn)
	}

	batchFiles, err := h.getBatchFiles(cif)
	if err != nil {
		return nil, err
	}

	txnOps, err := h.assembleBatchOperations(batchFiles, txn)
	if err != nil {
		return nil, err
	}

	if len(txnOps) != anchorData.NumberOfOperations {
		return nil, fmt.Errorf("number of txn ops[%d] doesn't match anchor string num of ops[%d]", len(txnOps), anchorData.NumberOfOperations)
	}

	return txnOps, nil
}

func (h *OperationProvider) processDeactivateOnly(cif *models.CoreIndexFile, txn *txn.SidetreeTxn) ([]*operation.AnchoredOperation, error) {
	anchorOps, e := h.parseCoreIndexOperations(cif, txn)
	if e != nil {
		return nil, fmt.Errorf("parse anchor operations: %s", e.Error())
	}

	// deactivate operations must have signed data in core proof file
	// TODO: signed data will be used to assemble anchor operations bellow upon SIP-1 completion
	_, err := h.getCoreProofFile(cif.CoreProofFileURI)
	if err != nil {
		return nil, err
	}

	return createAnchoredOperations(anchorOps.Deactivate)
}

// batchFiles contains the content of all batch files that are referenced in core index file.
type batchFiles struct {
	CoreIndex        *models.CoreIndexFile
	ProvisionalIndex *models.ProvisionalIndexFile
	ProvisionalProof *models.ProvisionalProofFile
	CoreProof        *models.CoreProofFile
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

	files.ProvisionalIndex, err = h.getProvisionalIndexFile(cif.ProvisionalIndexFileURI)
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

	logger.Debugf("successfully downloaded batch files")

	return files, nil
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

func (h *OperationProvider) assembleBatchOperations(batchFiles *batchFiles, txn *txn.SidetreeTxn) ([]*operation.AnchoredOperation, error) {
	cifOps, err := h.parseCoreIndexOperations(batchFiles.CoreIndex, txn)
	if err != nil {
		return nil, fmt.Errorf("parse anchor operations: %s", err.Error())
	}

	logger.Debugf("successfully parsed core index operations: create[%d], recover[%d], deactivate[%d]",
		len(cifOps.Create), len(cifOps.Recover), len(cifOps.Deactivate))

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
	operations = append(operations, cifOps.Recover...)
	operations = append(operations, pifOps.Update...)

	if len(operations) != len(batchFiles.Chunk.Deltas) {
		// this should never happen since we are assembling batch files
		return nil, fmt.Errorf("number of create+recover+update operations[%d] doesn't match number of deltas[%d]",
			len(operations), len(batchFiles.Chunk.Deltas))
	}

	operations = append(operations, cifOps.Deactivate...)

	for i, delta := range batchFiles.Chunk.Deltas {
		// TODO: Evaluate whether delta should be validated here
		err = h.parser.ValidateDelta(delta)
		if err != nil {
			return nil, fmt.Errorf("validate delta: %s", err.Error())
		}

		op := operations[i]

		op.Delta = delta
	}

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
func (h *OperationProvider) getCoreIndexFile(uri string) (*models.CoreIndexFile, error) {
	content, err := h.readFromCAS(uri, h.CompressionAlgorithm, h.MaxCoreIndexFileSize)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading core index file")
	}

	cif, err := models.ParseCoreIndexFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for core index file[%s]", uri)
	}

	return cif, nil
}

// getCoreProofFile will download core proof file from cas and parse it into core proof file model.
func (h *OperationProvider) getCoreProofFile(uri string) (*models.CoreProofFile, error) {
	content, err := h.readFromCAS(uri, h.CompressionAlgorithm, h.MaxProofFileSize)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading core proof file")
	}

	logger.Debugf("successfully downloaded core proof file[%s]: %s", uri, string(content))

	cpf, err := models.ParseCoreProofFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for core proof file[%s]", uri)
	}

	return cpf, nil
}

// getProvisionalProofFile will download provisional proof file from cas and parse it into provisional proof file model.
func (h *OperationProvider) getProvisionalProofFile(uri string) (*models.ProvisionalProofFile, error) {
	content, err := h.readFromCAS(uri, h.CompressionAlgorithm, h.MaxProofFileSize)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading provisional proof file")
	}

	logger.Debugf("successfully downloaded provisional proof file[%s]: %s", uri, string(content))

	ppf, err := models.ParseProvisionalProofFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for provisional proof file[%s]", uri)
	}

	return ppf, nil
}

// getProvisionalIndexFile will download provisional index file from cas and parse it into provisional index file model.
func (h *OperationProvider) getProvisionalIndexFile(uri string) (*models.ProvisionalIndexFile, error) {
	content, err := h.readFromCAS(uri, h.CompressionAlgorithm, h.MaxProvisionalIndexFileSize)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading provisional index file")
	}

	pif, err := models.ParseProvisionalIndexFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for provisional index file[%s]", uri)
	}

	return pif, nil
}

// getChunkFile will download chunk file from cas and parse it into chunk file model.
func (h *OperationProvider) getChunkFile(uri string) (*models.ChunkFile, error) {
	content, err := h.readFromCAS(uri, h.CompressionAlgorithm, h.MaxChunkFileSize)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading chunk file")
	}

	cf, err := models.ParseChunkFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for chunk file[%s]", uri)
	}

	return cf, nil
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

// anchorOperations contains operations which are assembled from batch files.
type anchorOperations struct {
	Create     []*model.Operation
	Recover    []*model.Operation
	Deactivate []*model.Operation
	Suffixes   []string
}

func (h *OperationProvider) parseCoreIndexOperations(cif *models.CoreIndexFile, txn *txn.SidetreeTxn) (*anchorOperations, error) {
	logger.Debugf("parsing core index file operations for anchor string: %s", txn.AnchorString)

	var suffixes []string

	var createOps []*model.Operation
	for _, op := range cif.Operations.Create {
		suffix, err := hashing.CalculateModelMultihash(op.SuffixData, h.MultihashAlgorithm)
		if err != nil {
			return nil, err
		}

		err = h.parser.ValidateSuffixData(op.SuffixData)
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
			SignedData:   op.SignedData,
		}

		suffixes = append(suffixes, op.DidSuffix)
		recoverOps = append(recoverOps, recover)
	}

	var deactivateOps []*model.Operation
	for _, op := range cif.Operations.Deactivate {
		deactivate := &model.Operation{
			Type:         operation.TypeDeactivate,
			UniqueSuffix: op.DidSuffix,
			SignedData:   op.SignedData,
		}

		suffixes = append(suffixes, op.DidSuffix)
		deactivateOps = append(deactivateOps, deactivate)
	}

	return &anchorOperations{
		Create:     createOps,
		Recover:    recoverOps,
		Deactivate: deactivateOps,
		Suffixes:   suffixes,
	}, nil
}

// ProvisionalIndexOperations contains parsed operations from provisional index file.
type ProvisionalIndexOperations struct {
	Update   []*model.Operation
	Suffixes []string
}

func parseProvisionalIndexOperations(mf *models.ProvisionalIndexFile) *ProvisionalIndexOperations {
	var suffixes []string

	var updateOps []*model.Operation
	for _, op := range mf.Operations.Update {
		update := &model.Operation{
			Type:         operation.TypeUpdate,
			UniqueSuffix: op.DidSuffix,
			SignedData:   op.SignedData,
		}

		suffixes = append(suffixes, op.DidSuffix)
		updateOps = append(updateOps, update)
	}

	return &ProvisionalIndexOperations{Update: updateOps, Suffixes: suffixes}
}
