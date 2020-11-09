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
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
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

	af, err := h.getAnchorFile(anchorData.AnchorAddress)
	if err != nil {
		return nil, err
	}

	if af.MapFileURI == "" {
		// if there's no map file that means that we have only deactivate operations in the batch
		return h.processDeactivateOnly(af, txn)
	}

	files, err := h.getBatchFiles(af)
	if err != nil {
		return nil, err
	}

	txnOps, err := h.assembleBatchOperations(af, files.Map, files.Chunk, txn)
	if err != nil {
		return nil, err
	}

	if len(txnOps) != anchorData.NumberOfOperations {
		return nil, fmt.Errorf("number of txn ops[%d] doesn't match anchor string num of ops[%d]", len(txnOps), anchorData.NumberOfOperations)
	}

	return txnOps, nil
}

func (h *OperationProvider) processDeactivateOnly(af *models.AnchorFile, txn *txn.SidetreeTxn) ([]*operation.AnchoredOperation, error) {
	anchorOps, e := h.parseAnchorOperations(af, txn)
	if e != nil {
		return nil, fmt.Errorf("parse anchor operations: %s", e.Error())
	}

	// deactivate operations must have signed data in core proof file
	// TODO: signed data will be used to assemble anchor operations bellow upon SIP-1 completion
	_, err := h.getCoreProofFile(af.CoreProofFileURI)
	if err != nil {
		return nil, err
	}

	return createAnchoredOperations(anchorOps.Deactivate)
}

// batchFiles contains the content of all batch files that are referenced in anchor file.
type batchFiles struct {
	Map              *models.MapFile
	ProvisionalProof *models.ProvisionalProofFile
	CoreProof        *models.CoreProofFile
	Chunk            *models.ChunkFile
}

// getBatchFiles retrieves all batch files that are referenced in anchor file.
func (h *OperationProvider) getBatchFiles(af *models.AnchorFile) (*batchFiles, error) {
	var err error

	files := &batchFiles{}

	files.Map, err = h.getMapFile(af.MapFileURI)
	if err != nil {
		return nil, err
	}

	// core proof file will not exist if we have only update operations in the batch
	if af.CoreProofFileURI != "" {
		files.CoreProof, err = h.getCoreProofFile(af.CoreProofFileURI)
		if err != nil {
			return nil, err
		}
	}

	// provisional proof file will not exist if we don't have any update operations in the batch
	if af.ProvisionalProofFileURI != "" {
		files.ProvisionalProof, err = h.getProvisionalProofFile(af.ProvisionalProofFileURI)
		if err != nil {
			return nil, err
		}
	}

	if len(files.Map.Chunks) == 0 {
		return nil, errors.Errorf("map file is missing chunk file URI")
	}

	chunkURI := files.Map.Chunks[0].ChunkFileURI
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

func (h *OperationProvider) assembleBatchOperations(af *models.AnchorFile, mf *models.MapFile, cf *models.ChunkFile, txn *txn.SidetreeTxn) ([]*operation.AnchoredOperation, error) {
	anchorOps, err := h.parseAnchorOperations(af, txn)
	if err != nil {
		return nil, fmt.Errorf("parse anchor operations: %s", err.Error())
	}

	logger.Debugf("successfully parsed anchor operations: create[%d], recover[%d], deactivate[%d]",
		len(anchorOps.Create), len(anchorOps.Recover), len(anchorOps.Deactivate))

	mapOps := parseMapOperations(mf)

	logger.Debugf("successfully parsed map operations: update[%d]", len(mapOps.Update))

	// check for duplicate suffixes for this combination anchor/map files
	txnSuffixes := append(anchorOps.Suffixes, mapOps.Suffixes...)
	err = checkForDuplicates(txnSuffixes)
	if err != nil {
		return nil, fmt.Errorf("check for duplicate suffixes in anchor/map files: %s", err.Error())
	}

	var operations []*model.Operation
	operations = append(operations, anchorOps.Create...)
	operations = append(operations, anchorOps.Recover...)
	operations = append(operations, mapOps.Update...)

	if len(operations) != len(cf.Deltas) {
		// this should never happen since we are assembling batch files
		return nil, fmt.Errorf("number of create+recover+update operations[%d] doesn't match number of deltas[%d]",
			len(operations), len(cf.Deltas))
	}

	operations = append(operations, anchorOps.Deactivate...)

	for i, delta := range cf.Deltas {
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

// getAnchorFile will download anchor file from cas and parse it into anchor file model.
func (h *OperationProvider) getAnchorFile(uri string) (*models.AnchorFile, error) {
	content, err := h.readFromCAS(uri, h.CompressionAlgorithm, h.MaxAnchorFileSize)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading anchor file")
	}

	af, err := models.ParseAnchorFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for anchor file[%s]", uri)
	}

	return af, nil
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

// getMapFile will download map file from cas and parse it into map file model.
func (h *OperationProvider) getMapFile(uri string) (*models.MapFile, error) {
	content, err := h.readFromCAS(uri, h.CompressionAlgorithm, h.MaxMapFileSize)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading map file")
	}

	mf, err := models.ParseMapFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for map file[%s]", uri)
	}

	return mf, nil
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

// anchorOperations contains parsed operations from anchor file.
type anchorOperations struct {
	Create     []*model.Operation
	Recover    []*model.Operation
	Deactivate []*model.Operation
	Suffixes   []string
}

func (h *OperationProvider) parseAnchorOperations(af *models.AnchorFile, txn *txn.SidetreeTxn) (*anchorOperations, error) {
	logger.Debugf("parsing anchor operations for anchor address: %s", txn.AnchorString)

	var suffixes []string

	var createOps []*model.Operation
	for _, op := range af.Operations.Create {
		suffix, err := docutil.CalculateModelMultihash(op.SuffixData, h.MultihashAlgorithm)
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
	for _, op := range af.Operations.Recover {
		recover := &model.Operation{
			Type:         operation.TypeRecover,
			UniqueSuffix: op.DidSuffix,
			SignedData:   op.SignedData,
		}

		suffixes = append(suffixes, op.DidSuffix)
		recoverOps = append(recoverOps, recover)
	}

	var deactivateOps []*model.Operation
	for _, op := range af.Operations.Deactivate {
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

// MapOperations contains parsed operations from map file.
type MapOperations struct {
	Update   []*model.Operation
	Suffixes []string
}

func parseMapOperations(mf *models.MapFile) *MapOperations {
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

	return &MapOperations{Update: updateOps, Suffixes: suffixes}
}

func getOperations(filter operation.Type, ops []*model.Operation) []*model.Operation {
	var result []*model.Operation
	for _, op := range ops {
		if op.Type == filter {
			result = append(result, op)
		}
	}

	return result
}
