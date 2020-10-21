/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnprovider

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
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
func (h *OperationProvider) GetTxnOperations(txn *txn.SidetreeTxn) ([]*batch.AnchoredOperation, error) {
	// ParseAnchorData anchor address and number of operations from anchor string
	anchorData, err := ParseAnchorData(txn.AnchorString)
	if err != nil {
		return nil, err
	}

	af, err := h.getAnchorFile(anchorData.AnchorAddress)
	if err != nil {
		return nil, err
	}

	if af.MapFileHash == "" {
		// if there's no map file that means that we have only deactivate operations in the batch
		anchorOps, e := h.parseAnchorOperations(af, txn)
		if e != nil {
			return nil, fmt.Errorf("parse anchor operations: %s", e.Error())
		}

		return createAnchoredOperations(anchorOps.Deactivate)
	}

	mf, err := h.getMapFile(af.MapFileHash)
	if err != nil {
		return nil, err
	}

	chunkAddress := mf.Chunks[0].ChunkFileURI
	cf, err := h.getChunkFile(chunkAddress)
	if err != nil {
		return nil, err
	}

	txnOps, err := h.assembleBatchOperations(af, mf, cf, txn)
	if err != nil {
		return nil, err
	}

	if len(txnOps) != anchorData.NumberOfOperations {
		return nil, fmt.Errorf("number of txn ops[%d] doesn't match anchor string num of ops[%d]", len(txnOps), anchorData.NumberOfOperations)
	}

	return txnOps, nil
}

func createAnchoredOperations(ops []*model.Operation) ([]*batch.AnchoredOperation, error) {
	var anchoredOps []*batch.AnchoredOperation
	for _, op := range ops {
		anchoredOp, err := model.GetAnchoredOperation(op)
		if err != nil {
			return nil, err
		}
		anchoredOps = append(anchoredOps, anchoredOp)
	}

	return anchoredOps, nil
}

func (h *OperationProvider) assembleBatchOperations(af *models.AnchorFile, mf *models.MapFile, cf *models.ChunkFile, txn *txn.SidetreeTxn) ([]*batch.AnchoredOperation, error) {
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
func (h *OperationProvider) getAnchorFile(address string) (*models.AnchorFile, error) {
	content, err := h.readFromCAS(address, h.CompressionAlgorithm, h.MaxAnchorFileSize)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading anchor file[%s]", address)
	}

	af, err := models.ParseAnchorFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for anchor file[%s]", address)
	}

	return af, nil
}

// getMapFile will download map file from cas and parse it into map file model.
func (h *OperationProvider) getMapFile(address string) (*models.MapFile, error) {
	content, err := h.readFromCAS(address, h.CompressionAlgorithm, h.MaxMapFileSize)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading map file[%s]", address)
	}

	mf, err := models.ParseMapFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for map file[%s]", address)
	}

	return mf, nil
}

// getChunkFile will download chunk file from cas and parse it into chunk file model.
func (h *OperationProvider) getChunkFile(address string) (*models.ChunkFile, error) {
	content, err := h.readFromCAS(address, h.CompressionAlgorithm, h.MaxChunkFileSize)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading chunk file[%s]", address)
	}

	cf, err := models.ParseChunkFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for chunk file[%s]", address)
	}

	return cf, nil
}

func (h *OperationProvider) readFromCAS(address, alg string, maxSize uint) ([]byte, error) {
	bytes, err := h.cas.Read(address)
	if err != nil {
		return nil, errors.Wrapf(err, "retrieve CAS content[%s]", address)
	}

	if len(bytes) > int(maxSize) {
		return nil, fmt.Errorf("content[%s] size %d exceeded maximum size %d", address, len(bytes), maxSize)
	}

	content, err := h.dp.Decompress(alg, bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "decompress CAS content[%s] using '%s'", address, alg)
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
		suffix, err := docutil.CalculateModelMultihash(op.SuffixData, h.HashAlgorithmInMultiHashCode)
		if err != nil {
			return nil, err
		}

		err = h.parser.ValidateSuffixData(op.SuffixData)
		if err != nil {
			return nil, err
		}

		create := &model.Operation{
			Type:         batch.OperationTypeCreate,
			UniqueSuffix: suffix,
			SuffixData:   op.SuffixData,
		}

		suffixes = append(suffixes, suffix)
		createOps = append(createOps, create)
	}

	var recoverOps []*model.Operation
	for _, op := range af.Operations.Recover {
		recover := &model.Operation{
			Type:         batch.OperationTypeRecover,
			UniqueSuffix: op.DidSuffix,
			SignedData:   op.SignedData,
		}

		suffixes = append(suffixes, op.DidSuffix)
		recoverOps = append(recoverOps, recover)
	}

	var deactivateOps []*model.Operation
	for _, op := range af.Operations.Deactivate {
		deactivate := &model.Operation{
			Type:         batch.OperationTypeDeactivate,
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
			Type:         batch.OperationTypeUpdate,
			UniqueSuffix: op.DidSuffix,
			SignedData:   op.SignedData,
		}

		suffixes = append(suffixes, op.DidSuffix)
		updateOps = append(updateOps, update)
	}

	return &MapOperations{Update: updateOps, Suffixes: suffixes}
}

func getOperations(filter batch.OperationType, ops []*model.Operation) []*model.Operation {
	var result []*model.Operation
	for _, op := range ops {
		if op.Type == filter {
			result = append(result, op)
		}
	}

	return result
}
