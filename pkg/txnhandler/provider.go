/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnhandler

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/txnhandler/models"
)

var logger = log.New("sidetree-core-txnhandler")

// DCAS interface to access content addressable storage
type DCAS interface {
	Read(key string) ([]byte, error)
}

type decompressionProvider interface {
	Decompress(alg string, data []byte) ([]byte, error)
}

// OperationProvider assembles batch operations from batch files
type OperationProvider struct {
	cas DCAS
	pcp protocol.ClientProvider
	dp  decompressionProvider
}

// NewOperationProvider returns new operation provider
func NewOperationProvider(cas DCAS, pcp protocol.ClientProvider, dp decompressionProvider) *OperationProvider {
	return &OperationProvider{cas: cas, pcp: pcp, dp: dp}
}

// GetTxnOperations will read batch files(Chunk, map, anchor) and assemble batch operations from those files
func (h *OperationProvider) GetTxnOperations(txn *txn.SidetreeTxn) ([]*batch.AnchoredOperation, error) {
	// ParseAnchorData anchor address and number of operations from anchor string
	anchorData, err := ParseAnchorData(txn.AnchorString)
	if err != nil {
		return nil, err
	}

	pc, err := h.pcp.ForNamespace(txn.Namespace)
	if err != nil {
		return nil, err
	}

	af, err := h.getAnchorFile(anchorData.AnchorAddress, pc.Current())
	if err != nil {
		return nil, err
	}

	if af.MapFileHash == "" {
		// if there's no map file that means that we have only deactivate operations in the batch
		anchorOps, e := h.parseAnchorOperations(af, txn)
		if e != nil {
			return nil, fmt.Errorf("parse anchor operations: %s", e.Error())
		}

		return anchorOps.Deactivate, nil
	}

	mf, err := h.getMapFile(af.MapFileHash, pc.Current())
	if err != nil {
		return nil, err
	}

	chunkAddress := mf.Chunks[0].ChunkFileURI
	cf, err := h.getChunkFile(chunkAddress, pc.Current())
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

func (h *OperationProvider) assembleBatchOperations(af *models.AnchorFile, mf *models.MapFile, cf *models.ChunkFile, txn *txn.SidetreeTxn) ([]*batch.AnchoredOperation, error) {
	anchorOps, err := h.parseAnchorOperations(af, txn)
	if err != nil {
		return nil, fmt.Errorf("parse anchor operations: %s", err.Error())
	}

	logger.Debugf("successfully parsed anchor operations: create[%d], recover[%d], deactivate[%d]",
		len(anchorOps.Create), len(anchorOps.Recover), len(anchorOps.Deactivate))

	mapOps := parseMapOperations(mf)

	logger.Debugf("successfully parsed map operations: update[%d]", len(mapOps.Update))

	var operations []*batch.AnchoredOperation
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
		p, err := h.getProtocol(txn)
		if err != nil {
			return nil, err
		}

		_, err = operation.ParseDelta(delta, p)
		if err != nil {
			return nil, fmt.Errorf("parse delta: %s", err.Error())
		}

		operations[i].Delta = delta
	}

	return operations, nil
}

// getAnchorFile will download anchor file from cas and parse it into anchor file model
func (h *OperationProvider) getAnchorFile(address string, p protocol.Protocol) (*models.AnchorFile, error) {
	content, err := h.readFromCAS(address, p.CompressionAlgorithm, p.MaxAnchorFileSize)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading anchor file[%s]", address)
	}

	af, err := models.ParseAnchorFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for anchor file[%s]", address)
	}

	return af, nil
}

// getMapFile will download map file from cas and parse it into map file model
func (h *OperationProvider) getMapFile(address string, p protocol.Protocol) (*models.MapFile, error) {
	content, err := h.readFromCAS(address, p.CompressionAlgorithm, p.MaxMapFileSize)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading map file[%s]", address)
	}

	mf, err := models.ParseMapFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for map file[%s]", address)
	}

	return mf, nil
}

// getChunkFile will download chunk file from cas and parse it into chunk file model
func (h *OperationProvider) getChunkFile(address string, p protocol.Protocol) (*models.ChunkFile, error) {
	content, err := h.readFromCAS(address, p.CompressionAlgorithm, p.MaxChunkFileSize)
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

// anchorOperations contains parsed operations from anchor file
type anchorOperations struct {
	Create     []*batch.AnchoredOperation
	Recover    []*batch.AnchoredOperation
	Deactivate []*batch.AnchoredOperation
	Suffixes   []string
}

func (h *OperationProvider) parseAnchorOperations(af *models.AnchorFile, txn *txn.SidetreeTxn) (*anchorOperations, error) { //nolint: funlen
	logger.Debugf("parsing anchor operations for anchor address: %s", txn.AnchorString)

	p, err := h.getProtocol(txn)
	if err != nil {
		return nil, fmt.Errorf("parsing anchor operations: %s", err.Error())
	}

	var suffixes []string

	var createOps []*batch.AnchoredOperation
	for _, op := range af.Operations.Create {
		suffix, err := docutil.CalculateUniqueSuffix(op.SuffixData, p.HashAlgorithmInMultiHashCode)
		if err != nil {
			return nil, err
		}

		_, err = operation.ParseSuffixData(op.SuffixData, p)
		if err != nil {
			return nil, err
		}

		// TODO: they are assembling operation buffer in reference implementation - issue-380
		// (might be easier for version manager)
		create := &batch.AnchoredOperation{
			Type:         batch.OperationTypeCreate,
			UniqueSuffix: suffix,
			SuffixData:   op.SuffixData,
		}

		suffixes = append(suffixes, suffix)
		createOps = append(createOps, create)
	}

	var recoverOps []*batch.AnchoredOperation
	for _, op := range af.Operations.Recover {
		recover := &batch.AnchoredOperation{
			Type:         batch.OperationTypeRecover,
			UniqueSuffix: op.DidSuffix,
			SignedData:   op.SignedData,
		}

		suffixes = append(suffixes, op.DidSuffix)
		recoverOps = append(recoverOps, recover)
	}

	var deactivateOps []*batch.AnchoredOperation
	for _, op := range af.Operations.Deactivate {
		deactivate := &batch.AnchoredOperation{
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

func (h *OperationProvider) getProtocol(txn *txn.SidetreeTxn) (protocol.Protocol, error) {
	pc, err := h.pcp.ForNamespace(txn.Namespace)
	if err != nil {
		return protocol.Protocol{}, err
	}

	return pc.Get(txn.TransactionTime)
}

// MapOperations contains parsed operations from map file
type MapOperations struct {
	Update   []*batch.AnchoredOperation
	Suffixes []string
}

func parseMapOperations(mf *models.MapFile) *MapOperations {
	var suffixes []string

	var updateOps []*batch.AnchoredOperation
	for _, op := range mf.Operations.Update {
		update := &batch.AnchoredOperation{
			Type:         batch.OperationTypeUpdate,
			UniqueSuffix: op.DidSuffix,
			SignedData:   op.SignedData,
		}

		suffixes = append(suffixes, op.DidSuffix)
		updateOps = append(updateOps, update)
	}

	return &MapOperations{Update: updateOps, Suffixes: suffixes}
}

func getOperations(filter batch.OperationType, ops []*batch.Operation) []*batch.Operation {
	var result []*batch.Operation
	for _, op := range ops {
		if op.Type == filter {
			result = append(result, op)
		}
	}

	return result
}
