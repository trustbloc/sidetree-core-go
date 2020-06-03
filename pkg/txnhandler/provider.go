/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnhandler

import (
	"fmt"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/txnhandler/models"
)

// DCAS interface to access content addressable storage
type DCAS interface {
	Read(key string) ([]byte, error)
}

// OperationProvider assembles batch operations from batch files
type OperationProvider struct {
	cas DCAS
	pcp protocol.ClientProvider
}

// NewOperationProvider returns new operation provider
func NewOperationProvider(cas DCAS, pcp protocol.ClientProvider) *OperationProvider {
	return &OperationProvider{cas: cas, pcp: pcp}
}

// GetTxnOperations will read batch files(Chunk, map, anchor) and assemble batch operations from those files
func (h *OperationProvider) GetTxnOperations(txn *txn.SidetreeTxn) ([]*batch.Operation, error) {
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

		return anchorOps.Deactivate, nil
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

	return h.assembleBatchOperations(af, mf, cf, txn)
}

func (h *OperationProvider) assembleBatchOperations(af *models.AnchorFile, mf *models.MapFile, cf *models.ChunkFile, txn *txn.SidetreeTxn) ([]*batch.Operation, error) {
	anchorOps, err := h.parseAnchorOperations(af, txn)
	if err != nil {
		return nil, fmt.Errorf("parse anchor operations: %s", err.Error())
	}

	log.Debugf("successfully parsed anchor operations: create[%d], recover[%d], deactivate[%d]",
		len(anchorOps.Create), len(anchorOps.Recover), len(anchorOps.Deactivate))

	mapOps := parseMapOperations(mf)

	log.Debugf("successfully parsed map operations: update[%d]", len(mapOps.Update))

	var operations []*batch.Operation
	operations = append(operations, anchorOps.Create...)
	operations = append(operations, anchorOps.Recover...)
	operations = append(operations, mapOps.Update...)
	operations = append(operations, anchorOps.Deactivate...)

	// TODO: Add checks here to makes sure that file sizes match - part of validation tickets

	for i, delta := range cf.Deltas {
		p, err := h.getProtocol(operations[i].Namespace)
		if err != nil {
			return nil, err
		}

		deltaModel, err := operation.ParseDelta(delta, p.HashAlgorithmInMultiHashCode)
		if err != nil {
			return nil, fmt.Errorf("parse delta: %s", err.Error())
		}

		operations[i].EncodedDelta = delta
		operations[i].Delta = deltaModel
	}

	return operations, nil
}

// getAnchorFile will download anchor file from cas and parse it into anchor file model
func (h *OperationProvider) getAnchorFile(address string) (*models.AnchorFile, error) {
	content, err := h.cas.Read(address)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve content for anchor file[%s]", address)
	}

	af, err := models.ParseAnchorFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for anchor file[%s]", address)
	}

	// TODO: verify anchor file - issue-294
	return af, nil
}

// getMapFile will download map file from cas and parse it into map file model
func (h *OperationProvider) getMapFile(address string) (*models.MapFile, error) {
	content, err := h.cas.Read(address)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve content for map file[%s]", address)
	}

	mf, err := models.ParseMapFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for map file[%s]", address)
	}

	// TODO: verify map file - issue-295
	return mf, nil
}

// getChunkFile will download chunk file from cas and parse it into chunk file model
func (h *OperationProvider) getChunkFile(address string) (*models.ChunkFile, error) {
	content, err := h.cas.Read(address)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve content for chunk file[%s]", address)
	}

	cf, err := models.ParseChunkFile(content)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse content for chunk file[%s]", address)
	}

	// TODO: verify chunk file - issue-296
	return cf, nil
}

// anchorOperations contains parsed operations from anchor file
type anchorOperations struct {
	Create     []*batch.Operation
	Recover    []*batch.Operation
	Deactivate []*batch.Operation
	Suffixes   []string
}

func (h *OperationProvider) parseAnchorOperations(af *models.AnchorFile, txn *txn.SidetreeTxn) (*anchorOperations, error) { //nolint: funlen
	log.Debugf("parsing anchor operations for anchor address: %s", txn.AnchorString)

	var suffixes []string

	var createOps []*batch.Operation
	for _, op := range af.Operations.Create {
		p, err := h.getProtocol(op.Namespace)
		if err != nil {
			return nil, err
		}

		suffix, err := docutil.CalculateUniqueSuffix(op.SuffixData, p.HashAlgorithmInMultiHashCode)
		if err != nil {
			return nil, err
		}

		suffixModel, err := operation.ParseSuffixData(op.SuffixData, p.HashAlgorithmInMultiHashCode)
		if err != nil {
			return nil, err
		}

		// TODO: they are assembling operation buffer in reference implementation (might be easier for version manager)
		create := &batch.Operation{
			Type:              batch.OperationTypeCreate,
			Namespace:         op.Namespace,
			UniqueSuffix:      suffix,
			ID:                op.Namespace + docutil.NamespaceDelimiter + suffix,
			EncodedSuffixData: op.SuffixData,
			SuffixData:        suffixModel,
		}

		suffixes = append(suffixes, suffix)
		createOps = append(createOps, create)
	}

	var recoverOps []*batch.Operation
	for _, op := range af.Operations.Recover {
		recover := &batch.Operation{
			Type:         batch.OperationTypeRecover,
			Namespace:    op.Namespace,
			UniqueSuffix: op.DidSuffix,
			ID:           op.Namespace + docutil.NamespaceDelimiter + op.DidSuffix,
			SignedData:   op.SignedData,
		}

		suffixes = append(suffixes, op.DidSuffix)
		recoverOps = append(recoverOps, recover)
	}

	var deactivateOps []*batch.Operation
	for _, op := range af.Operations.Deactivate {
		deactivate := &batch.Operation{
			Type:         batch.OperationTypeDeactivate,
			Namespace:    op.Namespace,
			UniqueSuffix: op.DidSuffix,
			ID:           op.Namespace + docutil.NamespaceDelimiter + op.DidSuffix,
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

func (h *OperationProvider) getProtocol(namespace string) (*protocol.Protocol, error) {
	pc, err := h.pcp.ForNamespace(namespace)
	if err != nil {
		return nil, err
	}

	// TODO: get protocol based on Sidetree transaction - for now use current
	p := pc.Current()

	return &p, nil
}

// MapOperations contains parsed operations from map file
type MapOperations struct {
	Update   []*batch.Operation
	Suffixes []string
}

func parseMapOperations(mf *models.MapFile) *MapOperations {
	var suffixes []string

	var updateOps []*batch.Operation
	for _, op := range mf.Operations.Update {
		update := &batch.Operation{
			Type:         batch.OperationTypeUpdate,
			Namespace:    op.Namespace,
			UniqueSuffix: op.DidSuffix,
			ID:           op.Namespace + docutil.NamespaceDelimiter + op.DidSuffix,
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
