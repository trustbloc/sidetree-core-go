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
	"github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/txnhandler/models"
)

// Handler creates batch files(chunk, map, anchor) from batch operations
type Handler struct {
	cas      cas.Client
	protocol protocol.Client
}

// New returns new transaction handler
func New(cas cas.Client, p protocol.Client) *Handler {
	return &Handler{cas: cas, protocol: p}
}

// PrepareTxnFiles will create batch files(chunk, map, anchor) from batch operations,
// store those files in CAS and return anchor string
func (h *Handler) PrepareTxnFiles(ops []*batch.Operation) (string, error) {
	deactivateOps := getOperations(batch.OperationTypeDeactivate, ops)

	// special case: if all ops are deactivate don't create chunk and map files
	mapFileAddr := ""
	if len(deactivateOps) != len(ops) {
		chunkFileAddr, err := h.createChunkFile(ops)
		if err != nil {
			return "", err
		}

		mapFileAddr, err = h.createMapFile([]string{chunkFileAddr}, ops)
		if err != nil {
			return "", err
		}
	}

	anchorAddr, err := h.createAnchorFile(mapFileAddr, ops)
	if err != nil {
		return "", err
	}

	// TODO: Create anchor string issue-293 - for now return anchor address
	return anchorAddr, nil
}

// GetTxnOperations will read batch files(Chunk, map, anchor) and assemble batch Operations from those files
func (h *Handler) GetTxnOperations(txn *txn.SidetreeTxn) ([]*batch.Operation, error) {
	// TODO: parse anchor file address from address string - issue-293
	anchorAddress := txn.AnchorAddress

	// TODO: get protocol based on Sidetree transaction - for now use current
	p := h.protocol.Current()

	af, err := h.getAnchorFile(anchorAddress)
	if err != nil {
		return nil, err
	}

	if af.MapFileHash == "" {
		// if there's no map file that means that we have only deactivate operations in the batch
		anchorOps, e := parseAnchorOperations(af, h.protocol.Current())
		if e != nil {
			return nil, fmt.Errorf("parse anchor operations: %s", err.Error())
		}

		return anchorOps.Deactivate, nil
	}

	mf, err := h.getMapFile(af.MapFileHash)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse map file: key[%s]", af.MapFileHash)
	}

	chunkAddress := mf.Chunks[0].ChunkFileURI
	cf, err := h.getChunkFile(chunkAddress)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse chunk file: key[%s]", chunkAddress)
	}

	return assembleBatchOperations(af, mf, cf, p)
}

func assembleBatchOperations(af *models.AnchorFile, mf *models.MapFile, cf *models.ChunkFile, p protocol.Protocol) ([]*batch.Operation, error) {
	anchorOps, err := parseAnchorOperations(af, p)
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
		deltaModel, err := operation.ParseDelta(delta, p.HashAlgorithmInMultiHashCode)
		if err != nil {
			return nil, fmt.Errorf("parse delta: %s", err.Error())
		}

		operations[i].EncodedDelta = delta
		operations[i].Delta = deltaModel
	}

	return operations, nil
}

// createAnchorFile will create anchor file from operations and map file and write it to CAS
// returns anchor file address
func (h *Handler) createAnchorFile(mapAddress string, ops []*batch.Operation) (string, error) {
	anchorFile := models.CreateAnchorFile(mapAddress, ops)

	return h.writeModelToCAS(anchorFile, "anchor")
}

// createChunkFile will create chunk file from operations and write it to CAS
// returns chunk file address
func (h *Handler) createChunkFile(ops []*batch.Operation) (string, error) {
	chunkFile := models.CreateChunkFile(ops)

	return h.writeModelToCAS(chunkFile, "chunk")
}

// createMapFile will create map file from operations and chunk file URIs and write it to CAS
// returns map file address
func (h *Handler) createMapFile(uri []string, ops []*batch.Operation) (string, error) {
	mapFile := models.CreateMapFile(uri, ops)

	return h.writeModelToCAS(mapFile, "map")
}

// getAnchorFile will download anchor file from cas and parse it into anchor file model
func (h *Handler) getAnchorFile(address string) (*models.AnchorFile, error) {
	content, err := h.cas.Read(address)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve content for anchor file[%s]", address)
	}

	af, err := models.ParseAnchorFile(content)
	if err != nil {
		return nil, err
	}

	// TODO: verify anchor file - issue-294
	return af, nil
}

// getMapFile will download map file from cas and parse it into map file model
func (h *Handler) getMapFile(address string) (*models.MapFile, error) {
	content, err := h.cas.Read(address)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve content for map file[%s]", address)
	}

	mf, err := models.ParseMapFile(content)
	if err != nil {
		return nil, err
	}

	// TODO: verify map file - issue-295
	return mf, nil
}

// getChunkFile will download chunk file from cas and parse it into chunk file model
func (h *Handler) getChunkFile(address string) (*models.ChunkFile, error) {
	content, err := h.cas.Read(address)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve content for chunk file[%s]", address)
	}

	cf, err := models.ParseChunkFile(content)
	if err != nil {
		return nil, err
	}

	// TODO: verify chunk file - issue-296
	return cf, nil
}

func (h *Handler) writeModelToCAS(model interface{}, alias string) (string, error) {
	bytes, err := docutil.MarshalCanonical(model)
	if err != nil {
		return "", fmt.Errorf("failed to marshal %s file: %s", alias, err.Error())
	}

	log.Debugf("%s file: %s", alias, string(bytes))

	// make file available in CAS
	address, err := h.cas.Write(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to store %s file: %s", alias, err.Error())
	}

	return address, nil
}

// anchorOperations contains parsed operations from anchor file
type anchorOperations struct {
	Create     []*batch.Operation
	Recover    []*batch.Operation
	Deactivate []*batch.Operation
	Suffixes   []string
}

func parseAnchorOperations(af *models.AnchorFile, p protocol.Protocol) (*anchorOperations, error) { //nolint: funlen
	var suffixes []string

	var createOps []*batch.Operation
	for _, op := range af.Operations.Create {
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
