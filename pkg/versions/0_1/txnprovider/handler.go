/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnprovider

import (
	"errors"
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/txnprovider/models"
)

type compressionProvider interface {
	Compress(alg string, data []byte) ([]byte, error)
}

// OperationHandler creates batch files(chunk, map, anchor) from batch operations.
type OperationHandler struct {
	cas      cas.Client
	protocol protocol.Protocol
	parser   OperationParser
	cp       compressionProvider
}

// NewOperationHandler returns new operations handler.
func NewOperationHandler(p protocol.Protocol, cas cas.Client, cp compressionProvider, parser OperationParser) *OperationHandler {
	return &OperationHandler{cas: cas, protocol: p, cp: cp, parser: parser}
}

// PrepareTxnFiles will create batch files(chunk, map, anchor) from batch operations,
// store those files in CAS and return anchor string.
func (h *OperationHandler) PrepareTxnFiles(ops []*operation.QueuedOperation) (string, []*operation.Reference, error) {
	parsedOps, dids, err := h.parseOperations(ops)
	if err != nil {
		return "", nil, err
	}

	// special case: if all ops are deactivate don't create chunk and provisional files
	provisionalIndexURI := ""
	if len(parsedOps.Deactivate) != len(ops) {
		chunkURI, innerErr := h.createChunkFile(parsedOps)
		if innerErr != nil {
			return "", nil, innerErr
		}

		provisionalProofURI, innerErr := h.createProvisionalProofFile(parsedOps.Update)
		if innerErr != nil {
			return "", nil, innerErr
		}

		provisionalIndexURI, innerErr = h.createProvisionalIndexFile([]string{chunkURI}, provisionalProofURI, parsedOps.Update)
		if innerErr != nil {
			return "", nil, innerErr
		}
	}

	coreProofURI, err := h.createCoreProofFile(parsedOps.Recover, parsedOps.Deactivate)
	if err != nil {
		return "", nil, err
	}

	coreIndexURI, err := h.createCoreIndexFile(coreProofURI, provisionalIndexURI, parsedOps)
	if err != nil {
		return "", nil, err
	}

	ad := AnchorData{
		NumberOfOperations: parsedOps.Size(),
		CoreIndexFileURI:   coreIndexURI,
	}

	return ad.GetAnchorString(), dids, nil
}

func (h *OperationHandler) parseOperations(ops []*operation.QueuedOperation) (*models.SortedOperations, []*operation.Reference, error) {
	if len(ops) == 0 {
		return nil, nil, errors.New("prepare txn operations called without operations, should not happen")
	}

	batchSuffixes := make(map[string]operation.Type)

	result := &models.SortedOperations{}
	for _, d := range ops {
		op, e := h.parser.ParseOperation(d.Namespace, d.OperationBuffer, false)
		if e != nil {
			return nil, nil, e
		}

		_, ok := batchSuffixes[op.UniqueSuffix]
		if ok {
			logger.Warnf("[%s] duplicate suffix[%s] found in batch operations: discarding operation %v", d.Namespace, op.UniqueSuffix, op)

			continue
		}

		switch op.Type {
		case operation.TypeCreate:
			result.Create = append(result.Create, op)
		case operation.TypeUpdate:
			result.Update = append(result.Update, op)
		case operation.TypeRecover:
			result.Recover = append(result.Recover, op)
		case operation.TypeDeactivate:
			result.Deactivate = append(result.Deactivate, op)
		}

		batchSuffixes[op.UniqueSuffix] = op.Type
	}

	dids := make([]*operation.Reference, 0, len(batchSuffixes))
	for did, op := range batchSuffixes {
		dids = append(dids, &operation.Reference{UniqueSuffix: did, Type: op})
	}

	return result, dids, nil
}

// createCoreIndexFile will create core index file from operations, proof files and provisional index file and write it to CAS
// returns core index file address.
func (h *OperationHandler) createCoreIndexFile(coreProofURI, mapURI string, ops *models.SortedOperations) (string, error) {
	coreIndexFile := models.CreateCoreIndexFile(coreProofURI, mapURI, ops)

	return h.writeModelToCAS(coreIndexFile, "core index")
}

// createCoreProofFile will create core proof file from recover and deactivate operations and write it to CAS
// returns core proof file address.
func (h *OperationHandler) createCoreProofFile(recoverOps, deactivateOps []*model.Operation) (string, error) {
	if len(recoverOps)+len(deactivateOps) == 0 {
		return "", nil
	}

	chunkFile := models.CreateCoreProofFile(recoverOps, deactivateOps)

	return h.writeModelToCAS(chunkFile, "core proof")
}

// createProvisionalProofFile will create provisional proof file from update operations and write it to CAS
// returns provisional proof file address.
func (h *OperationHandler) createProvisionalProofFile(updateOps []*model.Operation) (string, error) {
	if len(updateOps) == 0 {
		return "", nil
	}

	chunkFile := models.CreateProvisionalProofFile(updateOps)

	return h.writeModelToCAS(chunkFile, "provisional proof")
}

// createChunkFile will create chunk file from operations and write it to CAS
// returns chunk file address.
func (h *OperationHandler) createChunkFile(ops *models.SortedOperations) (string, error) {
	chunkFile := models.CreateChunkFile(ops)

	return h.writeModelToCAS(chunkFile, "chunk")
}

// createProvisionalIndexFile will create provisional index file from operations, provisional proof URI
// and chunk file URIs. The provisional index file is then written to CAS.
// returns the address of the provisional index file in the CAS.
func (h *OperationHandler) createProvisionalIndexFile(chunks []string, provisionalURI string, ops []*model.Operation) (string, error) {
	provisionalIndexFile := models.CreateProvisionalIndexFile(chunks, provisionalURI, ops)

	return h.writeModelToCAS(provisionalIndexFile, "provisional index")
}

func (h *OperationHandler) writeModelToCAS(model interface{}, alias string) (string, error) {
	bytes, err := docutil.MarshalCanonical(model)
	if err != nil {
		return "", fmt.Errorf("failed to marshal %s file: %s", alias, err.Error())
	}

	logger.Debugf("%s file: %s", alias, string(bytes))

	compressedBytes, err := h.cp.Compress(h.protocol.CompressionAlgorithm, bytes)
	if err != nil {
		return "", err
	}

	// make file available in CAS
	address, err := h.cas.Write(compressedBytes)
	if err != nil {
		return "", fmt.Errorf("failed to store %s file: %s", alias, err.Error())
	}

	return address, nil
}
