/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnhandler

import (
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/txnhandler/models"
)

type compressionProvider interface {
	Compress(alg string, data []byte) ([]byte, error)
}

// OperationHandler creates batch files(chunk, map, anchor) from batch operations
type OperationHandler struct {
	cas      cas.Client
	protocol protocol.Client
	cp       compressionProvider
}

// NewOperationHandler returns new operations handler
func NewOperationHandler(cas cas.Client, p protocol.Client, cp compressionProvider) *OperationHandler {
	return &OperationHandler{cas: cas, protocol: p, cp: cp}
}

// PrepareTxnFiles will create batch files(chunk, map, anchor) from batch operations,
// store those files in CAS and return anchor string
func (h *OperationHandler) PrepareTxnFiles(ops []*batch.Operation) (string, error) {
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

	ad := AnchorData{
		NumberOfOperations: len(ops),
		AnchorAddress:      anchorAddr,
	}

	return ad.GetAnchorString(), nil
}

// createAnchorFile will create anchor file from operations and map file and write it to CAS
// returns anchor file address
func (h *OperationHandler) createAnchorFile(mapAddress string, ops []*batch.Operation) (string, error) {
	anchorFile := models.CreateAnchorFile(mapAddress, ops)

	return h.writeModelToCAS(anchorFile, "anchor")
}

// createChunkFile will create chunk file from operations and write it to CAS
// returns chunk file address
func (h *OperationHandler) createChunkFile(ops []*batch.Operation) (string, error) {
	chunkFile := models.CreateChunkFile(ops)

	return h.writeModelToCAS(chunkFile, "chunk")
}

// createMapFile will create map file from operations and chunk file URIs and write it to CAS
// returns map file address
func (h *OperationHandler) createMapFile(uri []string, ops []*batch.Operation) (string, error) {
	mapFile := models.CreateMapFile(uri, ops)

	return h.writeModelToCAS(mapFile, "map")
}

func (h *OperationHandler) writeModelToCAS(model interface{}, alias string) (string, error) {
	bytes, err := docutil.MarshalCanonical(model)
	if err != nil {
		return "", fmt.Errorf("failed to marshal %s file: %s", alias, err.Error())
	}

	logger.Debugf("%s file: %s", alias, string(bytes))

	currentProtocol, err := h.protocol.Current()
	if err != nil {
		return "", err
	}

	compressedBytes, err := h.cp.Compress(currentProtocol.CompressionAlgorithm, bytes)
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
