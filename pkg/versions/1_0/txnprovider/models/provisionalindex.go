/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"encoding/json"

	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/model"
)

// ProvisionalIndexFile defines the schema for provisional index file and its related operations.
type ProvisionalIndexFile struct {

	// ProvisionalProofFileURI is provisional proof file URI
	ProvisionalProofFileURI string `json:"provisionalProofFileUri,omitempty"`

	// Chunks are chunk entries for the related delta data for a given chunk of operations in the batch.
	Chunks []Chunk `json:"chunks"`

	// Operations will contain provisional (update) operations
	Operations *ProvisionalOperations `json:"operations,omitempty"`
}

// ProvisionalOperations contains minimal operation proving data for provisional (update) operations.
type ProvisionalOperations struct {
	Update []OperationReference `json:"update,omitempty"`
}

// Chunk holds chunk file URI.
type Chunk struct {
	ChunkFileURI string `json:"chunkFileUri"`
}

// CreateProvisionalIndexFile will create provisional index file model from operations and chunk file URI.
// returns chunk file model.
func CreateProvisionalIndexFile(chunkURIs []string, provisionalProofURI string, updateOps []*model.Operation) *ProvisionalIndexFile {
	var provisionalOps *ProvisionalOperations
	if len(updateOps) > 0 {
		provisionalOps = &ProvisionalOperations{}

		provisionalOps.Update = getOperationReferences(updateOps)
	}

	return &ProvisionalIndexFile{
		Chunks:                  getChunks(chunkURIs),
		ProvisionalProofFileURI: provisionalProofURI,
		Operations:              provisionalOps,
	}
}

// ParseProvisionalIndexFile will parse content into provisional index file model.
func ParseProvisionalIndexFile(content []byte) (*ProvisionalIndexFile, error) {
	file := &ProvisionalIndexFile{}
	err := json.Unmarshal(content, file)
	if err != nil {
		return nil, err
	}

	return file, nil
}

func getChunks(uris []string) []Chunk {
	var chunks []Chunk
	for _, uri := range uris {
		chunks = append(chunks, Chunk{
			ChunkFileURI: uri,
		})
	}

	return chunks
}
