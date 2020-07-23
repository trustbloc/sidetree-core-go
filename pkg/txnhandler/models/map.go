/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"encoding/json"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
)

// MapFile defines the schema for map file and its related operations
type MapFile struct {
	Chunks     []Chunk    `json:"chunks"`
	Operations Operations `json:"operations,omitempty"`
}

// Chunk holds chunk file URI
type Chunk struct {
	ChunkFileURI string `json:"chunk_file_uri"`
}

// CreateMapFile will create map file model from operations and chunk file URI
// returns chunk file model
func CreateMapFile(uri []string, ops []*batch.Operation) *MapFile {
	return &MapFile{
		Chunks: getChunks(uri),
		Operations: Operations{
			Update: getSignedOperations(batch.OperationTypeUpdate, ops),
		},
	}
}

// ParseMapFile will parse map file model from content
func ParseMapFile(content []byte) (*MapFile, error) {
	mf, err := getMapFile(content)
	if err != nil {
		return nil, err
	}

	return mf, nil
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

func getSignedOperations(filter batch.OperationType, ops []*batch.Operation) []SignedOperation {
	var result []SignedOperation
	for _, op := range ops {
		if op.Type == filter {
			upd := SignedOperation{
				DidSuffix:  op.UniqueSuffix,
				SignedData: op.SignedData,
			}

			result = append(result, upd)
		}
	}

	return result
}

//  get map file struct from bytes
var getMapFile = func(bytes []byte) (*MapFile, error) {
	return unmarshalMapFile(bytes)
}

// unmarshal map file bytes into map file model
func unmarshalMapFile(bytes []byte) (*MapFile, error) {
	file := &MapFile{}
	err := json.Unmarshal(bytes, file)
	if err != nil {
		return nil, err
	}

	return file, nil
}
