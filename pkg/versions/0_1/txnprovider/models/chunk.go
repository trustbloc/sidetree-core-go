/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"encoding/json"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
)

// ChunkFile defines chunk file schema
type ChunkFile struct {
	// Deltas included in this chunk file, each delta is an encoded string
	Deltas []string `json:"deltas"`
}

// CreateChunkFile will combine all operation deltas into chunk file
// returns chunk file model
func CreateChunkFile(ops []*batch.Operation) *ChunkFile {
	var deltas []string

	deltas = append(deltas, getDeltas(batch.OperationTypeCreate, ops)...)
	deltas = append(deltas, getDeltas(batch.OperationTypeRecover, ops)...)
	deltas = append(deltas, getDeltas(batch.OperationTypeUpdate, ops)...)

	return &ChunkFile{Deltas: deltas}
}

// ParseChunkFile will parse chunk file model from content
func ParseChunkFile(content []byte) (*ChunkFile, error) {
	cf, err := getChunkFile(content)
	if err != nil {
		return nil, err
	}

	return cf, nil
}

func getDeltas(filter batch.OperationType, ops []*batch.Operation) []string {
	var deltas []string
	for _, op := range ops {
		if op.Type == filter {
			deltas = append(deltas, op.Delta)
		}
	}

	return deltas
}

// get chunk file struct from bytes
var getChunkFile = func(bytes []byte) (*ChunkFile, error) {
	return unmarshalChunkFile(bytes)
}

// unmarshal chunk file bytes into chunk file model
func unmarshalChunkFile(bytes []byte) (*ChunkFile, error) {
	file := &ChunkFile{}
	err := json.Unmarshal(bytes, file)
	if err != nil {
		return nil, err
	}

	return file, nil
}
