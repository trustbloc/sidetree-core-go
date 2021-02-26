/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"encoding/json"

	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/model"
)

// ChunkFile defines chunk file schema.
type ChunkFile struct {
	// Deltas included in this chunk file, each delta is an encoded string
	Deltas []*model.DeltaModel `json:"deltas"`
}

// CreateChunkFile will combine all operation deltas into chunk file.
// returns chunk file model.
func CreateChunkFile(ops *SortedOperations) *ChunkFile {
	var deltas []*model.DeltaModel

	deltas = append(deltas, getDeltas(ops.Create)...)
	deltas = append(deltas, getDeltas(ops.Recover)...)
	deltas = append(deltas, getDeltas(ops.Update)...)

	return &ChunkFile{Deltas: deltas}
}

// ParseChunkFile will parse chunk file model from content.
func ParseChunkFile(content []byte) (*ChunkFile, error) {
	file := &ChunkFile{}
	err := json.Unmarshal(content, file)
	if err != nil {
		return nil, err
	}

	return file, nil
}

func getDeltas(ops []*model.Operation) []*model.DeltaModel {
	var deltas []*model.DeltaModel
	for _, op := range ops {
		deltas = append(deltas, op.Delta)
	}

	return deltas
}
