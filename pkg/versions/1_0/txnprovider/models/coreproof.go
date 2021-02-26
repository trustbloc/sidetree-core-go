/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"encoding/json"

	"github.com/pkg/errors"

	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/model"
)

// CoreProofFile defines the schema for core proof file. Core proof file contains the cryptographic proofs
// (signatures, hashes, etc.) that form the signature-chained backbone for the state lineages of all DIDs in the system.
// The cryptographic proofs present in core proof file also link a given operation to its verbose state data,
// which resides in a related chunk file.
type CoreProofFile struct {

	// Operations contain proving data for recover and deactivate operations.
	Operations CoreProofOperations `json:"operations,omitempty"`
}

// CoreProofOperations contains proving data for any recover and deactivate operations to be included in a batch.
type CoreProofOperations struct {
	Recover    []string `json:"recover,omitempty"`
	Deactivate []string `json:"deactivate,omitempty"`
}

// CreateCoreProofFile will create core proof file from provided operations.
// returns core proof file model.
func CreateCoreProofFile(recoverOps, deactivateOps []*model.Operation) *CoreProofFile {
	return &CoreProofFile{
		Operations: CoreProofOperations{
			Recover:    getSignedData(recoverOps),
			Deactivate: getSignedData(deactivateOps),
		},
	}
}

// ParseCoreProofFile will parse core proof model from content.
func ParseCoreProofFile(content []byte) (*CoreProofFile, error) {
	file := &CoreProofFile{}
	err := json.Unmarshal(content, file)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to unmarshal core proof file")
	}

	return file, nil
}
