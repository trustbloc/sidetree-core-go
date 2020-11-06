/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"encoding/json"

	"github.com/pkg/errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
)

// ProvisionalProofFile defines the schema for provisional proof file. Provisional proof file contains the cryptographic
// proofs (signatures, hashes, etc.) for all the (eventually) prunable DID operations in the system. The cryptographic
// proofs present in provisional proof file also link a given operation to its verbose state data, which resides
// in a related chunk file.
type ProvisionalProofFile struct {
	Operations ProvisionalProofOperations `json:"operations,omitempty"`
}

// ProvisionalProofOperations contains proving data for any update operation to be included in the batch.
type ProvisionalProofOperations struct {
	Update []SignedOperation `json:"update,omitempty"`
}

// CreateProvisionalProofFile will create provisional proof file model from operations.
// returns provisional proof file model.
func CreateProvisionalProofFile(updateOps []*model.Operation) *ProvisionalProofFile {
	return &ProvisionalProofFile{
		Operations: ProvisionalProofOperations{
			Update: getSignedOperations(operation.TypeUpdate, updateOps),
		},
	}
}

// ParseProvisionalProofFile will parse provisional proof file model from content.
func ParseProvisionalProofFile(content []byte) (*ProvisionalProofFile, error) {
	file := &ProvisionalProofFile{}
	err := json.Unmarshal(content, file)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to unmarshal provisional proof file")
	}

	return file, nil
}
