/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/model"
)

// SortedOperations stores operations per type.
type SortedOperations struct {
	Create     []*model.Operation
	Update     []*model.Operation
	Recover    []*model.Operation
	Deactivate []*model.Operation
}

// Size returns the length of all operations(combined).
func (o *SortedOperations) Size() int {
	return len(o.Create) + len(o.Recover) + len(o.Deactivate) + len(o.Update)
}

// OperationReference contains minimum proving data.
type OperationReference struct {
	// DidSuffix is the suffix of the DID
	DidSuffix string `json:"didSuffix"`

	// RevealValue is multihash of JWK
	RevealValue string `json:"revealValue"`
}

func getOperationReferences(ops []*model.Operation) []OperationReference {
	var result []OperationReference
	for _, op := range ops {
		upd := OperationReference{
			DidSuffix:   op.UniqueSuffix,
			RevealValue: op.RevealValue,
		}

		result = append(result, upd)
	}

	return result
}

func getSignedData(ops []*model.Operation) []string {
	var result []string
	for _, op := range ops {
		result = append(result, op.SignedData)
	}

	return result
}
