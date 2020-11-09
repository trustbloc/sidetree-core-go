/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
)

// SignedOperation contains operation proving data.
type SignedOperation struct {
	// DidSuffix is the suffix of the DID
	DidSuffix string `json:"didSuffix"`

	// SignedData is compact JWS
	SignedData string `json:"signedData"`
}

// TODO: Remove type check when SIP-1 fully completed.
func getSignedOperations(filter operation.Type, ops []*model.Operation) []SignedOperation {
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

func getSignedData(ops []*model.Operation) []string {
	var result []string
	for _, op := range ops {
		result = append(result, op.SignedData)
	}

	return result
}
