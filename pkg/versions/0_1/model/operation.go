/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import (
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
)

// Operation is used for parsing operation request.
type Operation struct {

	// Type defines operation type
	Type operation.Type

	// Namespace defines document namespace
	Namespace string

	// ID is full ID for this document -  namespace + unique suffix
	ID string

	// UniqueSuffix is unique suffix
	UniqueSuffix string

	// OperationBuffer is the original operation request
	OperationBuffer []byte

	// SignedData is signed data for the operation (compact JWS)
	SignedData string

	// Delta is operation delta model
	Delta *DeltaModel

	// SuffixDataModel is suffix data model
	SuffixData *SuffixDataModel
}
