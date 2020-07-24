/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package batch

import (
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// Operation is used for parsing operation request
type Operation struct {

	//Type defines operation type
	Type OperationType

	//Namespace defines document namespace
	Namespace string

	// ID is full ID for this document -  namespace + unique suffix
	ID string

	//UniqueSuffix is unique suffix
	UniqueSuffix string

	// OperationBuffer is the original operation request
	OperationBuffer []byte

	//SignedData is signed data for the operation (compact JWS)
	SignedData string

	// DeltaModel is operation delta model
	DeltaModel *model.DeltaModel

	// Delta is encoded delta
	Delta string

	// SuffixDataModel is suffix data model
	SuffixDataModel *model.SuffixDataModel

	// SuffixData is encoded suffix data
	SuffixData string
}

// AnchoredOperation defines an anchored operation (stored in document operation store)
type AnchoredOperation struct {

	//Type defines operation type
	Type OperationType `json:"type"`

	//UniqueSuffix defines document unique suffix
	UniqueSuffix string `json:"unique_suffix"`

	//SignedData is signed data for the operation (compact JWS)
	SignedData string `json:"signed_data,omitempty"`

	//Delta is encoded delta
	Delta string `json:"delta,omitempty"`

	//SuffixData is encoded suffix data
	SuffixData string `json:"suffix_data,omitempty"`

	//The logical blockchain time (block number) that this operation was anchored on the blockchain
	TransactionTime uint64 `json:"transaction_time"`
	//The transaction number of the transaction this operation was batched within
	TransactionNumber uint64 `json:"transaction_number"`
	//The index this operation was assigned to in the batch
	OperationIndex uint `json:"operation_index"`
}

// OperationType defines valid values for operation type
type OperationType string

const (

	// OperationTypeCreate captures "create" operation type
	OperationTypeCreate OperationType = "create"

	// OperationTypeUpdate captures "update" operation type
	OperationTypeUpdate OperationType = "update"

	// OperationTypeDeactivate captures "deactivate" operation type
	OperationTypeDeactivate OperationType = "deactivate"

	// OperationTypeRecover captures "recover" operation type
	OperationTypeRecover OperationType = "recover"
)

// OperationInfo contains the unique suffix and namespace as well as the operation buffer
type OperationInfo struct {
	Data         []byte
	UniqueSuffix string
	Namespace    string
}
