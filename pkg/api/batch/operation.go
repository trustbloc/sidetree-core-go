/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package batch

import (
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// Operation defines an operation
type Operation struct {

	//Operation type
	Type OperationType `json:"type"`

	//ID is full ID for this document - includes namespace + unique suffix
	ID string `json:"id"`

	//The unique suffix - encoded hash of the original create document
	UniqueSuffix string `json:"uniqueSuffix"`

	// OperationBuffer is the original operation request
	OperationBuffer []byte `json:"operationBuffer"`

	// signed data for the operation
	SignedData *model.JWS `json:"signedData"`

	// operation delta
	Delta *model.DeltaModel `json:"delta"`

	// suffix data
	SuffixData *model.SuffixDataModel `json:"suffixData"`

	// encoded delta
	EncodedDelta string `json:"encodedDelta"`

	//HashAlgorithmInMultiHashCode
	HashAlgorithmInMultiHashCode uint `json:"hashAlgorithmInMultiHashCode"`
	//The logical blockchain time that this operation was anchored on the blockchain
	TransactionTime uint64 `json:"transactionTime"`
	//The transaction number of the transaction this operation was batched within
	TransactionNumber uint64 `json:"transactionNumber"`
	//The index this operation was assigned to in the batch
	OperationIndex uint `json:"operationIndex"`

	// Reveal value for this update operation
	UpdateRevealValue string `json:"updateRevealValue"`
	// Reveal value for this recovery/deactivate operation
	RecoveryRevealValue string `json:"recoveryRevealValue"`

	// Hash of reveal value for the next update operation
	UpdateCommitment string `json:"updateCommitment"`
	// Hash of reveal value for next recovery/deactivate operation
	RecoveryCommitment string `json:"recoveryCommitment"`
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

// OperationInfo contains the unique suffix as well as the operation payload
type OperationInfo struct {
	Data         []byte
	UniqueSuffix string
}
