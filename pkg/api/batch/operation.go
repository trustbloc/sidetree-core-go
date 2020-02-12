/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package batch

import (
	jsonpatch "github.com/evanphx/json-patch"
)

// Operation defines an operation
type Operation struct {

	//Operation type
	Type OperationType `json:"type"`
	//ID is full ID for this document - includes namespace + unique suffix
	ID string `json:"id"`

	//The unique suffix - encoded hash of the original create document
	UniqueSuffix string `json:"uniqueSuffix"`

	// EncodedProtectedHeader is the encoded protected header
	EncodedProtectedHeader string `json:"encodedProtectedHeader"`
	//EncodedPayload  is the encoded operation payload
	EncodedPayload string `json:"encodedPayload"`

	//EncodedDocument contains encoded original document
	EncodedDocument string `json:"document"`

	//SigningKeyID is the id of the key that was used to sign this operation
	SigningKeyID string `json:"signingKeyID"`
	//Signature is the signature of this operation
	Signature string `json:"signature"`

	//An RFC 6902 JSON patch to the current Document
	Patch jsonpatch.Patch `json:"patch"`

	//HashAlgorithmInMultiHashCode
	HashAlgorithmInMultiHashCode uint `json:"hashAlgorithmInMultiHashCode"`
	//The logical blockchain time that this operation was anchored on the blockchain
	TransactionTime uint64 `json:"transactionTime"`
	//The transaction number of the transaction this operation was batched within
	TransactionNumber uint64 `json:"transactionNumber"`
	//The index this operation was assigned to in the batch
	OperationIndex uint `json:"operationIndex"`

	// One-time password for update operation
	UpdateOTP string `json:"updateOTP"`
	// One-time password for this recovery/checkpoint/revoke operation
	RecoveryOTP string `json:"recoveryOTP"`

	// Hash of the one-time password for the next update operation
	NextUpdateOTPHash string `json:"nextUpdateOTPHash"`
	// Hash of the one-time password for this recovery/checkpoint/revoke operation.
	NextRecoveryOTPHash string `json:"nextRecoveryOTPHash"`
}

// OperationType defines valid values for operation type
type OperationType string

const (

	// OperationTypeCreate captures "create" operation type
	OperationTypeCreate OperationType = "create"

	// OperationTypeUpdate captures "update" operation type
	OperationTypeUpdate OperationType = "update"

	// OperationTypeDelete captures "delete" operation type
	OperationTypeDelete OperationType = "delete"

	// OperationTypeRecover captures "recover" operation type
	OperationTypeRecover OperationType = "recover"
)
