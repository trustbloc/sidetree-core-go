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
	Type OperationType
	//ID is full ID for this document - includes namespace + unique suffix
	ID string
	//SigningKeyID is the id of the key that was used to sign this operation
	SigningKeyID string
	//EncodedPayload  is the encoded operation payload
	EncodedPayload string
	//Signature is the signature of this operation
	Signature string
	//PreviousOperationHash is the hash of the previous operation - undefined for create operation
	PreviousOperationHash string
	//The unique suffix - encoded hash of the original create document
	UniqueSuffix string
	//The number incremented from the last change version number. 1 if first change.
	OperationNumber uint
	//An RFC 6902 JSON patch to the current Document
	Patch jsonpatch.Patch
	//HashAlgorithmInMultiHashCode
	HashAlgorithmInMultiHashCode uint
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
