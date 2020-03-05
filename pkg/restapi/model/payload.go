/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import jsonpatch "github.com/evanphx/json-patch"

// CreatePayloadSchema is the struct for create payload
type CreatePayloadSchema struct {
	// operation
	Operation OperationType `json:"type"`

	SuffixData SuffixDataSchema `json:"suffixData"`

	// Encoded JSON object containing create operation data
	OperationData OperationData `json:"operationData"`
}

// SuffixDataSchema is part of create request
type SuffixDataSchema struct {

	// Hash of the encoded operation data string
	OperationDataHash string `json:"operationDataHash"`

	// The recovery public key as a HEX string.
	RecoveryKey PublicKey `json:"recoveryKey"`

	// Hash of the one-time password for this recovery/checkpoint/revoke operation.
	NextRecoveryOTPHash string `json:"nextRecoveryOtpHash"`
}

// PublicKey is holder for public key in hex
type PublicKey struct {
	// public key as a HEX string.
	PublicKeyHex string `json:"publicKeyHex"`
}

// OperationData contains create operation data
type OperationData struct {

	// Hash of the one-time password for the next update operation
	NextUpdateOTPHash string `json:"nextUpdateOtpHash"`

	// Opaque content
	Document string `json:"document"`
}

//UpdatePayloadSchema is the struct for update payload
type UpdatePayloadSchema struct {
	// operation
	// Required: true
	Operation OperationType `json:"type"`

	//The unique suffix of the DID
	DidUniqueSuffix string `json:"didUniqueSuffix"`

	//An RFC 6902 JSON patch to the current DID Document
	Patch jsonpatch.Patch

	// One-time password for update operation
	UpdateOTP string `json:"updateOtp"`

	// Hash of the one-time password for the next update operation
	NextUpdateOTPHash string `json:"nextUpdateOtpHash"`
}

//DeletePayloadSchema is the struct for delete payload
type DeletePayloadSchema struct {
	// operation
	// Required: true
	Operation OperationType `json:"type"`

	//The unique suffix of the DID
	// Required: true
	DidUniqueSuffix string `json:"didUniqueSuffix"`

	// One-time password for recovery operation
	// Required: true
	RecoveryOTP string `json:"recoveryOtp"`
}
