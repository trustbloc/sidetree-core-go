/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import jsonpatch "github.com/evanphx/json-patch"

// CreateRequest is the struct for create payload
type CreateRequest struct {
	// operation
	// Required: true
	Operation OperationType `json:"type"`

	// Encoded JSON object containing data required for creating suffix
	// Required: true
	SuffixData string `json:"suffixData"`

	// Encoded JSON object containing create operation data
	// Required: true
	OperationData string `json:"operationData"`
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

// CreateOperationData contains create operation data
type CreateOperationData struct {

	// Hash of the one-time password for the next update operation
	NextUpdateOTPHash string `json:"nextUpdateOtpHash"`

	// Opaque content
	Document string `json:"document"`
}

//UpdateRequest is the struct for update request
type UpdateRequest struct {
	Operation OperationType `json:"type"`

	//The unique suffix of the DID
	DidUniqueSuffix string `json:"didUniqueSuffix"`

	//An RFC 6902 JSON patch to the current DID Document
	Patch jsonpatch.Patch

	// One-time password for update operation
	UpdateOTP string `json:"updateOtp"`

	// JWS signature information
	SignedOperationDataHash *SignedOperationData `json:"signedOperationDataHash"`

	// Encoded JSON object containing update operation data
	OperationData string `json:"operationData"`
}

// UpdateOperationData contains create operation data
type UpdateOperationData struct {

	// Hash of the one-time password for the next update operation
	NextUpdateOTPHash string `json:"nextUpdateOtpHash"`

	// Opaque content
	DocumentPatch string `json:"document"`
}

//RevokeRequest is the struct for revoking document
type RevokeRequest struct {
	// operation
	// Required: true
	Operation OperationType `json:"type"`

	//The unique suffix of the DID
	// Required: true
	DidUniqueSuffix string `json:"didUniqueSuffix"`

	// One-time password for recovery operation
	// Required: true
	RecoveryOTP string `json:"recoveryOtp"`

	// JWS Signature information
	SignedOperationData *SignedOperationData `json:"signedOperationDataHash"`
}

// SignedOperationData contains JWS signature
type SignedOperationData struct {
	// protected
	// Required: true
	Protected *Header `json:"protected"`

	// Hash of the operation data
	// Required: true
	Payload string `json:"payload"`

	// JWS signature
	// Required: true
	Signature string `json:"signature"`
}

// Protected describes JWS header
type Protected struct {
	// alg
	// Required: true
	Alg string `json:"alg"`

	// kid
	// Required: true
	Kid string `json:"kid"`
}
