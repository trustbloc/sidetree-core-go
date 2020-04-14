/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import (
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

// CreateRequest is the struct for create payload
type CreateRequest struct {
	// operation
	// Required: true
	Operation OperationType `json:"type"`

	// Encoded JSON object containing data used to compute the unique DID suffix
	// Required: true
	SuffixData string `json:"suffixData"`

	// Encoded JSON object containing create patch data
	// Required: true
	PatchData string `json:"patchData"`
}

// SuffixDataModel is part of create request
type SuffixDataModel struct {

	// Hash of the patch data
	PatchDataHash string `json:"patchDataHash"`

	// The recovery public key in JWK format
	RecoveryKey *jws.JWK `json:"recoveryKey"`

	// Commitment hash for the next recovery
	NextRecoveryCommitmentHash string `json:"nextRecoveryCommitmentHash"`
}

// PublicKey is holder for public key in hex
type PublicKey struct {
	// public key as a HEX string.
	PublicKeyHex string `json:"publicKeyHex"`
}

// PatchDataModel contains patch data (patches used for create, recover, update)
type PatchDataModel struct {

	// Commitment hash for the next update operation
	NextUpdateCommitmentHash string `json:"nextUpdateCommitmentHash"`

	// Patches defines document patches
	Patches []patch.Patch `json:"patches"`
}

//UpdateRequest is the struct for update request
type UpdateRequest struct {
	Operation OperationType `json:"type"`

	//The unique suffix of the DID
	DidUniqueSuffix string `json:"didUniqueSuffix"`

	// Reveal value for this update operation
	UpdateRevealValue string `json:"updateRevealValue"`

	// JWS signature information
	SignedData *JWS `json:"signedData"`

	// Encoded JSON object containing patch data
	PatchData string `json:"patchData"`
}

//DeactivateRequest is the struct for deactivating document
type DeactivateRequest struct {
	// operation
	// Required: true
	Operation OperationType `json:"type"`

	//The unique suffix of the DID
	// Required: true
	DidUniqueSuffix string `json:"didUniqueSuffix"`

	// the current reveal value to use for this request
	// Required: true
	RecoveryRevealValue string `json:"recoveryRevealValue"`

	// JWS Signature information
	SignedData *JWS `json:"signedData"`
}

// RecoverSignedDataModel defines signed data model for recovery
type RecoverSignedDataModel struct {

	// Hash of the unsigned patch data
	PatchDataHash string `json:"patchDataHash"`

	// The new recovery key
	RecoveryKey *jws.JWK `json:"recoveryKey"`

	// Hash of the one-time password to be used for the next recovery/deactivate
	NextRecoveryCommitmentHash string `json:"nextRecoveryCommitmentHash"`
}

// DeactivateSignedDataModel defines data model for deactivate
type DeactivateSignedDataModel struct {

	//The unique suffix of the DID
	// Required: true
	DidUniqueSuffix string `json:"didUniqueSuffix"`

	// the current reveal value to use for this request
	// Required: true
	RecoveryRevealValue string `json:"recoveryRevealValue"`
}

// RecoverRequest is the struct for document recovery payload
type RecoverRequest struct {
	// operation
	// Required: true
	Operation OperationType `json:"type"`

	//The unique suffix of the DID
	// Required: true
	DidUniqueSuffix string `json:"didUniqueSuffix"`

	// The reveal value for this recovery
	// Required: true
	RecoveryRevealValue string `json:"recoveryRevealValue"`

	// JWS Signature information
	SignedData *JWS `json:"signedData"`

	// Encoded JSON object containing recovery patch data
	// Required: true
	PatchData string `json:"patchData"`
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
