/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package helper

import (
	"errors"

	jsonpatch "github.com/evanphx/json-patch"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// CreateRequestInfo contains data for creating create payload
type CreateRequestInfo struct {

	// opaque content
	OpaqueDocument string

	// the recovery public key as a HEX string
	RecoveryKey string

	// encoded one-time password to be used for the next recovery
	NextRecoveryOTP string

	// encoded one-time password to be used for the next update
	NextUpdateOTP string

	// latest hashing algorithm supported by protocol
	MultihashCode uint
}

//RevokeRequestInfo is the information required to create revoke request
type RevokeRequestInfo struct {

	// Unique Suffix
	DidUniqueSuffix string

	// encoded one-time password for recovery operation
	RecoveryOTP string
}

//UpdateRequestInfo is the information required to create update request
type UpdateRequestInfo struct {

	// Unique Suffix
	DidUniqueSuffix string

	//An RFC 6902 JSON patch to the current DID Document
	Patch jsonpatch.Patch

	// encoded one-time password for update operation
	UpdateOTP string

	// encoded one-time password for the next update operation
	NextUpdateOTP string

	// latest hashing algorithm supported by protocol
	MultihashCode uint
}

// NewCreateRequest is utility function to create payload for 'create' request
func NewCreateRequest(info *CreateRequestInfo) ([]byte, error) {
	if info.OpaqueDocument == "" {
		return nil, errors.New("missing opaque document")
	}

	if info.RecoveryKey == "" {
		return nil, errors.New("missing recovery key")
	}

	mhNextUpdateOTPHash, err := getEncodedOTPMultihash(info.MultihashCode, info.NextUpdateOTP)
	if err != nil {
		return nil, err
	}

	operationData := model.CreateOperationData{
		NextUpdateOTPHash: mhNextUpdateOTPHash,
		Document:          info.OpaqueDocument,
	}

	operationDataBytes, err := docutil.MarshalCanonical(operationData)
	if err != nil {
		return nil, err
	}

	mhOperationData, err := docutil.ComputeMultihash(info.MultihashCode, operationDataBytes)
	if err != nil {
		return nil, err
	}

	mhNextRecoveryOTPHash, err := getEncodedOTPMultihash(info.MultihashCode, info.NextRecoveryOTP)
	if err != nil {
		return nil, err
	}

	suffixData := model.SuffixDataSchema{
		OperationDataHash:   docutil.EncodeToString(mhOperationData),
		RecoveryKey:         model.PublicKey{PublicKeyHex: info.RecoveryKey},
		NextRecoveryOTPHash: mhNextRecoveryOTPHash,
	}

	suffixDataBytes, err := docutil.MarshalCanonical(suffixData)
	if err != nil {
		return nil, err
	}

	schema := &model.CreateRequest{
		Operation:     model.OperationTypeCreate,
		OperationData: docutil.EncodeToString(operationDataBytes),
		SuffixData:    docutil.EncodeToString(suffixDataBytes),
	}

	return docutil.MarshalCanonical(schema)
}

func getEncodedOTPMultihash(mhCode uint, encodedOTP string) (string, error) {
	otpBytes, err := docutil.DecodeString(encodedOTP)
	if err != nil {
		return "", err
	}

	otpHash, err := docutil.ComputeMultihash(mhCode, otpBytes)
	if err != nil {
		return "", err
	}

	return docutil.EncodeToString(otpHash), nil
}

// NewRevokeRequest is utility function to create payload for 'revoke' request
func NewRevokeRequest(info *RevokeRequestInfo) ([]byte, error) {
	if info.DidUniqueSuffix == "" {
		return nil, errors.New("missing did unique suffix")
	}

	schema := &model.RevokeRequest{
		Operation:       model.OperationTypeRevoke,
		DidUniqueSuffix: info.DidUniqueSuffix,
		RecoveryOTP:     info.RecoveryOTP,
	}

	return docutil.MarshalCanonical(schema)
}

// NewUpdateRequest is utility function to create payload for 'update' request
func NewUpdateRequest(info *UpdateRequestInfo) ([]byte, error) {
	if info.DidUniqueSuffix == "" {
		return nil, errors.New("missing did unique suffix")
	}

	if info.Patch == nil {
		return nil, errors.New("missing update information")
	}

	mhNextUpdateOTPHash, err := getEncodedOTPMultihash(info.MultihashCode, info.NextUpdateOTP)
	if err != nil {
		return nil, err
	}

	opData := &model.UpdateOperationData{
		NextUpdateOTPHash: mhNextUpdateOTPHash,
		// TODO: Set new patches here
	}

	opDataBytes, err := docutil.MarshalCanonical(opData)
	if err != nil {
		return nil, err
	}

	schema := &model.UpdateRequest{
		Operation:       model.OperationTypeUpdate,
		DidUniqueSuffix: info.DidUniqueSuffix,
		UpdateOTP:       info.UpdateOTP,
		OperationData:   docutil.EncodeToString(opDataBytes),
	}

	return docutil.MarshalCanonical(schema)
}
