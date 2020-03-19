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

	// encoded one-time password for revoke operation
	RecoveryOTP string
}

//RecoverRequestInfo is the information required to create recover request
type RecoverRequestInfo struct {

	// Unique Suffix of the did to be recovered
	DidUniqueSuffix string

	// encoded one-time password for recovery operation
	RecoveryOTP string

	// the new recovery public key as a HEX string
	RecoveryKey string

	// opaque content
	OpaqueDocument string

	// encoded one-time password to be used for the next recovery
	NextRecoveryOTP string

	// encoded one-time password to be used for the next update
	NextUpdateOTP string

	// latest hashing algorithm supported by protocol
	MultihashCode uint
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

	operationData := model.OperationDataSchema{
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

	// TODO: Construct signed operation data here and set it in request

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
		DocumentPatch:     info.Patch,
	}

	opDataBytes, err := docutil.MarshalCanonical(opData)
	if err != nil {
		return nil, err
	}

	// TODO: Assemble signed operation data hash and add to the request

	schema := &model.UpdateRequest{
		Operation:       model.OperationTypeUpdate,
		DidUniqueSuffix: info.DidUniqueSuffix,
		UpdateOTP:       info.UpdateOTP,
		OperationData:   docutil.EncodeToString(opDataBytes),
	}

	return docutil.MarshalCanonical(schema)
}

// NewRecoverRequest is utility function to create payload for 'recovery' request
func NewRecoverRequest(info *RecoverRequestInfo) ([]byte, error) {
	err := checkRequiredDataForRecovery(info)
	if err != nil {
		return nil, err
	}

	mhNextUpdateOTPHash, err := getEncodedOTPMultihash(info.MultihashCode, info.NextUpdateOTP)
	if err != nil {
		return nil, err
	}

	operationData := model.OperationDataSchema{
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

	signedSchema := model.SignedOperationDataSchema{
		OperationDataHash:   docutil.EncodeToString(mhOperationData),
		RecoveryKey:         model.PublicKey{PublicKeyHex: info.RecoveryKey},
		NextRecoveryOTPHash: mhNextRecoveryOTPHash,
	}

	signedSchemaBytes, err := docutil.MarshalCanonical(signedSchema)
	if err != nil {
		return nil, err
	}

	signedOperationData := &model.JWS{
		// TODO: should be JWS encoded, encode for now
		// TODO: Sign and set protected header here
		Payload: docutil.EncodeToString(signedSchemaBytes),
	}

	schema := &model.RecoverRequest{
		Operation:           model.OperationTypeRecover,
		DidUniqueSuffix:     info.DidUniqueSuffix,
		RecoveryOTP:         info.RecoveryOTP,
		SignedOperationData: signedOperationData,
		OperationData:       docutil.EncodeToString(operationDataBytes),
	}

	return docutil.MarshalCanonical(schema)
}

func checkRequiredDataForRecovery(info *RecoverRequestInfo) error {
	if info.DidUniqueSuffix == "" {
		return errors.New("missing did unique suffix")
	}

	if info.OpaqueDocument == "" {
		return errors.New("missing opaque document")
	}

	if info.RecoveryKey == "" {
		return errors.New("missing recovery key")
	}

	return nil
}
