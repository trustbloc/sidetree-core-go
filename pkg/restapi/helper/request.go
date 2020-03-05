/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package helper

import (
	"encoding/json"
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// CreateRequestInfo contains data for creating create payload
type CreateRequestInfo struct {

	// opaque content
	OpaqueDocument string

	// the recovery public key as a HEX string
	RecoveryKey string

	// one-time password to be used for the next recovery
	NextRecoveryOTP string

	// one-time password to be used for the next update
	NextUpdateOTP string

	// latest hashing algorithm supported by protocol
	MultihashCode uint
}

//DeletePayloadInfo is the information required to create delete payload
type DeletePayloadInfo struct {

	// Unique Suffix
	DidUniqueSuffix string

	// One-time password for recovery operation
	RecoveryOTP string
}

// SignedRequestInfo contains data required for signed requests
type SignedRequestInfo struct {

	// encoded payload
	Payload string

	// algorithm used for signing
	Algorithm string

	// ID of the signing key
	KID string

	// signature over payload
	Signature string
}

// NewCreateRequest is utility function to create payload for 'create' request
func NewCreateRequest(info *CreateRequestInfo) ([]byte, error) {
	if info.OpaqueDocument == "" {
		return nil, errors.New("missing opaque document")
	}

	if info.RecoveryKey == "" {
		return nil, errors.New("missing recovery key")
	}

	mhNextRecoveryOTPHash, err := docutil.ComputeMultihash(info.MultihashCode, []byte(info.NextRecoveryOTP))
	if err != nil {
		return nil, err
	}

	mhNextUpdateOTPHash, err := docutil.ComputeMultihash(info.MultihashCode, []byte(info.NextUpdateOTP))
	if err != nil {
		return nil, err
	}

	operationData := model.OperationData{
		NextUpdateOTPHash: docutil.EncodeToString(mhNextUpdateOTPHash),
		Document:          info.OpaqueDocument,
	}

	operationDataBytes, err := json.Marshal(operationData)
	if err != nil {
		return nil, err
	}

	mhOperationData, err := docutil.ComputeMultihash(info.MultihashCode, operationDataBytes)
	if err != nil {
		return nil, err
	}

	schema := &model.CreatePayloadSchema{
		Operation:     model.OperationTypeCreate,
		OperationData: operationData,
		SuffixData: model.SuffixDataSchema{
			OperationDataHash:   docutil.EncodeToString(mhOperationData),
			RecoveryKey:         model.PublicKey{PublicKeyHex: info.RecoveryKey},
			NextRecoveryOTPHash: docutil.EncodeToString(mhNextRecoveryOTPHash),
		},
	}

	return json.Marshal(schema)
}

// NewDeletePayload is utility function to create payload for 'delete' request
func NewDeletePayload(info *DeletePayloadInfo) (string, error) {
	if info.DidUniqueSuffix == "" {
		return "", errors.New("missing did unique suffix")
	}

	schema := &model.DeletePayloadSchema{
		Operation:       model.OperationTypeDelete,
		DidUniqueSuffix: info.DidUniqueSuffix,
		RecoveryOTP:     info.RecoveryOTP,
	}

	payload, err := json.Marshal(schema)
	if err != nil {
		panic(err)
	}

	return docutil.EncodeToString(payload), nil
}

// NewSignedRequest is utility function to create request with payload and payload signature
// This helper function applies to update, delete and recovery
func NewSignedRequest(info *SignedRequestInfo) ([]byte, error) {
	if info.Payload == "" {
		return nil, errors.New("missing payload")
	}

	if info.Algorithm == "" {
		return nil, errors.New("missing algorithm")
	}

	if info.KID == "" {
		return nil, errors.New("missing signing key ID")
	}

	if info.Signature == "" {
		return nil, errors.New("missing signature")
	}

	req := model.Request{
		Protected: &model.Header{
			Alg: info.Algorithm,
			Kid: info.KID,
		},
		Payload:   info.Payload,
		Signature: info.Signature,
	}

	return json.Marshal(req)
}
