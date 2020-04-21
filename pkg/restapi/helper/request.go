/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package helper

import (
	"encoding/json"
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/jsoncanonicalizer"
	internal "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// Signer defines JWS Signer interface that will be used to sign required data in Sidetree request
type Signer interface {
	// Sign signs data and returns signature value
	Sign(data []byte) ([]byte, error)

	// Headers provides required JWS protected headers. It provides information about signing key and algorithm.
	Headers() jws.Headers
}

// CreateRequestInfo contains data for creating create payload
type CreateRequestInfo struct {

	// opaque document content
	// required
	OpaqueDocument string

	// the recovery public key as a HEX string
	// required
	RecoveryKey *jws.JWK

	// reveal value to be used for the next recovery
	NextRecoveryRevealValue []byte

	// reveal value to be used for the next update
	NextUpdateRevealValue []byte

	// latest hashing algorithm supported by protocol
	MultihashCode uint
}

//DeactivateRequestInfo is the information required to create deactivate request
type DeactivateRequestInfo struct {

	// DID Suffix of the document to be deactivated
	DidSuffix string

	// reveal value for this deactivate operation
	RecoveryRevealValue []byte

	// Signer that will be used for signing specific subset of request data
	// Signer for recover operation must be recovery key
	Signer Signer
}

//RecoverRequestInfo is the information required to create recover request
type RecoverRequestInfo struct {

	// DID Suffix of the document to be recovered
	DidSuffix string

	// reveal value for this recovery operation
	RecoveryRevealValue []byte

	// the new recovery public key as a HEX string
	RecoveryKey *jws.JWK

	// opaque content
	OpaqueDocument string

	// reveal value to be used for the next recovery
	NextRecoveryRevealValue []byte

	// reveal value to be used for the next update
	NextUpdateRevealValue []byte

	// latest hashing algorithm supported by protocol
	MultihashCode uint

	// Signer will be used for signing specific subset of request data
	// Signer for recover operation must be recovery key
	Signer Signer
}

//UpdateRequestInfo is the information required to create update request
type UpdateRequestInfo struct {

	// DID Suffix of the document to be updated
	DidSuffix string

	// Patch is one of standard patch actions
	Patch patch.Patch

	// reveal value for this update operation
	UpdateRevealValue []byte

	// reveal value to be used for the next update
	// optional if NextUpdateCommitmentHash is provided
	NextUpdateRevealValue []byte

	// latest hashing algorithm supported by protocol
	MultihashCode uint

	// Signer that will be used for signing request specific subset of data
	Signer Signer
}

// NewCreateRequest is utility function to create payload for 'create' request
func NewCreateRequest(info *CreateRequestInfo) ([]byte, error) {
	if info.OpaqueDocument == "" {
		return nil, errors.New("missing opaque document")
	}

	if info.RecoveryKey == nil {
		return nil, errors.New("missing recovery key")
	}

	replace, err := patch.NewReplacePatch(info.OpaqueDocument)
	if err != nil {
		return nil, err
	}

	patches := []patch.Patch{replace}
	deltaBytes, err := getDeltaBytes(info.MultihashCode, info.NextUpdateRevealValue, patches)
	if err != nil {
		return nil, err
	}

	mhDelta, err := getEncodedMultihash(info.MultihashCode, deltaBytes)
	if err != nil {
		return nil, err
	}

	mhNextRecoveryCommitmentHash, err := getEncodedMultihash(info.MultihashCode, info.NextRecoveryRevealValue)
	if err != nil {
		return nil, err
	}

	suffixData := model.SuffixDataModel{
		DeltaHash:          mhDelta,
		RecoveryKey:        info.RecoveryKey,
		RecoveryCommitment: mhNextRecoveryCommitmentHash,
	}

	suffixDataBytes, err := MarshalCanonical(suffixData)
	if err != nil {
		return nil, err
	}

	schema := &model.CreateRequest{
		Operation:  model.OperationTypeCreate,
		Delta:      docutil.EncodeToString(deltaBytes),
		SuffixData: docutil.EncodeToString(suffixDataBytes),
	}

	return MarshalCanonical(schema)
}

func getEncodedMultihash(mhCode uint, bytes []byte) (string, error) {
	hash, err := docutil.ComputeMultihash(mhCode, bytes)
	if err != nil {
		return "", err
	}

	return docutil.EncodeToString(hash), nil
}

// NewDeactivateRequest is utility function to create payload for 'deactivate' request
func NewDeactivateRequest(info *DeactivateRequestInfo) ([]byte, error) {
	if info.DidSuffix == "" {
		return nil, errors.New("missing did unique suffix")
	}

	signedDataModel := model.DeactivateSignedDataModel{
		DidSuffix:           info.DidSuffix,
		RecoveryRevealValue: docutil.EncodeToString(info.RecoveryRevealValue),
	}

	jws, err := signModel(signedDataModel, info.Signer)
	if err != nil {
		return nil, err
	}

	schema := &model.DeactivateRequest{
		Operation:           model.OperationTypeDeactivate,
		DidSuffix:           info.DidSuffix,
		RecoveryRevealValue: docutil.EncodeToString(info.RecoveryRevealValue),
		SignedData:          jws,
	}

	return MarshalCanonical(schema)
}

// NewUpdateRequest is utility function to create payload for 'update' request
func NewUpdateRequest(info *UpdateRequestInfo) ([]byte, error) {
	if info.DidSuffix == "" {
		return nil, errors.New("missing did unique suffix")
	}

	if info.Patch == nil {
		return nil, errors.New("missing update information")
	}

	patches := []patch.Patch{info.Patch}
	deltaBytes, err := getDeltaBytes(info.MultihashCode, info.NextUpdateRevealValue, patches)
	if err != nil {
		return nil, err
	}

	mhDelta, err := getEncodedMultihash(info.MultihashCode, deltaBytes)
	if err != nil {
		return nil, err
	}

	jws, err := signPayload(mhDelta, info.Signer)
	if err != nil {
		return nil, err
	}

	schema := &model.UpdateRequest{
		Operation:         model.OperationTypeUpdate,
		DidSuffix:         info.DidSuffix,
		UpdateRevealValue: docutil.EncodeToString(info.UpdateRevealValue),
		Delta:             docutil.EncodeToString(deltaBytes),
		SignedData:        jws,
	}

	return MarshalCanonical(schema)
}

// NewRecoverRequest is utility function to create payload for 'recovery' request
func NewRecoverRequest(info *RecoverRequestInfo) ([]byte, error) {
	err := checkRequiredDataForRecovery(info)
	if err != nil {
		return nil, err
	}

	replacePatch, err := patch.NewReplacePatch(info.OpaqueDocument)
	if err != nil {
		return nil, err
	}

	patches := []patch.Patch{replacePatch}
	deltaBytes, err := getDeltaBytes(info.MultihashCode, info.NextUpdateRevealValue, patches)
	if err != nil {
		return nil, err
	}

	mhDelta, err := docutil.ComputeMultihash(info.MultihashCode, deltaBytes)
	if err != nil {
		return nil, err
	}

	mhNextRecoveryCommitmentHash, err := getEncodedMultihash(info.MultihashCode, info.NextRecoveryRevealValue)
	if err != nil {
		return nil, err
	}

	signedDataModel := model.RecoverSignedDataModel{
		DeltaHash:          docutil.EncodeToString(mhDelta),
		RecoveryKey:        info.RecoveryKey,
		RecoveryCommitment: mhNextRecoveryCommitmentHash,
	}

	jws, err := signModel(signedDataModel, info.Signer)
	if err != nil {
		return nil, err
	}

	schema := &model.RecoverRequest{
		Operation:           model.OperationTypeRecover,
		DidSuffix:           info.DidSuffix,
		RecoveryRevealValue: docutil.EncodeToString(info.RecoveryRevealValue),
		Delta:               docutil.EncodeToString(deltaBytes),
		SignedData:          jws,
	}

	return MarshalCanonical(schema)
}

func signModel(data interface{}, signer Signer) (*model.JWS, error) {
	signedDataBytes, err := MarshalCanonical(data)
	if err != nil {
		return nil, err
	}

	payload := docutil.EncodeToString(signedDataBytes)

	return signPayload(payload, signer)
}

func signPayload(payload string, signer Signer) (*model.JWS, error) {
	alg, ok := signer.Headers().Algorithm()
	if !ok || alg == "" {
		return nil, errors.New("signing algorithm is required")
	}

	kid, ok := signer.Headers().KeyID()
	if !ok || kid == "" {
		return nil, errors.New("signing kid is required")
	}

	jwsSignature, err := internal.NewJWS(signer.Headers(), nil, []byte(payload), signer)
	if err != nil {
		return nil, err
	}

	signature, err := jwsSignature.SerializeCompact(false)
	if err != nil {
		return nil, err
	}

	protected := &model.Header{
		Alg: alg,
		Kid: kid,
	}
	return &model.JWS{
		Protected: protected,
		Signature: signature,
		Payload:   payload,
	}, nil
}

func checkRequiredDataForRecovery(info *RecoverRequestInfo) error {
	if info.DidSuffix == "" {
		return errors.New("missing did unique suffix")
	}

	if info.OpaqueDocument == "" {
		return errors.New("missing opaque document")
	}

	if info.RecoveryKey == nil {
		return errors.New("missing recovery key")
	}

	return nil
}

func getDeltaBytes(mhCode uint, reveal []byte, patches []patch.Patch) ([]byte, error) {
	mhNextUpdateCommitmentHash, err := getEncodedMultihash(mhCode, reveal)
	if err != nil {
		return nil, err
	}

	delta := model.DeltaModel{
		UpdateCommitment: mhNextUpdateCommitmentHash,
		Patches:          patches,
	}

	return MarshalCanonical(delta)
}

// MarshalCanonical is using JCS RFC canonicalization
func MarshalCanonical(value interface{}) ([]byte, error) {
	jsonLiteralValByte, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	return jsoncanonicalizer.Transform(jsonLiteralValByte)
}
