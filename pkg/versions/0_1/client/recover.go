/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/signutil"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
)

// RecoverRequestInfo is the information required to create recover request.
type RecoverRequestInfo struct {

	// DidSuffix is the suffix of the document to be recovered
	DidSuffix string

	// RecoveryKey is the current recovery public key
	RecoveryKey *jws.JWK

	// OpaqueDocument is opaque content
	OpaqueDocument string

	// Patches that will be used to create document
	// required if opaque document is not specified
	Patches []patch.Patch

	// RecoveryCommitment is recovery commitment to be used for the next recovery
	RecoveryCommitment string

	// UpdateCommitment is update commitment to be used for the next update
	UpdateCommitment string

	// MultihashCode is the latest hashing algorithm supported by protocol
	MultihashCode uint

	// Signer will be used for signing specific subset of request data
	// Signer for recover operation must be recovery key
	Signer Signer
}

// NewRecoverRequest is utility function to create payload for 'recovery' request.
func NewRecoverRequest(info *RecoverRequestInfo) ([]byte, error) {
	err := validateRecoverRequest(info)
	if err != nil {
		return nil, err
	}

	patches, err := getPatches(info.OpaqueDocument, info.Patches)
	if err != nil {
		return nil, err
	}

	delta := &model.DeltaModel{
		UpdateCommitment: info.UpdateCommitment,
		Patches:          patches,
	}

	deltaHash, err := docutil.CalculateModelMultihash(delta, info.MultihashCode)
	if err != nil {
		return nil, err
	}

	signedDataModel := model.RecoverSignedDataModel{
		DeltaHash:          deltaHash,
		RecoveryKey:        info.RecoveryKey,
		RecoveryCommitment: info.RecoveryCommitment,
	}

	jws, err := signutil.SignModel(signedDataModel, info.Signer)
	if err != nil {
		return nil, err
	}

	schema := &model.RecoverRequest{
		Operation:  batch.OperationTypeRecover,
		DidSuffix:  info.DidSuffix,
		Delta:      delta,
		SignedData: jws,
	}

	return canonicalizer.MarshalCanonical(schema)
}

func validateRecoverRequest(info *RecoverRequestInfo) error {
	if info.DidSuffix == "" {
		return errors.New("missing did unique suffix")
	}

	if info.OpaqueDocument == "" && len(info.Patches) == 0 {
		return errors.New("either opaque document or patches have to be supplied")
	}

	if info.OpaqueDocument != "" && len(info.Patches) > 0 {
		return errors.New("cannot provide both opaque document and patches")
	}

	if err := validateSigner(info.Signer); err != nil {
		return err
	}

	return validateRecoveryKey(info.RecoveryKey)
}

func validateRecoveryKey(key *jws.JWK) error {
	if key == nil {
		return errors.New("missing recovery key")
	}

	return key.Validate()
}
