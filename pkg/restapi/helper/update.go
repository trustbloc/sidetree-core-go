/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package helper

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

// UpdateRequestInfo is the information required to create update request.
type UpdateRequestInfo struct {

	// DidSuffix is the suffix of the document to be updated
	DidSuffix string

	// Patches is an array of standard patch actions
	Patches []patch.Patch

	// update commitment to be used for the next update
	UpdateCommitment string

	// update key to be used for this update
	UpdateKey *jws.JWK

	// latest hashing algorithm supported by protocol
	MultihashCode uint

	// Signer that will be used for signing request specific subset of data
	Signer Signer
}

// NewUpdateRequest is utility function to create payload for 'update' request.
func NewUpdateRequest(info *UpdateRequestInfo) ([]byte, error) {
	if err := validateUpdateRequest(info); err != nil {
		return nil, err
	}

	delta := &model.DeltaModel{
		UpdateCommitment: info.UpdateCommitment,
		Patches:          info.Patches,
	}

	deltaHash, err := docutil.CalculateModelMultihash(delta, info.MultihashCode)
	if err != nil {
		return nil, err
	}

	signedDataModel := &model.UpdateSignedDataModel{
		DeltaHash: deltaHash,
		UpdateKey: info.UpdateKey,
	}

	jws, err := signutil.SignModel(signedDataModel, info.Signer)
	if err != nil {
		return nil, err
	}

	schema := &model.UpdateRequest{
		Operation:  batch.OperationTypeUpdate,
		DidSuffix:  info.DidSuffix,
		Delta:      delta,
		SignedData: jws,
	}

	return canonicalizer.MarshalCanonical(schema)
}

func validateUpdateRequest(info *UpdateRequestInfo) error {
	if info.DidSuffix == "" {
		return errors.New("missing did unique suffix")
	}

	if len(info.Patches) == 0 {
		return errors.New("missing update information")
	}

	if err := validateUpdateKey(info.UpdateKey); err != nil {
		return err
	}

	return validateSigner(info.Signer)
}

func validateUpdateKey(key *jws.JWK) error {
	if key == nil {
		return errors.New("missing update key")
	}

	return key.Validate()
}
