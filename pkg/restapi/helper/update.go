/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package helper

import (
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/signutil"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

//UpdateRequestInfo is the information required to create update request
type UpdateRequestInfo struct {

	// DID Suffix of the document to be updated
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

// NewUpdateRequest is utility function to create payload for 'update' request
func NewUpdateRequest(info *UpdateRequestInfo) ([]byte, error) {
	if err := validateUpdateRequest(info); err != nil {
		return nil, err
	}

	deltaBytes, err := getDeltaBytes(info.UpdateCommitment, info.Patches)
	if err != nil {
		return nil, err
	}

	mhDelta, err := getEncodedMultihash(info.MultihashCode, deltaBytes)
	if err != nil {
		return nil, err
	}

	signedDataModel := model.UpdateSignedDataModel{
		DeltaHash: mhDelta,
		UpdateKey: info.UpdateKey,
	}

	jws, err := signutil.SignModel(signedDataModel, info.Signer)
	if err != nil {
		return nil, err
	}

	schema := &model.UpdateRequest{
		Operation:  model.OperationTypeUpdate,
		DidSuffix:  info.DidSuffix,
		Delta:      docutil.EncodeToString(deltaBytes),
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
