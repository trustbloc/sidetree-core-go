/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package helper

import (
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

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

// NewCreateRequest is utility function to create payload for 'create' request
func NewCreateRequest(info *CreateRequestInfo) ([]byte, error) {
	if err := validateCreateRequest(info); err != nil {
		return nil, err
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

	suffixDataBytes, err := canonicalizer.MarshalCanonical(suffixData)
	if err != nil {
		return nil, err
	}

	schema := &model.CreateRequest{
		Operation:  model.OperationTypeCreate,
		Delta:      docutil.EncodeToString(deltaBytes),
		SuffixData: docutil.EncodeToString(suffixDataBytes),
	}

	return canonicalizer.MarshalCanonical(schema)
}

func validateCreateRequest(info *CreateRequestInfo) error {
	if info.OpaqueDocument == "" {
		return errors.New("missing opaque document")
	}

	return validateRecoveryKey(info.RecoveryKey)
}

func validateRecoveryKey(key *jws.JWK) error {
	if key == nil {
		return errors.New("missing recovery key")
	}

	return key.Validate()
}

func getEncodedMultihash(mhCode uint, bytes []byte) (string, error) {
	hash, err := docutil.ComputeMultihash(mhCode, bytes)
	if err != nil {
		return "", err
	}

	return docutil.EncodeToString(hash), nil
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

	return canonicalizer.MarshalCanonical(delta)
}
