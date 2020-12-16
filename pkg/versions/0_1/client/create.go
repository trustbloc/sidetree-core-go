/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"errors"
	"fmt"

	"github.com/multiformats/go-multihash"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
)

// CreateRequestInfo contains data for creating create payload.
type CreateRequestInfo struct {

	// opaque document content
	// required
	OpaqueDocument string

	// patches that will be used to create document
	// required if opaque document is not specified
	Patches []patch.Patch

	// the recovery commitment
	// required
	RecoveryCommitment string

	// the update commitment
	// required
	UpdateCommitment string

	// latest hashing algorithm supported by protocol
	MultihashCode uint
}

// NewCreateRequest is utility function to create payload for 'create' request.
func NewCreateRequest(info *CreateRequestInfo) ([]byte, error) {
	if err := validateCreateRequest(info); err != nil {
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

	deltaHash, err := hashing.CalculateModelMultihash(delta, info.MultihashCode)
	if err != nil {
		return nil, err
	}

	suffixData := &model.SuffixDataModel{
		DeltaHash:          deltaHash,
		RecoveryCommitment: info.RecoveryCommitment,
	}

	schema := &model.CreateRequest{
		Operation:  operation.TypeCreate,
		Delta:      delta,
		SuffixData: suffixData,
	}

	return canonicalizer.MarshalCanonical(schema)
}

func getPatches(opaque string, patches []patch.Patch) ([]patch.Patch, error) {
	if opaque != "" {
		return patch.PatchesFromDocument(opaque)
	}

	return patches, nil
}

func validateCreateRequest(info *CreateRequestInfo) error {
	if info.OpaqueDocument == "" && len(info.Patches) == 0 {
		return errors.New("either opaque document or patches have to be supplied")
	}

	if info.OpaqueDocument != "" && len(info.Patches) > 0 {
		return errors.New("cannot provide both opaque document and patches")
	}

	supported := multihash.ValidCode(uint64(info.MultihashCode))

	if !supported {
		return fmt.Errorf("multihash[%d] not supported", info.MultihashCode)
	}

	if !hashing.IsComputedUsingMultihashAlgorithms(info.RecoveryCommitment, []uint{info.MultihashCode}) {
		return errors.New("next recovery commitment is not computed with the specified hash algorithm")
	}

	if !hashing.IsComputedUsingMultihashAlgorithms(info.UpdateCommitment, []uint{info.MultihashCode}) {
		return errors.New("next update commitment is not computed with the specified hash algorithm")
	}

	if info.RecoveryCommitment == info.UpdateCommitment {
		return errors.New("recovery and update commitments cannot be equal, re-using public keys is not allowed")
	}

	return nil
}
