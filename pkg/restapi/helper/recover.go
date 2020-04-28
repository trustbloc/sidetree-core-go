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

// NewRecoverRequest is utility function to create payload for 'recovery' request
func NewRecoverRequest(info *RecoverRequestInfo) ([]byte, error) {
	err := validateRecoverRequest(info)
	if err != nil {
		return nil, err
	}

	patches, err := patch.PatchesFromDocument(info.OpaqueDocument)
	if err != nil {
		return nil, err
	}

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

	jws, err := signutil.SignModel(signedDataModel, info.Signer)
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

	return canonicalizer.MarshalCanonical(schema)
}

func validateRecoverRequest(info *RecoverRequestInfo) error {
	if info.DidSuffix == "" {
		return errors.New("missing did unique suffix")
	}

	if info.OpaqueDocument == "" {
		return errors.New("missing opaque document")
	}

	if err := validateSigner(info.Signer, true); err != nil {
		return err
	}

	return validateRecoveryKey(info.RecoveryKey)
}
