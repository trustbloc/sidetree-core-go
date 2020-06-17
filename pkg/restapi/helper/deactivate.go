/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package helper

import (
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/internal/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/signutil"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// Signer defines JWS Signer interface that will be used to sign required data in Sidetree request
type Signer interface {
	// Sign signs data and returns signature value
	Sign(data []byte) ([]byte, error)

	// Headers provides required JWS protected headers. It provides information about signing key and algorithm.
	Headers() jws.Headers
}

//DeactivateRequestInfo is the information required to create deactivate request
type DeactivateRequestInfo struct {

	// DID Suffix of the document to be deactivated
	DidSuffix string

	// Recovery key for current deactivate request
	RecoveryKey *jws.JWK

	// Signer that will be used for signing specific subset of request data
	// Signer for recover operation must be recovery key
	Signer Signer
}

// NewDeactivateRequest is utility function to create payload for 'deactivate' request
func NewDeactivateRequest(info *DeactivateRequestInfo) ([]byte, error) {
	if err := validateDeactivateRequest(info); err != nil {
		return nil, err
	}

	signedDataModel := model.DeactivateSignedDataModel{
		DidSuffix:   info.DidSuffix,
		RecoveryKey: info.RecoveryKey,
	}

	jws, err := signutil.SignModel(signedDataModel, info.Signer)
	if err != nil {
		return nil, err
	}

	schema := &model.DeactivateRequest{
		Operation:  model.OperationTypeDeactivate,
		DidSuffix:  info.DidSuffix,
		SignedData: jws,
	}

	return canonicalizer.MarshalCanonical(schema)
}

func validateDeactivateRequest(info *DeactivateRequestInfo) error {
	if info.DidSuffix == "" {
		return errors.New("missing did unique suffix")
	}

	return validateSigner(info.Signer, true)
}

func validateSigner(signer Signer, recovery bool) error {
	if signer == nil {
		return errors.New("missing signer")
	}

	if signer.Headers() == nil {
		return errors.New("missing protected headers")
	}

	kid, ok := signer.Headers().KeyID()
	if recovery && ok {
		return errors.New("kid must not be provided for recovery signer")
	}

	if !recovery && (!ok || kid == "") {
		return errors.New("kid has to be provided for update signer")
	}

	return nil
}
