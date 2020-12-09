/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"errors"
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/signutil"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
)

// Signer defines JWS Signer interface that will be used to sign required data in Sidetree request.
type Signer interface {
	// Sign signs data and returns signature value
	Sign(data []byte) ([]byte, error)

	// Headers provides required JWS protected headers. It provides information about signing key and algorithm.
	Headers() jws.Headers
}

// DeactivateRequestInfo is the information required to create deactivate request.
type DeactivateRequestInfo struct {

	// DidSuffix is the suffix of the document to be deactivated
	DidSuffix string

	// RecoveryKey is recovery key for current deactivate request
	RecoveryKey *jws.JWK

	// Signer that will be used for signing specific subset of request data
	// Signer for recover operation must be recovery key
	Signer Signer

	// RevealValue is reveal value
	RevealValue string
}

// NewDeactivateRequest is utility function to create payload for 'deactivate' request.
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
		Operation:   operation.TypeDeactivate,
		DidSuffix:   info.DidSuffix,
		RevealValue: info.RevealValue,
		SignedData:  jws,
	}

	return canonicalizer.MarshalCanonical(schema)
}

func validateDeactivateRequest(info *DeactivateRequestInfo) error {
	if info.DidSuffix == "" {
		return errors.New("missing did unique suffix")
	}

	if info.RevealValue == "" {
		return errors.New("missing reveal value")
	}

	return validateSigner(info.Signer)
}

func validateSigner(signer Signer) error {
	if signer == nil {
		return errors.New("missing signer")
	}

	if signer.Headers() == nil {
		return errors.New("missing protected headers")
	}

	alg, ok := signer.Headers().Algorithm()
	if !ok {
		return errors.New("algorithm must be present in the protected header")
	}

	if alg == "" {
		return errors.New("algorithm cannot be empty in the protected header")
	}

	allowedHeaders := map[string]bool{
		jws.HeaderAlgorithm: true,
		jws.HeaderKeyID:     true,
	}

	for h := range signer.Headers() {
		if _, ok := allowedHeaders[h]; !ok {
			return fmt.Errorf("header '%s' is not allowed in the protected headers", h)
		}
	}

	return nil
}
