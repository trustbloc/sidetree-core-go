/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signutil

import (
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/internal/canonicalizer"
	internaljws "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

// Signer defines JWS Signer interface that will be used to sign required data in Sidetree request
type Signer interface {
	// Sign signs data and returns signature value
	Sign(data []byte) ([]byte, error)

	// Headers provides required JWS protected headers. It provides information about signing key and algorithm.
	Headers() jws.Headers
}

//SignModel signs model
func SignModel(model interface{}, signer Signer) (string, error) {
	// first you normalize model
	signedDataBytes, err := canonicalizer.MarshalCanonical(model)
	if err != nil {
		return "", err
	}

	return SignPayload(signedDataBytes, signer)
}

// SignPayload allows for singing payload
func SignPayload(payload []byte, signer Signer) (string, error) {
	alg, ok := signer.Headers().Algorithm()
	if !ok || alg == "" {
		return "", errors.New("signing algorithm is required")
	}

	jwsSignature, err := internaljws.NewJWS(signer.Headers(), nil, payload, signer)
	if err != nil {
		return "", err
	}

	return jwsSignature.SerializeCompact(false)
}
