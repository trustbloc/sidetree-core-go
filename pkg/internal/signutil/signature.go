/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signutil

import (
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/canonicalizer"
	internaljws "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
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

//SignModel signs model
func SignModel(model interface{}, signer Signer) (*model.JWS, error) {
	// first you normalize model
	signedDataBytes, err := canonicalizer.MarshalCanonical(model)
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

	protected := &model.Header{
		Alg: alg,
	}

	kid, ok := signer.Headers().KeyID()
	if ok {
		protected.Kid = kid
	}

	jwsSignature, err := internaljws.NewJWS(signer.Headers(), nil, []byte(payload), signer)
	if err != nil {
		return nil, err
	}

	signature, err := jwsSignature.SerializeCompact(false)
	if err != nil {
		return nil, err
	}

	return &model.JWS{
		Protected: protected,
		Signature: signature,
		Payload:   payload,
	}, nil
}
