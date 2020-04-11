/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/ecdsa"
	"encoding/json"

	gojose "github.com/square/go-jose/v3"

	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

// GetECPublicKey returns EC public key in JWK format
func GetECPublicKey(privateKey *ecdsa.PrivateKey) (*jws.JWK, error) {
	joseJWK := gojose.JSONWebKey{Key: &privateKey.PublicKey}
	jsonJWK, err := joseJWK.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var jwk jws.JWK
	err = json.Unmarshal(jsonJWK, &jwk)
	if err != nil {
		return nil, err
	}

	return &jwk, nil
}
