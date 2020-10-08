/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pubkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"

	"github.com/btcsuite/btcd/btcec"
	gojose "github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/json"

	internal "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

const (
	secp256k1Crv = "secp256k1"
	secp256k1Kty = "EC"
)

// GetPublicKeyJWK returns public key in JWK format.
func GetPublicKeyJWK(pubKey interface{}) (*jws.JWK, error) {
	internalJWK := internal.JWK{
		JSONWebKey: gojose.JSONWebKey{Key: pubKey},
	}

	switch key := pubKey.(type) {
	case ed25519.PublicKey:
		// handled automatically by gojose
	case *ecdsa.PublicKey:
		ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			// check because linter complains; should never happen
			return nil, errors.New("unexpected interface")
		}
		// using internal jwk wrapper marshall feature since gojose doesn't handle secp256k1 curve
		if ecdsaPubKey.Curve == btcec.S256() {
			internalJWK.Kty = secp256k1Kty
			internalJWK.Crv = secp256k1Crv
		}
	default:
		return nil, fmt.Errorf("unknown key type '%s'", reflect.TypeOf(key))
	}

	jsonJWK, err := internalJWK.MarshalJSON()
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
