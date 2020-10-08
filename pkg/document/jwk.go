/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

import "errors"

// JWK represents public key in JWK format.
type JWK map[string]interface{}

// NewJWK creates new JWK.
func NewJWK(jwk map[string]interface{}) JWK {
	return jwk
}

// Kty is key type.
func (jwk JWK) Kty() string {
	return stringEntry(jwk["kty"])
}

// Crv is curve.
func (jwk JWK) Crv() string {
	return stringEntry(jwk["crv"])
}

// X is x.
func (jwk JWK) X() string {
	return stringEntry(jwk["x"])
}

// Y is y.
func (jwk JWK) Y() string {
	return stringEntry(jwk["y"])
}

// Validate will validate JWK properties.
func (jwk JWK) Validate() error {
	// TODO: validation of the JWK fields depends on the algorithm (issue-409)
	// For now check required fields for currently supported algorithms secp256k1, P-256, P-384, P-512 and Ed25519

	if jwk.Crv() == "" {
		return errors.New("JWK crv is missing")
	}

	if jwk.Kty() == "" {
		return errors.New("JWK kty is missing")
	}

	if jwk.X() == "" {
		return errors.New("JWK x is missing")
	}

	return nil
}
