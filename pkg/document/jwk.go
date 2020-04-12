/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

// JWK represents public key in JWK format
type JWK map[string]interface{}

// NewJWK creates new JWK
func NewJWK(jwk map[string]interface{}) JWK {
	return jwk
}

// Kty is key type
func (jwk JWK) Kty() string {
	return stringEntry(jwk["kty"])
}

// Crv is curve
func (jwk JWK) Crv() string {
	return stringEntry(jwk["crv"])
}

// X is x
func (jwk JWK) X() string {
	return stringEntry(jwk["x"])
}

// Y is y
func (jwk JWK) Y() string {
	return stringEntry(jwk["y"])
}
