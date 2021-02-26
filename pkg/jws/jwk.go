/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jws

import "errors"

// JWK contains public key in JWK format.
type JWK struct {
	Kty   string `json:"kty"`
	Crv   string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`
	Nonce string `json:"nonce,omitempty"`
}

// Validate validates JWK.
func (jwk *JWK) Validate() error {
	if jwk.Crv == "" {
		return errors.New("JWK crv is missing")
	}

	if jwk.Kty == "" {
		return errors.New("JWK kty is missing")
	}

	if jwk.X == "" {
		return errors.New("JWK x is missing")
	}

	return nil
}
