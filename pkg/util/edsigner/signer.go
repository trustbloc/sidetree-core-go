/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edsigner

import (
	"crypto/ed25519"
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

// Signer implements signer interface.
type Signer struct {
	alg        string
	kid        string
	privateKey ed25519.PrivateKey
}

// New returns ED25519 signer.
func New(privKey ed25519.PrivateKey, alg, kid string) *Signer {
	return &Signer{privateKey: privKey, kid: kid, alg: alg}
}

// Headers provides required JWS protected headers. It provides information about signing key and algorithm.
func (signer *Signer) Headers() jws.Headers {
	headers := make(jws.Headers)

	if signer.alg != "" {
		headers[jws.HeaderAlgorithm] = signer.alg
	}

	if signer.kid != "" {
		headers[jws.HeaderKeyID] = signer.kid
	}

	return headers
}

// Sign signs msg and returns signature value.
func (signer *Signer) Sign(msg []byte) ([]byte, error) {
	if l := len(signer.privateKey); l != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}

	return ed25519.Sign(signer.privateKey, msg), nil
}
