/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"

	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

// Signer implements signer interface
type Signer struct {
	alg        string
	kid        string
	privateKey *ecdsa.PrivateKey
}

// NewECDSASigner created new ecdsa signer
func NewECDSASigner(privKey *ecdsa.PrivateKey, alg, kid string) *Signer {
	return &Signer{privateKey: privKey, kid: kid, alg: alg}
}

// Headers provides required JWS protected headers. It provides information about signing key and algorithm.
func (signer *Signer) Headers() jws.Headers {
	headers := make(jws.Headers)
	headers[jws.HeaderKeyID] = signer.kid
	headers[jws.HeaderAlgorithm] = signer.alg

	return headers
}

// Sign signs msg and returns signature value
func (signer *Signer) Sign(msg []byte) ([]byte, error) {
	hasher := crypto.SHA256.New()

	_, err := hasher.Write(msg)
	if err != nil {
		return nil, err
	}

	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, signer.privateKey, hashed)
	if err != nil {
		return nil, err
	}

	curveBits := signer.privateKey.Curve.Params().BitSize

	const bitsInByte = 8
	keyBytes := curveBits / bitsInByte
	if curveBits%bitsInByte > 0 {
		keyBytes++
	}

	return append(copyPadded(r.Bytes(), keyBytes), copyPadded(s.Bytes(), keyBytes)...), nil
}

func copyPadded(source []byte, size int) []byte {
	dest := make([]byte, size)
	copy(dest[size-len(source):], source)

	return dest
}
