/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecsigner

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"

	"github.com/btcsuite/btcd/btcec"

	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

// Signer implements signer interface.
type Signer struct {
	alg        string
	kid        string
	privateKey *ecdsa.PrivateKey
}

// New creates new ECDSA signer.
func New(privKey *ecdsa.PrivateKey, alg, kid string) *Signer {
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
	if signer.privateKey == nil {
		return nil, errors.New("private key not provided")
	}

	hasher := getHasher(signer.privateKey.Curve).New()

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

func getHasher(curve elliptic.Curve) crypto.Hash {
	switch curve {
	case elliptic.P256():
		return crypto.SHA256
	case elliptic.P384():
		return crypto.SHA384
	case elliptic.P521():
		return crypto.SHA512
	case btcec.S256():
		return crypto.SHA256
	default:
		return crypto.SHA256
	}
}
