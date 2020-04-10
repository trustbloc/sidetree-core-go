/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"

	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

const (
	p256KeySize      = 32
	p384KeySize      = 48
	p521KeySize      = 66
	secp256k1KeySize = 32
)

//VerifySignature verifies signature against public key in JWK format
func VerifySignature(jwk *jws.JWK, signature, msg []byte) error {
	switch jwk.Kty {
	case "EC":
		return verifyECSignature(jwk, signature, msg)
	default:
		return fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

func verifyECSignature(jwk *jws.JWK, signature, msg []byte) error {
	ec := parseEllipticCurve(jwk.Crv)
	if ec == nil {
		return fmt.Errorf("ecdsa: unsupported elliptic curve '%s'", jwk.Crv)
	}

	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		return err
	}

	internalJWK := JWK{
		Kty: jwk.Kty,
		Crv: jwk.Crv,
	}

	err = internalJWK.UnmarshalJSON(jwkBytes)
	if err != nil {
		return err
	}

	ecdsaPubKey, ok := internalJWK.JSONWebKey.Key.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("not an EC public key")
	}

	if len(signature) != 2*ec.keySize {
		return errors.New("ecdsa: invalid signature size")
	}

	hasher := ec.hash.New()

	_, err = hasher.Write(msg)
	if err != nil {
		return errors.New("ecdsa: hash error")
	}

	hash := hasher.Sum(nil)

	r := big.NewInt(0).SetBytes(signature[:ec.keySize])
	s := big.NewInt(0).SetBytes(signature[ec.keySize:])

	verified := ecdsa.Verify(ecdsaPubKey, hash, r, s)
	if !verified {
		return errors.New("ecdsa: invalid signature")
	}

	return nil
}

type ellipticCurve struct {
	curve   elliptic.Curve
	keySize int
	hash    crypto.Hash
}

func parseEllipticCurve(curve string) *ellipticCurve {
	switch curve {
	case "P-256":
		return &ellipticCurve{
			curve:   elliptic.P256(),
			keySize: p256KeySize,
			hash:    crypto.SHA256,
		}
	case "P-384":
		return &ellipticCurve{
			curve:   elliptic.P384(),
			keySize: p384KeySize,
			hash:    crypto.SHA384,
		}
	case "P-521":
		return &ellipticCurve{
			curve:   elliptic.P521(),
			keySize: p521KeySize,
			hash:    crypto.SHA512,
		}
	case "secp256k1":
		return &ellipticCurve{
			curve:   btcec.S256(),
			keySize: secp256k1KeySize,
			hash:    crypto.SHA256,
		}
	default:
		return nil
	}
}
