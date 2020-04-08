/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

const (
	jwkType          = "JwsVerificationKey2020"
	p256KeySize      = 32
	secp256k1KeySize = 32
)

// PublicKey contains a result of public key resolution.
type PublicKey struct {
	Type  string
	Value []byte
	JWK   *JWK
}

// PublicKeyVerifier verifies signatures against public key.
// Supported algorithms: Ed25519 and EC (P-256, secp256k1)
type PublicKeyVerifier struct {
}

// Verify will verify a signature.
func (v *PublicKeyVerifier) Verify(pubKey *PublicKey, doc, signature []byte) error {
	// A presence of JSON Web Key is mandatory (due to JwsVerificationKey2020 type).
	if pubKey.JWK == nil {
		return ErrJWKNotPresent
	}

	if pubKey.Type != jwkType {
		return ErrTypeNotJwsVerificationKey2020
	}

	switch pubKey.JWK.Kty {
	case "EC":
		return v.verifyEllipticCurve(pubKey, signature, doc)
	case "OKP":
		return v.verifyEdDSA(pubKey, signature, doc)
	default:
		return fmt.Errorf("unsupported key type: %s", pubKey.JWK.Kty)
	}
}

func (v *PublicKeyVerifier) verifyEllipticCurve(pubKey *PublicKey, signature, msg []byte) error {
	ec := parseEllipticCurve(pubKey.JWK.Crv)
	if ec == nil {
		return fmt.Errorf("ecdsa: unsupported elliptic curve '%s'", pubKey.JWK.Crv)
	}

	pubKeyBytes := pubKey.Value

	x, y := elliptic.Unmarshal(ec.Curve, pubKeyBytes)
	if x == nil {
		return errors.New("ecdsa: invalid public key")
	}

	ecdsaPubKey := &ecdsa.PublicKey{
		Curve: ec.Curve,
		X:     x,
		Y:     y,
	}

	if len(signature) != 2*ec.KeySize {
		return errors.New("ecdsa: invalid signature size")
	}

	hasher := crypto.SHA256.New()

	_, err := hasher.Write(msg)
	if err != nil {
		return errors.New("ecdsa: hash error")
	}

	hash := hasher.Sum(nil)

	r := big.NewInt(0).SetBytes(signature[:ec.KeySize])
	s := big.NewInt(0).SetBytes(signature[ec.KeySize:])

	verified := ecdsa.Verify(ecdsaPubKey, hash, r, s)
	if !verified {
		return errors.New("ecdsa: invalid signature")
	}

	return nil
}

type ellipticCurve struct {
	Curve   elliptic.Curve
	KeySize int
}

func parseEllipticCurve(curve string) *ellipticCurve {
	switch curve {
	case "P-256":
		return &ellipticCurve{
			Curve:   elliptic.P256(),
			KeySize: p256KeySize,
		}
	case "secp256k1":
		return &ellipticCurve{
			Curve:   btcec.S256(),
			KeySize: secp256k1KeySize,
		}
	default:
		return nil
	}
}

func (v *PublicKeyVerifier) verifyEdDSA(pubKey *PublicKey, signature, msg []byte) error {
	if pubKey.JWK.Algorithm != "" && pubKey.JWK.Algorithm != "EdDSA" {
		return fmt.Errorf("unsupported OKP algorithm: %s", pubKey.JWK.Algorithm)
	}

	// Check the key size before calling ed25519.Verify() as it will panic in case of invalid key size.
	if len(pubKey.Value) != ed25519.PublicKeySize {
		return errors.New("ed25519: invalid key")
	}

	verified := ed25519.Verify(pubKey.Value, msg, signature)
	if !verified {
		return errors.New("ed25519: invalid signature")
	}

	return nil
}

var (
	// ErrJWKNotPresent is returned when no JWK is defined in a public key (must be defined for JwsVerificationKey2020).
	ErrJWKNotPresent = errors.New("JWK is not present")

	// ErrTypeNotJwsVerificationKey2020 is returned when a public key passed for signature verification has a type
	// different from JwsVerificationKey2020.
	ErrTypeNotJwsVerificationKey2020 = errors.New("a type of public key is not JwsVerificationKey2020")
)
