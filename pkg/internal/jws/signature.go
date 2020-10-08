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

// VerifySignature verifies signature against public key in JWK format.
func VerifySignature(jwk *jws.JWK, signature, msg []byte) error {
	switch jwk.Kty {
	case "EC":
		return verifyECSignature(jwk, signature, msg)
	case "OKP":
		return verifyEd25519Signature(jwk, signature, msg)
	default:
		return fmt.Errorf("'%s' key type is not supported for verifying signature", jwk.Kty)
	}
}

func verifyEd25519Signature(jwk *jws.JWK, signature, msg []byte) error {
	pubKey, err := GetED25519PublicKey(jwk)
	if err != nil {
		return err
	}

	verified := ed25519.Verify(pubKey, msg, signature)
	if !verified {
		return errors.New("ed25519: invalid signature")
	}

	return nil
}

// GetED25519PublicKey retunns ed25519 public key.
func GetED25519PublicKey(jwk *jws.JWK) (ed25519.PublicKey, error) {
	jsonBytes, err := json.Marshal(jwk)
	if err != nil {
		return nil, err
	}

	var internalJWK JWK
	err = internalJWK.UnmarshalJSON(jsonBytes)
	if err != nil {
		return nil, err
	}

	pubKey, ok := internalJWK.Key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("unexpected public key type for ed25519")
	}

	// ed25519 panics if key size is wrong
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, errors.New("ed25519: invalid key")
	}

	return pubKey, nil
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
