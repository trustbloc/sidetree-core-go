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
	"crypto/rand"
	"fmt"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	gojose "github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/json"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

func TestVerifySignature(t *testing.T) {
	t.Run("success EC P-256", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		jwk, err := getPublicKeyJWK(&privateKey.PublicKey)
		require.NoError(t, err)

		payload := []byte("test")

		signature := getECSignature(privateKey, payload, crypto.SHA256)
		err = VerifySignature(jwk, signature, payload)
		require.NoError(t, err)
	})

	t.Run("success EC P-384", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		jwk, err := getPublicKeyJWK(&privateKey.PublicKey)
		require.NoError(t, err)

		payload := []byte("test")

		signature := getECSignature(privateKey, payload, crypto.SHA384)
		err = VerifySignature(jwk, signature, payload)
		require.NoError(t, err)
	})

	t.Run("success EC P-521", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)

		jwk, err := getPublicKeyJWK(&privateKey.PublicKey)
		require.NoError(t, err)

		payload := []byte("test")

		signature := getECSignature(privateKey, payload, crypto.SHA512)
		err = VerifySignature(jwk, signature, payload)
		require.NoError(t, err)
	})

	t.Run("success EC secp256k1", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
		require.NoError(t, err)

		jwk, err := getPublicKeyJWK(&privateKey.PublicKey)
		require.NoError(t, err)

		payload := []byte("test")

		signature := getECSignature(privateKey, payload, crypto.SHA256)
		err = VerifySignature(jwk, signature, payload)
		require.NoError(t, err)
	})

	t.Run("success ED25519", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		payload := []byte("test message")
		signature := ed25519.Sign(privateKey, payload)

		jwk, err := getPublicKeyJWK(publicKey)
		require.NoError(t, err)

		err = VerifySignature(jwk, signature, payload)
		require.NoError(t, err)
	})

	t.Run("unsupported key type", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		jwk, err := getPublicKeyJWK(&privateKey.PublicKey)
		require.NoError(t, err)

		payload := []byte("test")
		signature := getECSignatureSHA256(privateKey, payload)

		jwk.Kty = "not-supported"
		err = VerifySignature(jwk, signature, payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key type is not supported for verifying signature")
	})
}

func TestVerifyECSignature(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		jwk, err := getPublicKeyJWK(&privateKey.PublicKey)
		require.NoError(t, err)

		payload := []byte("test")

		signature := getECSignatureSHA256(privateKey, payload)
		err = verifyECSignature(jwk, signature, payload)
		require.NoError(t, err)
	})
	t.Run("unsupported elliptic curve", func(t *testing.T) {
		jwk, err := getPublicKeyJWK(&privateKey.PublicKey)
		require.NoError(t, err)

		payload := []byte("test")
		signature := getECSignatureSHA256(privateKey, payload)

		jwk.Crv = "invalid"
		err = verifyECSignature(jwk, signature, payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported elliptic curve")
	})
	t.Run("invalid signature size", func(t *testing.T) {
		jwk, err := getPublicKeyJWK(&privateKey.PublicKey)
		require.NoError(t, err)

		err = verifyECSignature(jwk, []byte("signature"), []byte("test"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signature size")
	})
	t.Run("invalid signature", func(t *testing.T) {
		jwk, err := getPublicKeyJWK(&privateKey.PublicKey)
		require.NoError(t, err)

		signature := getECSignatureSHA256(privateKey, []byte("test"))

		err = verifyECSignature(jwk, signature, []byte("different"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "ecdsa: invalid signature")
	})
}

func TestVerifyED25519Signature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	payload := []byte("test message")
	signature := ed25519.Sign(privateKey, payload)

	t.Run("success", func(t *testing.T) {
		jwk, err := getPublicKeyJWK(publicKey)
		require.NoError(t, err)

		err = verifyEd25519Signature(jwk, signature, payload)
		require.NoError(t, err)
	})

	t.Run("invalid payload", func(t *testing.T) {
		jwk, err := getPublicKeyJWK(publicKey)
		require.NoError(t, err)

		err = verifyEd25519Signature(jwk, signature, []byte("different payload"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "ed25519: invalid signature")
	})

	t.Run("invalid signature", func(t *testing.T) {
		jwk, err := getPublicKeyJWK(publicKey)
		require.NoError(t, err)

		err = verifyEd25519Signature(jwk, []byte("signature"), payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "ed25519: invalid signature")
	})

	t.Run("invalid curve", func(t *testing.T) {
		jwk, err := getPublicKeyJWK(publicKey)
		require.NoError(t, err)
		jwk.Crv = "invalid"

		err = verifyEd25519Signature(jwk, signature, payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown curve")
	})

	t.Run("wrong key type - EC key", func(t *testing.T) {
		ecPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		jwk, err := getPublicKeyJWK(&ecPrivateKey.PublicKey)
		require.NoError(t, err)

		err = verifyEd25519Signature(jwk, signature, payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected public key type for ed25519")
	})
}

func getECSignatureSHA256(privateKey *ecdsa.PrivateKey, payload []byte) []byte {
	return getECSignature(privateKey, payload, crypto.SHA256)
}

func getECSignature(privKey *ecdsa.PrivateKey, payload []byte, hash crypto.Hash) []byte {
	hasher := hash.New()

	_, err := hasher.Write(payload)
	if err != nil {
		panic(err)
	}

	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, hashed)
	if err != nil {
		panic(err)
	}

	curveBits := privKey.Curve.Params().BitSize

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	copyPadded := func(source []byte, size int) []byte {
		dest := make([]byte, size)
		copy(dest[size-len(source):], source)

		return dest
	}

	return append(copyPadded(r.Bytes(), keyBytes), copyPadded(s.Bytes(), keyBytes)...)
}

// getPublicKeyJWK returns public key in JWK format.
func getPublicKeyJWK(pubKey interface{}) (*jws.JWK, error) {
	internalJWK := JWK{
		JSONWebKey: gojose.JSONWebKey{Key: pubKey},
	}

	switch key := pubKey.(type) {
	case ed25519.PublicKey:
		// handled automatically by gojose
	case *ecdsa.PublicKey:
		ecdsaPubKey := pubKey.(*ecdsa.PublicKey)
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
