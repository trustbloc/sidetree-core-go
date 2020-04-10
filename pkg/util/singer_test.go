/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	curve := elliptic.P256()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	signer := NewECDSASigner(privKey, "ES256", "key-1")

	msg := []byte("test message")
	signature, err := signer.Sign(msg)
	require.NoError(t, err)
	require.NotEmpty(t, signature)
}

func TestHeaders(t *testing.T) {
	curve := elliptic.P256()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	signer := NewECDSASigner(privKey, "ES256", "key-1")

	// verify headers
	kid, ok := signer.Headers().KeyID()
	require.Equal(t, true, ok)
	require.Equal(t, "key-1", kid)

	alg, ok := signer.Headers().Algorithm()
	require.Equal(t, true, ok)
	require.Equal(t, "ES256", alg)
}
