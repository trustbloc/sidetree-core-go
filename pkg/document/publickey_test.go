/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPublicKey(t *testing.T) {

	pk := NewPublicKey(map[string]interface{}{})
	require.Empty(t, pk.ID())
	require.Empty(t, pk.Type())
	require.Empty(t, pk.Controller())

	pk = NewPublicKey(map[string]interface{}{
		"id":              "did:example:123456789abcdefghi#keys-1",
		"type":            "RsaVerificationKey2018",
		"controller":      "did:example:123456789abcdefghi",
		"publicKeyPem":    "-----BEGIN PUBLIC KEY...END PUBLIC KEY-----",
		"publicKeyBase64": "Base64",
		"publicKeyBase58": "Base58",
		"publicKeyHex":    "Hex",
		"publicKeyJwk":    "Jwk",
		"other":           "otherValue",
	})
	require.Equal(t, "did:example:123456789abcdefghi#keys-1", pk.ID())
	require.Equal(t, "RsaVerificationKey2018", pk.Type())
	require.Equal(t, "did:example:123456789abcdefghi", pk.Controller())
	require.Equal(t, "-----BEGIN PUBLIC KEY...END PUBLIC KEY-----", pk.PublicKeyPEM())
	require.Equal(t, "Base64", pk.PublicKeyBase64())
	require.Equal(t, "Base58", pk.PublicKeyBase58())
	require.Equal(t, "Hex", pk.PublicKeyHex())
	require.Equal(t, "Jwk", pk.PublicKeyJWK())
	require.Equal(t, "otherValue", pk["other"])

}
