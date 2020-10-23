/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
)

const (
	didSuffix = "whatever"
	opaqueDoc = "{}"

	signerErr = "signer error"

	sha2_256 = 18
)

func TestNewCreateRequest(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
	require.NoError(t, err)

	recoveryCommitment, err := commitment.Calculate(jwk, sha2_256, crypto.SHA256)
	require.NoError(t, err)

	t.Run("missing opaque document or patches", func(t *testing.T) {
		request, err := NewCreateRequest(&CreateRequestInfo{})
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "either opaque document or patches have to be supplied")
	})
	t.Run("cannot provide both opaque document and patches", func(t *testing.T) {
		request, err := NewCreateRequest(&CreateRequestInfo{OpaqueDocument: "{}", Patches: []patch.Patch{{}}})
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "cannot provide both opaque document and patches")
	})
	t.Run("recovery commitment error", func(t *testing.T) {
		request, err := NewCreateRequest(&CreateRequestInfo{OpaqueDocument: "{}", RecoveryCommitment: recoveryCommitment})
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "recovery commitment is not computed with the specified hash algorithm")
	})
	t.Run("update commitment error", func(t *testing.T) {
		info := &CreateRequestInfo{
			OpaqueDocument:     "{}",
			RecoveryCommitment: recoveryCommitment,
			MultihashCode:      sha2_256,
		}

		request, err := NewCreateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "update commitment is not computed with the specified hash algorithm")
	})
	t.Run("multihash not supported", func(t *testing.T) {
		info := &CreateRequestInfo{
			OpaqueDocument: "{}",
			MultihashCode:  55,
		}

		request, err := NewCreateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "multihash[55] not supported")
	})
	t.Run("error - malformed opaque doc", func(t *testing.T) {
		info := &CreateRequestInfo{
			OpaqueDocument:     `{,}`,
			RecoveryCommitment: recoveryCommitment,
			UpdateCommitment:   recoveryCommitment,
			MultihashCode:      sha2_256,
		}

		request, err := NewCreateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "invalid character ','")
	})
	t.Run("success - opaque document", func(t *testing.T) {
		info := &CreateRequestInfo{
			OpaqueDocument:     "{}",
			RecoveryCommitment: recoveryCommitment,
			UpdateCommitment:   recoveryCommitment,
			MultihashCode:      sha2_256,
		}

		request, err := NewCreateRequest(info)
		require.NoError(t, err)
		require.NotEmpty(t, request)
	})

	t.Run("success - patches", func(t *testing.T) {
		p, err := patch.NewAddPublicKeysPatch(addKeys)
		require.NoError(t, err)

		info := &CreateRequestInfo{
			Patches:            []patch.Patch{p},
			RecoveryCommitment: recoveryCommitment,
			UpdateCommitment:   recoveryCommitment,
			MultihashCode:      sha2_256,
		}

		request, err := NewCreateRequest(info)
		require.NoError(t, err)
		require.NotEmpty(t, request)
	})
}

const addKeys = `[{
	"id": "test",
	"type": "JsonWebKey2020",
	"purpose": ["general"],
	"jwk": {
		"kty": "EC",
		"crv": "P-256K",
		"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA"
	}
}]`
