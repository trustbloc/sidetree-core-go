/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/model"
)

const (
	didSuffix = "whatever"
	opaqueDoc = "{}"

	signerErr = "signer error"

	sha2_256 = 18
)

func TestNewCreateRequest(t *testing.T) {
	recoverPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	updatePrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	recoverJWK, err := pubkey.GetPublicKeyJWK(&recoverPrivateKey.PublicKey)
	require.NoError(t, err)

	updateJWK, err := pubkey.GetPublicKeyJWK(&updatePrivateKey.PublicKey)
	require.NoError(t, err)

	recoveryCommitment, err := commitment.GetCommitment(recoverJWK, sha2_256)
	require.NoError(t, err)

	updateCommitment, err := commitment.GetCommitment(updateJWK, sha2_256)
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
			UpdateCommitment:   updateCommitment,
			MultihashCode:      sha2_256,
		}

		request, err := NewCreateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "invalid character ','")
	})

	t.Run("error - update and recover commitment equal", func(t *testing.T) {
		info := &CreateRequestInfo{
			OpaqueDocument:     "{}",
			RecoveryCommitment: recoveryCommitment,
			UpdateCommitment:   recoveryCommitment,
			MultihashCode:      sha2_256,
		}

		request, err := NewCreateRequest(info)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "recovery and update commitments cannot be equal, re-using public keys is not allowed")
	})

	t.Run("success - opaque document", func(t *testing.T) {
		info := &CreateRequestInfo{
			OpaqueDocument:     "{}",
			RecoveryCommitment: recoveryCommitment,
			UpdateCommitment:   updateCommitment,
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
			UpdateCommitment:   updateCommitment,
			MultihashCode:      sha2_256,
		}

		request, err := NewCreateRequest(info)
		require.NoError(t, err)
		require.NotEmpty(t, request)
	})

	t.Run("success - optional params (entity type and anchor origin)", func(t *testing.T) {
		p, err := patch.NewAddPublicKeysPatch(addKeys)
		require.NoError(t, err)

		info := &CreateRequestInfo{
			Patches:            []patch.Patch{p},
			RecoveryCommitment: recoveryCommitment,
			UpdateCommitment:   updateCommitment,
			AnchorOrigin:       "anchor-origin",
			Type:               "did-entity-type",
			MultihashCode:      sha2_256,
		}

		bytes, err := NewCreateRequest(info)
		require.NoError(t, err)
		require.NotEmpty(t, bytes)

		var request model.CreateRequest
		err = json.Unmarshal(bytes, &request)
		require.NoError(t, err)

		require.Contains(t, request.SuffixData.AnchorOrigin, "anchor-origin")
		require.Contains(t, request.SuffixData.Type, "did-entity-type")
	})
}

const addKeys = `[{
	"id": "test",
	"type": "JsonWebKey2020",
	"purposes": ["authentication"],
	"publicKeyJwk": {
		"kty": "EC",
		"crv": "P-256K",
		"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA"
	}
}]`
