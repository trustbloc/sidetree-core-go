/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationparser

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/client"
)

func TestParser_GetCommitment(t *testing.T) {
	p := mocks.NewMockProtocolClient()

	parser := New(p.Protocol)

	recoveryKey, _, err := generateKeyAndCommitment(p.Protocol)
	require.NoError(t, err)

	updateKey, _, err := generateKeyAndCommitment(p.Protocol)
	require.NoError(t, err)

	_, recoveryCommitment, err := generateKeyAndCommitment(p.Protocol)
	require.NoError(t, err)

	_, updateCommitment, err := generateKeyAndCommitment(p.Protocol)
	require.NoError(t, err)

	t.Run("success - recover", func(t *testing.T) {
		recover, err := generateRecoverRequest(recoveryKey, recoveryCommitment, parser.Protocol)
		require.NoError(t, err)

		c, err := parser.GetCommitment(recover)
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, c, recoveryCommitment)
	})

	t.Run("success - deactivate", func(t *testing.T) {
		deactivate, err := generateDeactivateRequest(recoveryKey)
		require.NoError(t, err)

		c, err := parser.GetCommitment(deactivate)
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, c, "")
	})

	t.Run("success - update", func(t *testing.T) {
		update, err := generateUpdateRequest(updateKey, updateCommitment, parser.Protocol)
		require.NoError(t, err)

		c, err := parser.GetCommitment(update)
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, c, updateCommitment)
	})

	t.Run("success - update", func(t *testing.T) {
		update, err := generateUpdateRequest(updateKey, updateCommitment, parser.Protocol)
		require.NoError(t, err)

		c, err := parser.GetCommitment(update)
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, c, updateCommitment)
	})

	t.Run("error - create", func(t *testing.T) {
		create, err := generateCreateRequest(recoveryCommitment, updateCommitment, parser.Protocol)
		require.NoError(t, err)

		c, err := parser.GetCommitment(create)
		require.Error(t, err)
		require.Empty(t, c)
		require.Contains(t, err.Error(), "operation type 'create' not supported for getting next operation commitment")
	})

	t.Run("error - parse operation fails", func(t *testing.T) {
		c, err := parser.GetCommitment([]byte(`{"type":"other"}`))
		require.Error(t, err)
		require.Empty(t, c)
		require.Contains(t, err.Error(), "get commitment - parse operation error")
	})
}

func TestParser_GetRevealValue(t *testing.T) {
	p := mocks.NewMockProtocolClient()

	parser := New(p.Protocol)

	recoveryKey, _, err := generateKeyAndCommitment(p.Protocol)
	require.NoError(t, err)

	updateKey, _, err := generateKeyAndCommitment(p.Protocol)
	require.NoError(t, err)

	_, recoveryCommitment, err := generateKeyAndCommitment(p.Protocol)
	require.NoError(t, err)

	_, updateCommitment, err := generateKeyAndCommitment(p.Protocol)
	require.NoError(t, err)

	t.Run("success - recover", func(t *testing.T) {
		recover, err := generateRecoverRequest(recoveryKey, recoveryCommitment, parser.Protocol)
		require.NoError(t, err)

		revealJWK, err := parser.GetRevealValue(recover)
		require.NoError(t, err)
		require.NotNil(t, revealJWK)

		pubJWK, err := pubkey.GetPublicKeyJWK(&recoveryKey.PublicKey)
		require.NoError(t, err)

		require.Equal(t, revealJWK, pubJWK)
	})

	t.Run("success - deactivate", func(t *testing.T) {
		deactivate, err := generateDeactivateRequest(recoveryKey)
		require.NoError(t, err)

		revealJWK, err := parser.GetRevealValue(deactivate)
		require.NoError(t, err)
		require.NotNil(t, revealJWK)

		pubJWK, err := pubkey.GetPublicKeyJWK(&recoveryKey.PublicKey)
		require.NoError(t, err)

		require.Equal(t, revealJWK, pubJWK)
	})

	t.Run("success - update", func(t *testing.T) {
		update, err := generateUpdateRequest(updateKey, updateCommitment, parser.Protocol)
		require.NoError(t, err)

		revealJWK, err := parser.GetRevealValue(update)
		require.NoError(t, err)
		require.NotNil(t, revealJWK)

		pubJWK, err := pubkey.GetPublicKeyJWK(&updateKey.PublicKey)
		require.NoError(t, err)

		require.Equal(t, revealJWK, pubJWK)
	})

	t.Run("error - create", func(t *testing.T) {
		create, err := generateCreateRequest(recoveryCommitment, updateCommitment, parser.Protocol)
		require.NoError(t, err)

		c, err := parser.GetRevealValue(create)
		require.Error(t, err)
		require.Empty(t, c)
		require.Contains(t, err.Error(), "operation type 'create' not supported for getting operation reveal value")
	})

	t.Run("error - parse operation fails", func(t *testing.T) {
		c, err := parser.GetRevealValue([]byte(`{"type":"other"}`))
		require.Error(t, err)
		require.Empty(t, c)
		require.Contains(t, err.Error(), "get reveal value - parse operation error")
	})
}

func generateRecoverRequest(recoveryKey *ecdsa.PrivateKey, commitment string, p protocol.Protocol) ([]byte, error) {
	jwk, err := pubkey.GetPublicKeyJWK(&recoveryKey.PublicKey)
	if err != nil {
		return nil, err
	}

	_, updateCommitment, err := generateKeyAndCommitment(p)
	if err != nil {
		return nil, err
	}

	info := &client.RecoverRequestInfo{
		DidSuffix:          "recover-suffix",
		OpaqueDocument:     `{"test":"value"}`,
		RecoveryCommitment: commitment,
		UpdateCommitment:   updateCommitment, // not evaluated in operation getting commitment/reveal value
		RecoveryKey:        jwk,
		MultihashCode:      p.MultihashAlgorithm,
		Signer:             ecsigner.New(recoveryKey, "ES256", ""),
	}

	return client.NewRecoverRequest(info)
}

func generateCreateRequest(recoveryCommitment, updateCommitment string, p protocol.Protocol) ([]byte, error) {
	info := &client.CreateRequestInfo{
		OpaqueDocument:     `{"test":"value"}`,
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      p.MultihashAlgorithm,
	}

	return client.NewCreateRequest(info)
}

func generateDeactivateRequest(recoveryKey *ecdsa.PrivateKey) ([]byte, error) {
	jwk, err := pubkey.GetPublicKeyJWK(&recoveryKey.PublicKey)
	if err != nil {
		return nil, err
	}
	info := &client.DeactivateRequestInfo{
		DidSuffix:   "deactivate-suffix",
		Signer:      ecsigner.New(recoveryKey, "ES256", ""),
		RecoveryKey: jwk,
	}

	return client.NewDeactivateRequest(info)
}

func generateUpdateRequest(updateKey *ecdsa.PrivateKey, commitment string, p protocol.Protocol) ([]byte, error) {
	jwk, err := pubkey.GetPublicKeyJWK(&updateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	testPatch, err := patch.NewJSONPatch(`[{"op": "replace", "path": "/name", "value": "Jane"}]`)
	if err != nil {
		return nil, err
	}

	info := &client.UpdateRequestInfo{
		DidSuffix:        "update-suffix",
		Signer:           ecsigner.New(updateKey, "ES256", "key-1"),
		UpdateCommitment: commitment,
		UpdateKey:        jwk,
		Patches:          []patch.Patch{testPatch},
		MultihashCode:    p.MultihashAlgorithm,
	}

	return client.NewUpdateRequest(info)
}

func generateKeyAndCommitment(p protocol.Protocol) (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}

	pubKey, err := pubkey.GetPublicKeyJWK(&key.PublicKey)
	if err != nil {
		return nil, "", err
	}

	c, err := commitment.Calculate(pubKey, p.MultihashAlgorithm)
	if err != nil {
		return nil, "", err
	}

	return key, c, nil
}
