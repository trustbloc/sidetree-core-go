/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package hashing

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/hashing/sha256"
)

const algSHA256 = "SHA256"

func TestNew(t *testing.T) {
	t.Run("test new success", func(t *testing.T) {
		registry := New()
		require.NotNil(t, registry)
	})
	t.Run("test new with SHA256 algorithm option", func(t *testing.T) {
		registry := New(WithAlgorithm(sha256.New()))
		require.NotNil(t, registry)
	})
	t.Run("test new with default algorithms", func(t *testing.T) {
		registry := New(WithDefaultAlgorithms())
		require.NotNil(t, registry)
	})
}
func TestRegistry_Hash(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		registry := New(WithAlgorithm(sha256.New()))

		test := []byte("hello world")
		h, err := registry.Hash(algSHA256, test)
		require.NoError(t, err)
		require.NotEmpty(t, h)
	})

	t.Run("error - algorithm not supported", func(t *testing.T) {
		registry := New()

		test := []byte("test data")
		h, err := registry.Hash("other", test)
		require.Error(t, err)
		require.Empty(t, h)
		require.Contains(t, err.Error(), "hashing algorithm 'other' not supported")
	})
}

func TestRegistry_Close(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		registry := New(WithAlgorithm(sha256.New()), WithAlgorithm(&mockAlgorithm{}))

		require.NoError(t, registry.Close())
	})
	t.Run("success", func(t *testing.T) {
		registry := New(WithAlgorithm(&mockAlgorithm{CloseErr: errors.New("close error")}))
		require.Error(t, registry.Close())
	})
}

type mockAlgorithm struct {
	CloseErr error
}

// Hash will mock hashing data
func (m *mockAlgorithm) Hash(data []byte) []byte {
	return data
}

// Accept algorithm
func (m *mockAlgorithm) Accept(alg string) bool {
	return true
}

// Close will close resources
func (m *mockAlgorithm) Close() error {
	return m.CloseErr
}
