/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package compression

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/compression/gzip"
)

const algGZIP = "GZIP"

func TestNew(t *testing.T) {
	t.Run("test new success", func(t *testing.T) {
		registry := New()
		require.NotNil(t, registry)
	})
	t.Run("test new with gzip algorithm option", func(t *testing.T) {
		registry := New(WithAlgorithm(gzip.New()))
		require.NotNil(t, registry)
	})
	t.Run("test new with default algorithms", func(t *testing.T) {
		registry := New(WithDefaultAlgorithms())
		require.NotNil(t, registry)
	})
}

func TestRegistry_Compress(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		registry := New(WithAlgorithm(gzip.New()))

		test := []byte("hello world")
		compressed, err := registry.Compress(algGZIP, test)
		require.NoError(t, err)
		require.NotEmpty(t, compressed)

		data, err := registry.Decompress(algGZIP, compressed)
		require.NoError(t, err)
		require.NotEmpty(t, data)
		require.Equal(t, data, test)
	})

	t.Run("error - algorithm not supported", func(t *testing.T) {
		registry := New()

		test := []byte("test data")
		compressed, err := registry.Compress(algGZIP, test)
		require.Error(t, err)
		require.Empty(t, compressed)
		require.Contains(t, err.Error(), "compression algorithm 'GZIP' not supported")
	})

	t.Run("error - compression error", func(t *testing.T) {
		registry := New(WithAlgorithm(&mockAlgorithm{CompressErr: errors.New("test error")}))

		test := []byte("test data")
		compressed, err := registry.Compress(algGZIP, test)
		require.Error(t, err)
		require.Empty(t, compressed)
		require.Contains(t, err.Error(), "test error")
	})
}

func TestRegistry_Decompress(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		registry := New(WithAlgorithm(gzip.New()))

		test := []byte("hello world")
		compressed, err := registry.Compress(algGZIP, test)
		require.NoError(t, err)
		require.NotEmpty(t, compressed)

		data, err := registry.Decompress(algGZIP, compressed)
		require.NoError(t, err)
		require.NotEmpty(t, data)
		require.Equal(t, data, test)
	})

	t.Run("error - algorithm not supported", func(t *testing.T) {
		registry := New()

		test := []byte("test data")
		data, err := registry.Decompress("alg", test)
		require.Error(t, err)
		require.Empty(t, data)
		require.Contains(t, err.Error(), "compression algorithm 'alg' not supported")
	})

	t.Run("error - compression error", func(t *testing.T) {
		registry := New(WithAlgorithm(&mockAlgorithm{DecompressErr: errors.New("test error")}))

		test := []byte("test data")
		compressed, err := registry.Decompress("mock", test)
		require.Error(t, err)
		require.Empty(t, compressed)
		require.Contains(t, err.Error(), "test error")
	})
}

func TestRegistry_Close(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		registry := New(WithAlgorithm(gzip.New()), WithAlgorithm(&mockAlgorithm{}))

		require.NoError(t, registry.Close())
	})
	t.Run("success", func(t *testing.T) {
		registry := New(WithAlgorithm(&mockAlgorithm{CloseErr: errors.New("close error")}))
		require.Error(t, registry.Close())
	})
}

type mockAlgorithm struct {
	CompressErr   error
	DecompressErr error
	CloseErr      error
}

// Compress will mock compressing data.
func (m *mockAlgorithm) Compress(data []byte) ([]byte, error) {
	if m.CompressErr != nil {
		return nil, m.CompressErr
	}

	return data, nil
}

// Decompress will mock decompressing compressed data.
func (m *mockAlgorithm) Decompress(data []byte) ([]byte, error) {
	if m.DecompressErr != nil {
		return nil, m.DecompressErr
	}

	return data, nil
}

// Accept algorithm.
func (m *mockAlgorithm) Accept(alg string) bool {
	return true
}

// Close will close resources.
func (m *mockAlgorithm) Close() error {
	return m.CloseErr
}
