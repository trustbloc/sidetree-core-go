/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gzip

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAlgorithm_Accept(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		alg := New()
		require.True(t, alg.Accept("GZIP"))
		require.False(t, alg.Accept("other"))
	})
}

func TestAlgorithm_Compress(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		alg := New()

		test := []byte("test data")
		compressed, err := alg.Compress(test)
		require.NoError(t, err)
		require.NotEmpty(t, compressed)

		data, err := alg.Decompress(compressed)
		require.NoError(t, err)
		require.NotEmpty(t, data)
		require.Equal(t, data, test)
	})
	t.Run("error reading header", func(t *testing.T) {
		alg := New()

		test := []byte("hello data")
		compressed, err := alg.Compress(test)
		require.NoError(t, err)
		require.NotEmpty(t, compressed)
	})
}

func TestAlgorithm_Decompress(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		alg := New()

		test := []byte("hello world")
		compressed, err := alg.Compress(test)
		require.NoError(t, err)
		require.NotEmpty(t, compressed)

		data, err := alg.Decompress(compressed)
		require.NoError(t, err)
		require.NotEmpty(t, data)
		require.Equal(t, data, test)
	})
	t.Run("error - data not compressed", func(t *testing.T) {
		alg := New()

		test := []byte("test data")
		data, err := alg.Decompress(test)
		require.Error(t, err)
		require.Empty(t, data)
		require.Contains(t, err.Error(), "unexpected EOF")
	})
}

func TestAlgorithm_Close(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		alg := New()
		require.NoError(t, alg.Close())
	})
}
