/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cutter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var operation = []byte("Test Operation")

func TestAdd(t *testing.T) {

	r := New()

	batch, pending := r.Add(operation, 2)
	require.Nil(t, batch)
	require.True(t, pending)

	batch, pending = r.Add(operation, 2)
	require.NotNil(t, batch)
	require.False(t, pending)
}

func TestCut(t *testing.T) {

	r := New()

	batch, pending := r.Add(operation, 2)
	require.Nil(t, batch)
	require.True(t, pending)

	batch = r.Cut()
	require.NotNil(t, batch)
	require.Equal(t, 1, len(batch))
}
