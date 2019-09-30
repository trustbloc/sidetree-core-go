/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cutter

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

var (
	operation1 = []byte("operation1")
	operation2 = []byte("operation2")
	operation3 = []byte("operation3")
	operation4 = []byte("operation4")
)

func TestBatchCutter(t *testing.T) {

	c := mocks.NewMockProtocolClient()
	c.Protocol.MaxOperationsPerBatch = 3
	r := New(c)

	batch, pending := r.Cut(false)
	require.Empty(t, batch)
	require.Zero(t, pending)

	require.Equal(t, uint(2), r.Add(operation1, operation2))
	batch, pending = r.Cut(false)
	require.Empty(t, batch)
	require.Equal(t, uint(2), pending)

	batch, pending = r.Cut(true)
	require.Len(t, batch, 2)
	require.Equal(t, operation1, batch[0])
	require.Equal(t, operation2, batch[1])
	require.Zero(t, pending)

	require.Equal(t, uint(2), r.Add(operation1, operation2))
	batch, pending = r.Cut(false)
	require.Empty(t, batch)
	require.Equal(t, uint(2), pending)

	r.AddFirst(operation3, operation4)

	batch, pending = r.Cut(false)
	require.Len(t, batch, 3)
	require.Equal(t, operation3, batch[0])
	require.Equal(t, operation4, batch[1])
	require.Equal(t, operation1, batch[2])
	require.Equal(t, uint(1), pending)

	batch, pending = r.Cut(true)
	require.Len(t, batch, 1)
	require.Equal(t, operation2, batch[0])
	require.Zero(t, pending)
}
