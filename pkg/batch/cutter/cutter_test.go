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

	ops, uniqueSuffixes, pending := r.Cut(false)
	require.Empty(t, ops)
	require.Empty(t, uniqueSuffixes)
	require.Zero(t, pending)

	require.Equal(t, uint(1), r.Add(operation1, "1"))
	require.Equal(t, uint(2), r.Add(operation2, "2"))
	ops, uniqueSuffixes, pending = r.Cut(false)
	require.Empty(t, ops)
	require.Empty(t, uniqueSuffixes)
	require.Equal(t, uint(2), pending)

	ops, uniqueSuffixes, pending = r.Cut(true)
	require.Len(t, ops, 2)
	require.Equal(t, operation1, ops[0])
	require.Equal(t, operation2, ops[1])
	require.Zero(t, pending)

	require.Equal(t, uint(1), r.Add(operation1, "1"))
	require.Equal(t, uint(2), r.Add(operation2, "2"))
	ops, uniqueSuffixes, pending = r.Cut(false)
	require.Empty(t, ops)
	require.Empty(t, uniqueSuffixes)
	require.Equal(t, uint(2), pending)

	r.AddFirst([][]byte{operation3, operation4}, []string{"3", "4"})

	ops, uniqueSuffixes, pending = r.Cut(false)
	require.Len(t, ops, 3)
	require.Len(t, uniqueSuffixes, 3)
	require.Equal(t, operation3, ops[0])
	require.Equal(t, operation4, ops[1])
	require.Equal(t, operation1, ops[2])
	require.Equal(t, "3", uniqueSuffixes[0])
	require.Equal(t, "4", uniqueSuffixes[1])
	require.Equal(t, "1", uniqueSuffixes[2])
	require.Equal(t, uint(1), pending)

	ops, uniqueSuffixes, pending = r.Cut(true)
	require.Len(t, ops, 1)
	require.Len(t, ops, 1)
	require.Equal(t, operation2, ops[0])
	require.Zero(t, pending)
}
