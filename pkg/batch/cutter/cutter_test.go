/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cutter

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/opqueue"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

var (
	operation1 = &batch.OperationInfo{UniqueSuffix: "1", Data: []byte("operation1")}
	operation2 = &batch.OperationInfo{UniqueSuffix: "2", Data: []byte("operation2")}
	operation3 = &batch.OperationInfo{UniqueSuffix: "3", Data: []byte("operation3")}
	operation4 = &batch.OperationInfo{UniqueSuffix: "4", Data: []byte("operation4")}
)

func TestBatchCutter(t *testing.T) {
	c := mocks.NewMockProtocolClient()
	c.Protocol.MaxOperationCount = 3
	c.CurrentVersion.ProtocolReturns(c.Protocol)

	r := New(c, &opqueue.MemQueue{})

	c.Err = fmt.Errorf("injected protocol error")
	ops, pending, commit, err := r.Cut(false)
	require.EqualError(t, err, c.Err.Error())
	require.Empty(t, ops)
	require.Zero(t, pending)
	require.Nil(t, commit)

	c.Err = nil

	ops, pending, commit, err = r.Cut(false)
	require.NoError(t, err)
	require.Empty(t, ops)
	require.Zero(t, pending)
	require.Nil(t, commit)

	l, err := r.Add(operation1)
	require.NoError(t, err)
	require.Equal(t, uint(1), l)
	l, err = r.Add(operation2)
	require.NoError(t, err)
	require.Equal(t, uint(2), l)
	ops, pending, commit, err = r.Cut(false)
	require.NoError(t, err)
	require.Empty(t, ops)
	require.Equal(t, uint(2), pending)
	require.Nil(t, commit)

	ops, pending, commit, err = r.Cut(true)
	require.NoError(t, err)
	require.Len(t, ops, 2)
	require.Equal(t, operation1, ops[0])
	require.Equal(t, operation2, ops[1])
	require.Zero(t, pending)

	// Without committing, the operations should still be in the queue
	ops, pending, commit, err = r.Cut(true)
	require.NoError(t, err)
	require.Len(t, ops, 2)
	require.Equal(t, operation1, ops[0])
	require.Equal(t, operation2, ops[1])
	require.Zero(t, pending)

	pending, err = commit()
	require.NoError(t, err)
	require.Zero(t, pending)

	// After a commit, the operations should be gone
	ops, pending, commit, err = r.Cut(true)
	require.NoError(t, err)
	require.Empty(t, ops)
	require.Zero(t, pending)

	l, err = r.Add(operation1)
	require.NoError(t, err)
	require.Equal(t, uint(1), l)
	l, err = r.Add(operation2)
	require.NoError(t, err)
	require.Equal(t, uint(2), l)

	ops, pending, commit, err = r.Cut(false)
	require.NoError(t, err)
	require.Empty(t, ops)
	require.Equal(t, uint(2), pending)
	require.Nil(t, commit)

	l, err = r.Add(operation3)
	require.NoError(t, err)
	require.Equal(t, uint(3), l)
	l, err = r.Add(operation4)
	require.NoError(t, err)
	require.Equal(t, uint(4), l)

	ops, pending, commit, err = r.Cut(false)
	require.NoError(t, err)
	require.Len(t, ops, 3)
	require.Equal(t, operation1, ops[0])
	require.Equal(t, operation2, ops[1])
	require.Equal(t, operation3, ops[2])
	require.Equal(t, uint(1), pending)
	require.NotNil(t, commit)

	pending, err = commit()
	require.NoError(t, err)
	require.Equal(t, uint(1), pending)

	ops, pending, commit, err = r.Cut(true)
	require.NoError(t, err)
	require.Len(t, ops, 1)
	require.Equal(t, operation4, ops[0])
	require.Zero(t, pending)

	pending, err = commit()
	require.NoError(t, err)
	require.Zero(t, pending)
}
