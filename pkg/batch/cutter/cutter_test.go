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
	operation5 = &batch.OperationInfo{UniqueSuffix: "5", Data: []byte("operation5")}
	operation6 = &batch.OperationInfo{UniqueSuffix: "6", Data: []byte("operation6")}
)

func TestBatchCutter(t *testing.T) {
	c := mocks.NewMockProtocolClient()
	c.Protocol.MaxOperationCount = 3
	c.CurrentVersion.ProtocolReturns(c.Protocol)

	r := New(c, &opqueue.MemQueue{})

	c.Err = fmt.Errorf("injected protocol error")
	result, err := r.Cut(false)
	require.EqualError(t, err, c.Err.Error())
	require.Empty(t, result.Operations)
	require.Zero(t, result.Pending)
	require.Nil(t, result.Commit)
	require.Zero(t, result.ProtocolGenesisTime)

	c.Err = nil

	result, err = r.Cut(false)
	require.NoError(t, err)
	require.Empty(t, result.Operations)
	require.Zero(t, result.Pending)
	require.Nil(t, result.Commit)
	require.Zero(t, result.ProtocolGenesisTime)

	l, err := r.Add(operation1, 10)
	require.NoError(t, err)
	require.Equal(t, uint(1), l)
	l, err = r.Add(operation2, 10)
	require.NoError(t, err)
	require.Equal(t, uint(2), l)
	result, err = r.Cut(false)
	require.NoError(t, err)
	require.Empty(t, result.Operations)
	require.Equal(t, uint(2), result.Pending)
	require.Nil(t, result.Commit)
	require.Equal(t, uint64(0), result.ProtocolGenesisTime)

	result, err = r.Cut(true)
	require.NoError(t, err)
	require.Len(t, result.Operations, 2)
	require.Equal(t, operation1, result.Operations[0])
	require.Equal(t, operation2, result.Operations[1])
	require.Zero(t, result.Pending)
	require.Equal(t, uint64(10), result.ProtocolGenesisTime)

	// Without committing, the operations should still be in the queue
	result, err = r.Cut(true)
	require.NoError(t, err)
	require.Len(t, result.Operations, 2)
	require.Equal(t, operation1, result.Operations[0])
	require.Equal(t, operation2, result.Operations[1])
	require.Zero(t, result.Pending)

	pending, err := result.Commit()
	require.NoError(t, err)
	require.Zero(t, pending)

	// After a commit, the operations should be gone
	result, err = r.Cut(true)
	require.NoError(t, err)
	require.Empty(t, result.Operations)
	require.Zero(t, result.Pending)

	l, err = r.Add(operation3, 10)
	require.NoError(t, err)
	require.Equal(t, uint(1), l)
	l, err = r.Add(operation4, 10)
	require.NoError(t, err)
	require.Equal(t, uint(2), l)

	result, err = r.Cut(false)
	require.NoError(t, err)
	require.Empty(t, result.Operations)
	require.Equal(t, uint(2), result.Pending)
	require.Nil(t, result.Commit)

	l, err = r.Add(operation5, 20)
	require.NoError(t, err)
	require.Equal(t, uint(3), l)
	l, err = r.Add(operation6, 20)
	require.NoError(t, err)
	require.Equal(t, uint(4), l)

	result, err = r.Cut(false)
	require.NoError(t, err)
	require.Lenf(t, result.Operations, 2, "should have only cut two operations since the third operation in the queue is using a different protocol version")
	require.Equal(t, operation3, result.Operations[0])
	require.Equal(t, operation4, result.Operations[1])
	require.Equal(t, uint(2), result.Pending)
	require.NotNil(t, result.Commit)

	pending, err = result.Commit()
	require.NoError(t, err)
	require.Equal(t, uint(2), pending)

	result, err = r.Cut(true)
	require.NoError(t, err)
	require.Len(t, result.Operations, 2)
	require.Equal(t, operation5, result.Operations[0])
	require.Equal(t, operation6, result.Operations[1])
	require.Zero(t, result.Pending)

	pending, err = result.Commit()
	require.NoError(t, err)
	require.Zero(t, pending)
}
