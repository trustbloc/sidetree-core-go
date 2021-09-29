/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cutter

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/opqueue"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

var (
	operation1 = &operation.QueuedOperation{UniqueSuffix: "1", OperationRequest: []byte("operation1")}
	operation2 = &operation.QueuedOperation{UniqueSuffix: "2", OperationRequest: []byte("operation2")}
	operation3 = &operation.QueuedOperation{UniqueSuffix: "3", OperationRequest: []byte("operation3")}
	operation4 = &operation.QueuedOperation{UniqueSuffix: "4", OperationRequest: []byte("operation4")}
	operation5 = &operation.QueuedOperation{UniqueSuffix: "5", OperationRequest: []byte("operation5")}
	operation6 = &operation.QueuedOperation{UniqueSuffix: "6", OperationRequest: []byte("operation6")}
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
	require.Zero(t, result.ProtocolVersion)

	c.Err = nil

	result, err = r.Cut(false)
	require.NoError(t, err)
	require.Empty(t, result.Operations)
	require.Zero(t, result.Pending)
	require.Zero(t, result.ProtocolVersion)

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
	require.Equal(t, uint64(0), result.ProtocolVersion)

	result, err = r.Cut(true)
	require.NoError(t, err)
	require.Len(t, result.Operations, 2)
	require.Equal(t, operation1, result.Operations[0])
	require.Equal(t, operation2, result.Operations[1])
	require.Zero(t, result.Pending)
	require.Equal(t, uint64(10), result.ProtocolVersion)

	result.Nack()

	// After a rollback, the operations should still be in the queue
	result, err = r.Cut(true)
	require.NoError(t, err)
	require.Len(t, result.Operations, 2)
	require.Equal(t, operation1, result.Operations[0])
	require.Equal(t, operation2, result.Operations[1])
	require.Zero(t, result.Pending)

	require.Zero(t, result.Ack())

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

	require.Equal(t, uint(2), result.Ack())

	result, err = r.Cut(true)
	require.NoError(t, err)
	require.Len(t, result.Operations, 2)
	require.Equal(t, operation5, result.Operations[0])
	require.Equal(t, operation6, result.Operations[1])
	require.Zero(t, result.Pending)

	require.Zero(t, result.Ack())
}
