/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opqueue

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
)

var (
	op1 = &operation.QueuedOperation{Namespace: "ns", UniqueSuffix: "op1", OperationRequest: []byte("op1")}
	op2 = &operation.QueuedOperation{Namespace: "ns", UniqueSuffix: "op2", OperationRequest: []byte("op2")}
	op3 = &operation.QueuedOperation{Namespace: "ns", UniqueSuffix: "op3", OperationRequest: []byte("op3")}
)

func TestMemQueue(t *testing.T) {
	q := &MemQueue{}
	require.Zero(t, q.Len())

	ops, err := q.Peek(1)
	require.NoError(t, err)
	require.Empty(t, ops)

	l, err := q.Add(op1, 10)
	require.NoError(t, err)
	require.Equal(t, uint(1), l)
	require.Equal(t, uint(1), q.Len())

	l, err = q.Add(op2, 10)
	require.NoError(t, err)
	require.Equal(t, uint(2), l)
	require.Equal(t, uint(2), q.Len())

	l, err = q.Add(op3, 10)
	require.NoError(t, err)
	require.Equal(t, uint(3), l)
	require.Equal(t, uint(3), q.Len())

	ops, err = q.Peek(1)
	require.NoError(t, err)
	require.Len(t, ops, 1)
	require.Equal(t, *op1, ops[0].QueuedOperation)

	ops, err = q.Peek(4)
	require.NoError(t, err)
	require.Len(t, ops, 3)
	require.Equal(t, *op1, ops[0].QueuedOperation)
	require.Equal(t, *op2, ops[1].QueuedOperation)
	require.Equal(t, *op3, ops[2].QueuedOperation)

	ops, ack, nack, err := q.Remove(1)
	require.NoError(t, err)
	require.NotNil(t, ack)
	require.NotNil(t, nack)
	require.Len(t, ops, 1)
	require.Equal(t, *op1, ops[0].QueuedOperation)

	require.Equal(t, uint(2), ack())

	ops, err = q.Peek(1)
	require.NoError(t, err)
	require.Len(t, ops, 1)
	require.Equal(t, *op2, ops[0].QueuedOperation)

	ops, _, nack, err = q.Remove(5)
	require.NoError(t, err)
	require.NotNil(t, nack)
	require.Len(t, ops, 2)
	require.Equal(t, *op2, ops[0].QueuedOperation)
	require.Equal(t, *op3, ops[1].QueuedOperation)

	nack(errors.New("injected error"))

	ops, ack, _, err = q.Remove(5)
	require.NoError(t, err)
	require.NotNil(t, ack)
	require.Len(t, ops, 2)
	require.Equal(t, *op2, ops[0].QueuedOperation)
	require.Equal(t, *op3, ops[1].QueuedOperation)

	require.Zero(t, ack())
}
