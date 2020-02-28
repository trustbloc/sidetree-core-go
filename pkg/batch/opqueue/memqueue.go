/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package opqueue

import (
	"sync"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
)

// MemQueue implements an in-memory operation queue
type MemQueue struct {
	items []*batch.OperationInfo
	mutex sync.RWMutex
}

// Add adds the given data to the tail of the queue and returns the new length of the queue
func (q *MemQueue) Add(data *batch.OperationInfo) (uint, error) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	q.items = append(q.items, data)

	return uint(len(q.items)), nil
}

// Peek returns (up to) the given number of operations from the head of the queue but does not remove them.
func (q *MemQueue) Peek(num uint) ([]*batch.OperationInfo, error) {
	q.mutex.RLock()
	defer q.mutex.RUnlock()

	n := int(num)
	if len(q.items) < n {
		n = len(q.items)
	}

	return q.items[0:n], nil
}

// Remove removes (up to) the given number of items from the head of the queue and returns the new length of the queue.
func (q *MemQueue) Remove(num uint) ([]*batch.OperationInfo, uint, error) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	n := int(num)
	if len(q.items) < n {
		n = len(q.items)
	}

	items := q.items[0:n]
	q.items = q.items[n:]

	return items, uint(len(q.items)), nil
}

// Len returns the length of the queue.
func (q *MemQueue) Len() uint {
	q.mutex.RLock()
	defer q.mutex.RUnlock()

	return uint(len(q.items))
}
