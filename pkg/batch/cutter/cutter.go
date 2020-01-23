/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cutter

import (
	"github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
)

var logger = logrus.New()

// Cutter defines queue for batching document operations. It also cuts batch file based on batch size.
type Cutter interface {

	// Add adds the given operation(s) to pending batch queue and returns the total
	// number of pending operations.
	Add(operation ...[]byte) uint

	// AddFirst adds the given operation(s) to the front of the pending batch queue
	// and returns the total number of pending operations.
	AddFirst(bytes ...[]byte) uint

	// Cut returns the current batch along with number of items remaining in the queue.
	// If force is false then the batch will be cut only if it has reached the max batch size (as specified in the protocol)
	// If force is true then the batch will be cut if there is at least one operation in the batch
	Cut(force bool) ([][]byte, uint)
}

// BatchCutter implements batch cutting
type BatchCutter struct {
	pendingBatch [][]byte
	client       protocol.Client
}

// New creates a Cutter implementation
func New(client protocol.Client) *BatchCutter {
	return &BatchCutter{
		client: client,
	}
}

// Add adds the given operation(s) to pending batch queue and returns the total
// number of pending operations.
func (r *BatchCutter) Add(operations ...[]byte) uint {
	// Enqueuing operations into batch
	r.pendingBatch = append(r.pendingBatch, operations...)
	return uint(len(r.pendingBatch))
}

// AddFirst adds the given operation(s) to the front of the pending batch queue
// and returns the total number of pending operations.
func (r *BatchCutter) AddFirst(operations ...[]byte) uint {
	r.pendingBatch = append(operations, r.pendingBatch...)
	return uint(len(r.pendingBatch))
}

// Cut returns the current batch along with number of items remaining in the queue.
// If force is false then the batch will be cut only if it has reached the max batch size (as specified in the protocol)
// If force is true then the batch will be cut if there is at least one operation in the batch
func (r *BatchCutter) Cut(force bool) (operations [][]byte, pending uint) {
	pendingSize := uint(len(r.pendingBatch))
	if pendingSize == 0 {
		return nil, 0
	}

	maxOperationsPerBatch := r.client.Current().MaxOperationsPerBatch
	if !force && pendingSize < maxOperationsPerBatch {
		return nil, pendingSize
	}

	batchSize := min(pendingSize, maxOperationsPerBatch)
	batch := r.pendingBatch[0:batchSize]
	r.pendingBatch = r.pendingBatch[batchSize:]

	logger.Debugf("Pending Size: %d, MaxOperationsPerBatch: %d, Batch Size: %d", pendingSize, maxOperationsPerBatch, batchSize)
	return batch, uint(len(r.pendingBatch))
}

func min(i, j uint) uint {
	if i < j {
		return i
	}
	return j
}
