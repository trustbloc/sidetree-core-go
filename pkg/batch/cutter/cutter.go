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
	Add(operation []byte, uniqueSuffix string) uint

	// AddFirst adds the given operation(s) to the front of the pending batch queue
	// and returns the total number of pending operations.
	AddFirst(operation [][]byte, uniqueSuffix []string) uint

	// Cut returns the current batch along with number of items remaining in the queue.
	// If force is false then the batch will be cut only if it has reached the max batch size (as specified in the protocol)
	// If force is true then the batch will be cut if there is at least one operation in the batch
	Cut(force bool) ([][]byte, []string, uint)
}

// BatchCutter implements batch cutting
type BatchCutter struct {
	pendingBatch   [][]byte
	uniqueSuffixes []string
	client         protocol.Client
}

// New creates a Cutter implementation
func New(client protocol.Client) *BatchCutter {
	return &BatchCutter{
		client: client,
	}
}

// Add adds the given operation(s) to pending batch queue and returns the total
// number of pending operations.
func (r *BatchCutter) Add(operation []byte, uniqueSuffix string) uint {
	// Enqueuing operation into batch
	r.pendingBatch = append(r.pendingBatch, operation)
	r.uniqueSuffixes = append(r.uniqueSuffixes, uniqueSuffix)

	return uint(len(r.pendingBatch))
}

// AddFirst adds the given operation(s) to the front of the pending batch queue
// and returns the total number of pending operations.
func (r *BatchCutter) AddFirst(operations [][]byte, uniqueSuffixes []string) uint {
	// TODO: Only one operation per DID per batch is allowed; re-shuffle DIDs
	r.pendingBatch = append(operations, r.pendingBatch...)
	r.uniqueSuffixes = append(uniqueSuffixes, r.uniqueSuffixes...)
	return uint(len(r.pendingBatch))
}

// Cut returns the current batch along with number of items remaining in the queue.
// If force is false then the batch will be cut only if it has reached the max batch size (as specified in the protocol)
// If force is true then the batch will be cut if there is at least one operation in the batch
func (r *BatchCutter) Cut(force bool) (operations [][]byte, uniqueSuffixes []string, pending uint) {
	pendingSize := uint(len(r.pendingBatch))
	if pendingSize == 0 {
		return nil, nil, 0
	}

	maxOperationsPerBatch := r.client.Current().MaxOperationsPerBatch
	if !force && pendingSize < maxOperationsPerBatch {
		return nil, nil, pendingSize
	}

	batchSize := min(pendingSize, maxOperationsPerBatch)
	operations = r.pendingBatch[0:batchSize]
	r.pendingBatch = r.pendingBatch[batchSize:]

	uniqueSuffixes = r.uniqueSuffixes[0:batchSize]
	r.uniqueSuffixes = r.uniqueSuffixes[batchSize:]

	logger.Debugf("Pending Size: %d, MaxOperationsPerBatch: %d, Batch Size: %d", pendingSize, maxOperationsPerBatch, batchSize)
	return operations, uniqueSuffixes, uint(len(r.pendingBatch))
}

func min(i, j uint) uint {
	if i < j {
		return i
	}
	return j
}
