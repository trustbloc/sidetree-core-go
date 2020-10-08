/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cutter

import (
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
)

var logger = log.New("sidetree-core-cutter")

// OperationQueue defines the functions for adding and removing operations from a queue.
type OperationQueue interface {
	// Add adds the given operation to the tail of the queue and returns the new length of the queue.
	Add(data *batch.OperationInfo, protocolGenesisTime uint64) (uint, error)
	// Remove removes (up to) the given number of items from the head of the queue.
	// Returns the actual number of items that were removed and the new length of the queue.
	Remove(num uint) (uint, uint, error)
	// Peek returns (up to) the given number of operations from the head of the queue but does not remove them.
	Peek(num uint) ([]*batch.OperationInfoAtTime, error)
	// Len returns the number of operation in the queue.
	Len() uint
}

// Committer is invoked to commit a batch Cut. The new number of pending items
// in the queue is returned.
type Committer = func() (pending uint, err error)

// Result is the result of a batch 'Cut'.
type Result struct {
	// Operations holds the operations that were cut from the queue
	Operations []*batch.OperationInfo
	// ProtocolGenesisTime is the genesis time of the protocol version that was used to add the operations to the queue
	ProtocolGenesisTime uint64
	// Pending is the number of operations remaining in the queue
	Pending uint
	// Commit should be invoked in order to commit the 'Cut' (i.e. the operations will be permanently removed from the queue)
	// If Commit is not invoked then the operations will remain in the queue.
	Commit Committer
}

// BatchCutter implements batch cutting.
type BatchCutter struct {
	pendingBatch OperationQueue
	client       protocol.Client
}

// New creates a Cutter implementation.
func New(client protocol.Client, queue OperationQueue) *BatchCutter {
	return &BatchCutter{
		client:       client,
		pendingBatch: queue,
	}
}

// Add adds the given operation to pending batch queue and returns the total
// number of pending operations.
func (r *BatchCutter) Add(operation *batch.OperationInfo, protocolGenesisTime uint64) (uint, error) {
	// Enqueuing operation into batch
	return r.pendingBatch.Add(operation, protocolGenesisTime)
}

// Cut returns the current batch along with number of items that should be remaining in the queue after the committer is called.
// If force is false then the batch will be cut only if it has reached the max batch size (as specified in the protocol)
// If force is true then the batch will be cut if there is at least one Data in the batch
// Note that the operations are removed from the queue when Result.Commit is invoked, otherwise they remain in the queue.
func (r *BatchCutter) Cut(force bool) (Result, error) {
	pending := r.pendingBatch.Len()

	currentProtocol, err := r.client.Current()
	if err != nil {
		return Result{}, err
	}

	maxOperationsPerBatch := currentProtocol.Protocol().MaxOperationCount
	if !force && pending < maxOperationsPerBatch {
		return Result{Pending: pending}, nil
	}

	batchSize := min(pending, maxOperationsPerBatch)
	ops, err := r.pendingBatch.Peek(batchSize)
	if err != nil {
		return Result{Pending: pending}, nil
	}

	operations, protocolGenesisTime := getOperationsAtProtocolVersion(ops)

	batchSize = uint(len(operations))

	if batchSize == 0 {
		return Result{Pending: pending}, nil
	}

	pending -= batchSize

	logger.Infof("Pending Size: %d, MaxOperationsPerBatch: %d, Batch Size: %d", pending, maxOperationsPerBatch, batchSize)

	committer := func() (uint, error) {
		logger.Infof("Removing %d operations from the queue", batchSize)

		_, p, err := r.pendingBatch.Remove(batchSize)

		return p, err
	}

	return Result{
		Operations:          operations,
		ProtocolGenesisTime: protocolGenesisTime,
		Pending:             pending,
		Commit:              committer,
	}, nil
}

// getOperationsAtProtocolVersion iterates through the operations and returns the operations which are at the same protocol genesis time.
func getOperationsAtProtocolVersion(opsAtTime []*batch.OperationInfoAtTime) ([]*batch.OperationInfo, uint64) {
	var ops []*batch.OperationInfo
	var protocolGenesisTime uint64

	for _, op := range opsAtTime {
		if protocolGenesisTime == 0 {
			protocolGenesisTime = op.ProtocolGenesisTime
		}

		if op.ProtocolGenesisTime != protocolGenesisTime {
			// This operation was added using a different transaction time so it can't go into the same batch
			logger.Infof("Not adding operation since its protocol genesis time [%d] is different from the protocol genesis time [%d] of the existing ops in the batch", op.ProtocolGenesisTime, protocolGenesisTime)

			break
		}

		ops = append(ops,
			&batch.OperationInfo{
				Data:         op.Data,
				UniqueSuffix: op.UniqueSuffix,
				Namespace:    op.Namespace,
			},
		)
	}

	return ops, protocolGenesisTime
}

func min(i, j uint) uint {
	if i < j {
		return i
	}

	return j
}
