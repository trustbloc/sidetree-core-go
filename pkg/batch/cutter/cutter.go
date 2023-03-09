/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cutter

import (
	"fmt"

	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	logfields "github.com/trustbloc/sidetree-core-go/pkg/internal/log"
)

var logger = log.New("sidetree-core-cutter")

// OperationQueue defines the functions for adding and removing operations from a queue.
type OperationQueue interface {
	// Add adds the given operation to the tail of the queue and returns the new length of the queue.
	Add(data *operation.QueuedOperation, protocolVersion uint64) (uint, error)
	// Remove removes (up to) the given number of items from the head of the queue and returns:
	// - The operations that are to be removed.
	// - The 'Ack' function that must be called to commit the remove.
	// - The 'Nack' function that must be called to roll back the remove.
	Remove(num uint) (ops operation.QueuedOperationsAtTime, ack func() uint, nack func(), err error)
	// Peek returns (up to) the given number of operations from the head of the queue but does not remove them.
	Peek(num uint) (operation.QueuedOperationsAtTime, error)
	// Len returns the number of operation in the queue.
	Len() uint
}

// Committer is invoked to commit a batch Cut. The new number of pending items
// in the queue is returned.
type Committer = func() (pending uint, err error)

// Result is the result of a batch 'Cut'.
type Result struct {
	// Operations holds the operations that were cut from the queue
	Operations []*operation.QueuedOperation
	// ProtocolVersion is the genesis time of the protocol version that was used to add the operations to the queue
	ProtocolVersion uint64
	// Pending is the number of operations remaining in the queue
	Pending uint
	// Ack commits the remove from the queue and returns the number of pending operations.
	Ack func() uint
	// Nack rolls back the remove so that a retry may occur.
	Nack func()
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
func (r *BatchCutter) Add(op *operation.QueuedOperation, protocolVersion uint64) (uint, error) {
	// Enqueuing operation into batch
	return r.pendingBatch.Add(op, protocolVersion)
}

// Cut returns the current batch along with number of items that should be remaining in the queue after the committer is called.
// If force is false then the batch will be cut only if it has reached the max batch size (as specified in the protocol)
// If force is true then the batch will be cut if there is at least one Data in the batch
// Note that the operations are removed from the queue when Result.Ack is invoked, otherwise Result.Nack should be called
// in order to place the operations back in the queue so that they be processed again.
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

	operations, protocolVersion := getOperationsAtProtocolVersion(ops)

	batchSize = uint(len(operations))

	if batchSize == 0 {
		return Result{Pending: pending}, nil
	}

	pending -= batchSize

	logger.Info("Removing operations from queue.", logfields.WithTotalPending(pending),
		logfields.WithMaxSize(int(maxOperationsPerBatch)), logfields.WithSize(int(batchSize)))

	ops, ack, nack, err := r.pendingBatch.Remove(batchSize)
	if err != nil {
		return Result{}, fmt.Errorf("pending batch queue remove: %w", err)
	}

	return Result{
		Operations:      ops.QueuedOperations(),
		ProtocolVersion: protocolVersion,
		Pending:         pending,
		Ack:             ack,
		Nack:            nack,
	}, nil
}

// getOperationsAtProtocolVersion iterates through the operations and returns the operations which are at the same protocol genesis time.
func getOperationsAtProtocolVersion(opsAtTime []*operation.QueuedOperationAtTime) ([]*operation.QueuedOperation, uint64) {
	var ops []*operation.QueuedOperation
	var protocolVersion uint64

	for _, op := range opsAtTime {
		if protocolVersion == 0 {
			protocolVersion = op.ProtocolVersion
		}

		if op.ProtocolVersion != protocolVersion {
			// This operation was added using a different transaction time so it can't go into the same batch
			logger.Info("Not adding operation since its protocol genesis time is different from the protocol genesis "+
				"time of the existing ops in the batch.", logfields.WithOperationGenesisTime(op.ProtocolVersion),
				logfields.WithGenesisTime(protocolVersion))

			break
		}

		ops = append(ops,
			&operation.QueuedOperation{
				OperationRequest: op.OperationRequest,
				UniqueSuffix:     op.UniqueSuffix,
				Namespace:        op.Namespace,
			},
		)
	}

	return ops, protocolVersion
}

func min(i, j uint) uint {
	if i < j {
		return i
	}

	return j
}
