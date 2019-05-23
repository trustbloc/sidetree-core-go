/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cutter

// Cutter defines queue for batching document operations. It also cuts batch file based on batch size.
type Cutter interface {

	// Add adds an operation to pending batch and cuts batch if pending batch has reached max operations per batch
	Add(operation []byte, maxOperationsPerBatch uint) (batch [][]byte, pending bool)

	// Cut returns the current batch and starts a new one
	Cut() [][]byte
}

// BatchCutter implements batch cutting
type BatchCutter struct {
	pendingBatch [][]byte
}

// New creates a Cutter implementation
func New() *BatchCutter {
	return &BatchCutter{}
}

// Add adds an operation to operations queue and cuts batch if pending batch has reached max operations per batch
func (r *BatchCutter) Add(operation []byte, maxOperationsPerBatch uint) (batch [][]byte, pending bool) {

	// Enqueuing operation into batch
	r.pendingBatch = append(r.pendingBatch, operation)
	pending = true

	if uint(len(r.pendingBatch)) >= maxOperationsPerBatch {
		operationBatch := r.Cut()
		batch = append(batch, operationBatch...)
		pending = false
	}

	return
}

// Cut returns the current batch and starts a new one
func (r *BatchCutter) Cut() [][]byte {
	batch := r.pendingBatch
	r.pendingBatch = nil
	return batch
}
