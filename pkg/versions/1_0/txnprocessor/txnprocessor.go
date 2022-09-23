/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnprocessor

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/log"
)

var logger = log.New("sidetree-core-observer")

// OperationStore interface to access operation store.
type OperationStore interface {
	Put(ops []*operation.AnchoredOperation) error
}

type unpublishedOperationStore interface {
	// DeleteAll deletes unpublished operations.
	DeleteAll(ops []*operation.AnchoredOperation) error
}

// Providers contains the providers required by the TxnProcessor.
type Providers struct {
	OpStore                   OperationStore
	OperationProtocolProvider protocol.OperationProvider
}

// TxnProcessor processes Sidetree transactions by persisting them to an operation store.
type TxnProcessor struct {
	*Providers

	unpublishedOperationStore unpublishedOperationStore
	unpublishedOperationTypes []operation.Type
}

// New returns a new document operation processor.
func New(providers *Providers, opts ...Option) *TxnProcessor {
	tp := &TxnProcessor{
		Providers: providers,

		unpublishedOperationStore: &noopUnpublishedOpsStore{},
		unpublishedOperationTypes: []operation.Type{},
	}

	// apply options
	for _, opt := range opts {
		opt(tp)
	}

	return tp
}

// Option is an option for transaction processor.
type Option func(opts *TxnProcessor)

// WithUnpublishedOperationStore is unpublished operation store option.
func WithUnpublishedOperationStore(store unpublishedOperationStore, opTypes []operation.Type) Option {
	return func(opts *TxnProcessor) {
		opts.unpublishedOperationStore = store
		opts.unpublishedOperationTypes = opTypes
	}
}

// Process persists all of the operations for the given anchor.
func (p *TxnProcessor) Process(sidetreeTxn txn.SidetreeTxn, suffixes ...string) (int, error) {
	logger.Debugf("processing sidetree txn:%+v, suffixes: %s", sidetreeTxn, suffixes)

	txnOps, err := p.OperationProtocolProvider.GetTxnOperations(&sidetreeTxn)
	if err != nil {
		return 0, fmt.Errorf("failed to retrieve operations for anchor string[%s]: %s", sidetreeTxn.AnchorString, err)
	}

	return p.processTxnOperations(txnOps, sidetreeTxn)
}

func (p *TxnProcessor) processTxnOperations(txnOps []*operation.AnchoredOperation, sidetreeTxn txn.SidetreeTxn) (int, error) {
	logger.Debugf("processing %d transaction operations", len(txnOps))

	batchSuffixes := make(map[string]bool)

	var unpublishedOps []*operation.AnchoredOperation

	var ops []*operation.AnchoredOperation
	for _, op := range txnOps {
		_, ok := batchSuffixes[op.UniqueSuffix]
		if ok {
			logger.Warnf("[%s] duplicate suffix[%s] found in transaction operations: discarding operation %v", sidetreeTxn.Namespace, op.UniqueSuffix, op)

			continue
		}

		updatedOp := updateAnchoredOperation(op, sidetreeTxn)

		logger.Debugf("updated operation with anchoring time: %s", updatedOp.UniqueSuffix)
		ops = append(ops, updatedOp)

		batchSuffixes[op.UniqueSuffix] = true

		if containsOperationType(p.unpublishedOperationTypes, op.Type) {
			unpublishedOps = append(unpublishedOps, op)
		}
	}

	err := p.OpStore.Put(ops)
	if err != nil {
		return 0, errors.Wrapf(err, "failed to store operation from anchor string[%s]", sidetreeTxn.AnchorString)
	}

	err = p.unpublishedOperationStore.DeleteAll(unpublishedOps)
	if err != nil {
		return 0, fmt.Errorf("failed to delete unpublished operations for anchor string[%s]: %w", sidetreeTxn.AnchorString, err)
	}

	return len(ops), nil
}

func updateAnchoredOperation(op *operation.AnchoredOperation, sidetreeTxn txn.SidetreeTxn) *operation.AnchoredOperation {
	//  The logical anchoring time that this operation was anchored on
	op.TransactionTime = sidetreeTxn.TransactionTime
	// The transaction number of the transaction this operation was batched within
	op.TransactionNumber = sidetreeTxn.TransactionNumber
	// The genesis time of the protocol that was used for this operation
	op.ProtocolVersion = sidetreeTxn.ProtocolVersion

	return op
}

func containsOperationType(values []operation.Type, value operation.Type) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}

	return false
}

type noopUnpublishedOpsStore struct{}

func (noop *noopUnpublishedOpsStore) DeleteAll(_ []*operation.AnchoredOperation) error {
	return nil
}
