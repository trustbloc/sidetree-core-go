/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

var logger = log.New("sidetree-core-observer")

// Ledger interface to access ledger txn
type Ledger interface {
	RegisterForSidetreeTxn() <-chan []txn.SidetreeTxn
}

// TxnOpsProvider defines an interface for retrieving(assembling) operations from batch files(chunk, map, anchor)
type TxnOpsProvider interface {
	// GetTxnOperations will read batch files(chunk, map, anchor) and assemble batch operations from those files
	GetTxnOperations(txn *txn.SidetreeTxn) ([]*batch.Operation, error)
}

// DecompressionProvider defines an interface for decompressing data using specified algorithm
type DecompressionProvider interface {
	// Decompress will decompress compressed data using specified algorithm
	Decompress(alg string, data []byte) ([]byte, error)
}

// OperationStore interface to access operation store
type OperationStore interface {
	Put(ops []*batch.Operation) error
}

// OperationStoreProvider returns an operation store for the given namespace
type OperationStoreProvider interface {
	ForNamespace(namespace string) (OperationStore, error)
}

// OperationFilter filters out operations before they are persisted
type OperationFilter interface {
	Filter(uniqueSuffix string, ops []*batch.Operation) ([]*batch.Operation, error)
}

// OperationFilterProvider returns an operation filter for the given namespace
type OperationFilterProvider interface {
	Get(namespace string) (OperationFilter, error)
}

// Providers contains all of the providers required by the TxnProcessor
type Providers struct {
	Ledger                Ledger
	TxnOpsProvider        TxnOpsProvider
	OpStoreProvider       OperationStoreProvider
	OpFilterProvider      OperationFilterProvider
	DecompressionProvider DecompressionProvider
}

// Observer receives transactions over a channel and processes them by storing them to an operation store
type Observer struct {
	*Providers

	processor *TxnProcessor
	stopCh    chan struct{}
}

// New returns a new observer
func New(providers *Providers) *Observer {
	return &Observer{
		Providers: providers,
		stopCh:    make(chan struct{}, 1),
		processor: NewTxnProcessor(providers),
	}
}

// Start starts observer routines
func (o *Observer) Start() {
	go o.listen(o.Ledger.RegisterForSidetreeTxn())
}

// Stop stops the observer
func (o *Observer) Stop() {
	o.stopCh <- struct{}{}
}

func (o *Observer) listen(txnsCh <-chan []txn.SidetreeTxn) {
	for {
		select {
		case <-o.stopCh:
			logger.Infof("The observer has been stopped. Exiting.")
			return

		case txns, ok := <-txnsCh:
			if !ok {
				logger.Warnf("Notification channel was closed. Exiting.")
				return
			}

			o.process(txns)
		}
	}
}

func (o *Observer) process(txns []txn.SidetreeTxn) {
	for _, txn := range txns {
		err := o.processor.Process(txn)
		if err != nil {
			logger.Warnf("Failed to process anchor[%s]: %s", txn.AnchorString, err.Error())
			continue
		}
		logger.Debugf("Successfully processed anchor[%s]", txn.AnchorString)
	}
}

// TxnProcessor processes Sidetree transactions by persisting them to an operation store
type TxnProcessor struct {
	*Providers
}

// NewTxnProcessor returns a new document operation processor
func NewTxnProcessor(providers *Providers) *TxnProcessor {
	return &TxnProcessor{
		Providers: providers,
	}
}

// Process persists all of the operations for the given anchor
func (p *TxnProcessor) Process(sidetreeTxn txn.SidetreeTxn) error {
	logger.Debugf("processing sidetree txn:%+v", sidetreeTxn)

	txnOps, err := p.TxnOpsProvider.GetTxnOperations(&sidetreeTxn)
	if err != nil {
		return fmt.Errorf("failed to retrieve operations for anchor string[%s]: %s", sidetreeTxn.AnchorString, err)
	}

	return p.processTxnOperations(txnOps, sidetreeTxn)
}

func (p *TxnProcessor) processTxnOperations(txnOps []*batch.Operation, sidetreeTxn txn.SidetreeTxn) error {
	logger.Debugf("processing %d transaction operations", len(txnOps))

	batchSuffixes := make(map[string]bool)

	var ops []*batch.Operation
	for index, op := range txnOps {
		_, ok := batchSuffixes[op.UniqueSuffix]
		if ok {
			logger.Warnf("[%s] duplicate suffix[%s] found in transaction operations: discarding operation %v", sidetreeTxn.Namespace, op.UniqueSuffix, op)
			continue
		}

		updatedOp := updateOperation(op, uint(index), sidetreeTxn)

		logger.Debugf("updated operation with blockchain time: %s", updatedOp.ID)
		ops = append(ops, updatedOp)

		batchSuffixes[op.UniqueSuffix] = true
	}

	for suffix, mapping := range mapOperationsByUniqueSuffix(ops) {
		logger.Debugf("Filtering operations for namespace [%s] and suffix [%s]", mapping.namespace, suffix)

		opFilter, err := p.OpFilterProvider.Get(mapping.namespace)
		if err != nil {
			return errors.Wrapf(err, "error getting operation filter for namespace [%s]", mapping.namespace)
		}

		validOps, err := opFilter.Filter(suffix, mapping.operations)
		if err != nil {
			return errors.Wrap(err, "error filtering invalid operations")
		}

		opStore, err := p.OpStoreProvider.ForNamespace(mapping.namespace)
		if err != nil {
			return errors.Wrapf(err, "error getting operation store for namespace [%s]", mapping.namespace)
		}

		err = opStore.Put(validOps)
		if err != nil {
			return errors.Wrapf(err, "failed to store operation from anchor string[%s]", sidetreeTxn.AnchorString)
		}
	}

	return nil
}

func updateOperation(op *batch.Operation, index uint, sidetreeTxn txn.SidetreeTxn) *batch.Operation {
	//  The logical blockchain time that this operation was anchored on the blockchain
	op.TransactionTime = sidetreeTxn.TransactionTime
	// The transaction number of the transaction this operation was batched within
	op.TransactionNumber = sidetreeTxn.TransactionNumber
	// The index this operation was assigned to in the batch
	op.OperationIndex = index

	return op
}

type operationsMapping struct {
	namespace  string
	operations []*batch.Operation
}

func mapOperationsByUniqueSuffix(ops []*batch.Operation) map[string]*operationsMapping {
	m := make(map[string]*operationsMapping)

	for _, op := range ops {
		mapping, ok := m[op.UniqueSuffix]
		if !ok {
			ns, err := docutil.GetNamespaceFromID(op.ID)
			if err != nil {
				logger.Infof("Skipping operation since could not get namespace from operation {ID: %s, UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", op.ID, op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber, err)
				continue
			}

			mapping = &operationsMapping{
				namespace: ns,
			}

			m[op.UniqueSuffix] = mapping
		}

		mapping.operations = append(mapping.operations, op)
	}

	return m
}
