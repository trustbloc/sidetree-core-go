/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnprocessor

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
)

var logger = log.New("sidetree-core-observer")

// OperationStore interface to access operation store
type OperationStore interface {
	Put(ops []*batch.AnchoredOperation) error
}

// Providers contains the providers required by the TxnProcessor
type Providers struct {
	OpStore                   OperationStore
	OperationProtocolProvider protocol.OperationProvider
}

// TxnProcessor processes Sidetree transactions by persisting them to an operation store
type TxnProcessor struct {
	*Providers
}

// New returns a new document operation processor
func New(providers *Providers) *TxnProcessor {
	return &TxnProcessor{
		Providers: providers,
	}
}

// Process persists all of the operations for the given anchor
func (p *TxnProcessor) Process(sidetreeTxn txn.SidetreeTxn) error {
	logger.Debugf("processing sidetree txn:%+v", sidetreeTxn)

	txnOps, err := p.OperationProtocolProvider.GetTxnOperations(&sidetreeTxn)
	if err != nil {
		return fmt.Errorf("failed to retrieve operations for anchor string[%s]: %s", sidetreeTxn.AnchorString, err)
	}

	return p.processTxnOperations(txnOps, sidetreeTxn)
}

func (p *TxnProcessor) processTxnOperations(txnOps []*batch.AnchoredOperation, sidetreeTxn txn.SidetreeTxn) error {
	logger.Debugf("processing %d transaction operations", len(txnOps))

	batchSuffixes := make(map[string]bool)

	var ops []*batch.AnchoredOperation
	for index, op := range txnOps {
		_, ok := batchSuffixes[op.UniqueSuffix]
		if ok {
			logger.Warnf("[%s] duplicate suffix[%s] found in transaction operations: discarding operation %v", sidetreeTxn.Namespace, op.UniqueSuffix, op)
			continue
		}

		updatedOp := updateAnchoredOperation(op, uint(index), sidetreeTxn)

		logger.Debugf("updated operation with blockchain time: %s", updatedOp.UniqueSuffix)
		ops = append(ops, updatedOp)

		batchSuffixes[op.UniqueSuffix] = true
	}

	err := p.OpStore.Put(ops)
	if err != nil {
		return errors.Wrapf(err, "failed to store operation from anchor string[%s]", sidetreeTxn.AnchorString)
	}

	return nil
}

func updateAnchoredOperation(op *batch.AnchoredOperation, index uint, sidetreeTxn txn.SidetreeTxn) *batch.AnchoredOperation {
	//  The logical blockchain time that this operation was anchored on the blockchain
	op.TransactionTime = sidetreeTxn.TransactionTime
	// The transaction number of the transaction this operation was batched within
	op.TransactionNumber = sidetreeTxn.TransactionNumber
	// The genesis time of the protocol that was used for this operation
	op.ProtocolGenesisTime = sidetreeTxn.ProtocolGenesisTime
	// The index this operation was assigned to in the batch
	op.OperationIndex = index

	return op
}
