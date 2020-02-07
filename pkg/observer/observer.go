/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"encoding/json"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

var logger = logrus.New()

// SidetreeTxn defines info about sidetree transaction
type SidetreeTxn struct {
	TransactionTime   uint64
	TransactionNumber uint64
	AnchorAddress     string
}

// Ledger interface to access ledger txn
type Ledger interface {
	RegisterForSidetreeTxn() <-chan []SidetreeTxn
}

// DCAS interface to access content addressable storage
type DCAS interface {
	Read(key string) ([]byte, error)
}

// OperationStore interface to access operation store
type OperationStore interface {
	Put(ops []batch.Operation) error
}

// Start starts channel observer routines
func Start(ledger Ledger, dcas DCAS, operationStore OperationStore) {
	sidetreeTxnChannel := ledger.RegisterForSidetreeTxn()
	go func(txnsCh <-chan []SidetreeTxn) {
		processor := NewTxnProcessor(dcas, operationStore)
		for {
			txns, ok := <-txnsCh
			if !ok {
				logger.Warnf("received close from registerForSidetreeTxn")
				return
			}
			for _, txn := range txns {
				err := processor.Process(txn)
				if err != nil {
					logger.Warnf("Failed to process anchor[%s]: %s", txn.AnchorAddress, err.Error())
					continue
				}
				logger.Debugf("Successfully processed anchor[%s]", txn.AnchorAddress)
			}
		}
	}(sidetreeTxnChannel)
}

// TxnProcessor processes Sidetree transactions by persisting them to an operation store
type TxnProcessor struct {
	dcas           DCAS
	operationStore OperationStore
}

// NewTxnProcessor returns a new document operation processor
func NewTxnProcessor(dcas DCAS, opStore OperationStore) *TxnProcessor {
	return &TxnProcessor{
		dcas:           dcas,
		operationStore: opStore,
	}
}

// Process persists all of the operations for the given anchor
func (p *TxnProcessor) Process(sidetreeTxn SidetreeTxn) error {
	logger.Debugf("processing sidetree txn:%+v", sidetreeTxn)

	content, err := p.dcas.Read(sidetreeTxn.AnchorAddress)
	if err != nil {
		return errors.Wrapf(err, "failed to retrieve content for anchor: key[%s]", sidetreeTxn.AnchorAddress)
	}

	logger.Debugf("cas content for anchor[%s]: %s", sidetreeTxn.AnchorAddress, string(content))

	af, err := getAnchorFile(content)
	if err != nil {
		return errors.Wrapf(err, "failed to unmarshal anchor[%s]", sidetreeTxn.AnchorAddress)
	}

	return p.processBatchFile(af.BatchFileHash, sidetreeTxn)
}

func (p *TxnProcessor) processBatchFile(batchFileAddress string, sidetreeTxn SidetreeTxn) error {
	content, err := p.dcas.Read(batchFileAddress)
	if err != nil {
		return errors.Wrapf(err, "failed to retrieve content for batch: key[%s]", batchFileAddress)
	}

	bf, err := getBatchFile(content)
	if err != nil {
		return errors.Wrapf(err, "failed to unmarshal batch[%s]", batchFileAddress)
	}

	logger.Debugf("batch file operations: %s", bf.Operations)
	ops := make([]batch.Operation, 0)
	for index, op := range bf.Operations {
		updatedOp, errUpdateOps := updateOperation(op, uint(index), sidetreeTxn)
		if errUpdateOps != nil {
			return errors.Wrapf(errUpdateOps, "failed to update operation with blockchain metadata")
		}

		logger.Debugf("updated operation with blockchain time: %s", updatedOp.ID)
		ops = append(ops, *updatedOp)
	}

	err = p.operationStore.Put(ops)
	if err != nil {
		return errors.Wrapf(err, "failed to store operation from batch[%s]", batchFileAddress)
	}

	return nil
}

func updateOperation(encodedOp string, index uint, sidetreeTxn SidetreeTxn) (*batch.Operation, error) {
	decodedOp, err := docutil.DecodeString(encodedOp)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode ops")
	}
	var op batch.Operation
	err = json.Unmarshal(decodedOp, &op)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal decoded ops")
	}

	//  The logical blockchain time that this operation was anchored on the blockchain
	op.TransactionTime = sidetreeTxn.TransactionTime
	// The transaction number of the transaction this operation was batched within
	op.TransactionNumber = sidetreeTxn.TransactionNumber
	// The index this operation was assigned to in the batch
	op.OperationIndex = index

	return &op, nil
}

// AnchorFile defines the schema of a Anchor File
type AnchorFile struct {
	// BatchFileHash is encoded hash of the batch file
	BatchFileHash string `json:"batchFileHash"`

	// UniqueSuffixes is an array of suffixes (the unique portion of the ID string that differentiates
	// one document from another) for all documents that are declared to have operations within the associated batch file.
	UniqueSuffixes []string `json:"uniqueSuffixes"`
}

// getAnchorFile creates new anchor file struct from bytes
var getAnchorFile = func(bytes []byte) (*AnchorFile, error) {
	return unmarshalAnchorFile(bytes)
}

// unmarshalAnchorFile creates new anchor file struct from bytes
func unmarshalAnchorFile(bytes []byte) (*AnchorFile, error) {
	af := &AnchorFile{}
	err := json.Unmarshal(bytes, af)
	if err != nil {
		return nil, err
	}

	return af, nil
}

// BatchFile defines the schema of a Batch File and its related operations.
type BatchFile struct {
	// Operations included in this batch file, each operation is an encoded string
	Operations []string `json:"operations"`
}

// getBatchFile creates new batch file struct from bytes
var getBatchFile = func(bytes []byte) (*BatchFile, error) {
	return unmarshalBatchFile(bytes)
}

// unmarshalBatchFile creates new batch file struct from bytes
func unmarshalBatchFile(bytes []byte) (*BatchFile, error) {
	bf := &BatchFile{}
	err := json.Unmarshal(bytes, bf)
	if err != nil {
		return nil, err
	}
	return bf, nil
}
