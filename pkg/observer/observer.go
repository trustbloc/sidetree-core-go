/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
)

var logger = log.New("sidetree-core-observer")

// Ledger interface to access ledger txn.
type Ledger interface {
	RegisterForSidetreeTxn() <-chan []txn.SidetreeTxn
}

// OperationStore interface to access operation store.
type OperationStore interface {
	Put(ops []*operation.AnchoredOperation) error
}

// OperationFilter filters out operations before they are persisted.
type OperationFilter interface {
	Filter(uniqueSuffix string, ops []*operation.AnchoredOperation) ([]*operation.AnchoredOperation, error)
}

// Providers contains all of the providers required by the TxnProcessor.
type Providers struct {
	Ledger                 Ledger
	ProtocolClientProvider protocol.ClientProvider
}

// Observer receives transactions over a channel and processes them by storing them to an operation store.
type Observer struct {
	*Providers

	stopCh chan struct{}
}

// New returns a new observer.
func New(providers *Providers) *Observer {
	return &Observer{
		Providers: providers,
		stopCh:    make(chan struct{}, 1),
	}
}

// Start starts observer routines.
func (o *Observer) Start() {
	go o.listen(o.Ledger.RegisterForSidetreeTxn())
}

// Stop stops the observer.
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
		pc, err := o.ProtocolClientProvider.ForNamespace(txn.Namespace)
		if err != nil {
			logger.Warnf("Failed to get protocol client for namespace [%s]: %s", txn.Namespace, err.Error())

			continue
		}

		v, err := pc.Get(txn.ProtocolVersion)
		if err != nil {
			logger.Warnf("Failed to get processor for transaction time [%d]: %s", txn.ProtocolVersion, err.Error())

			continue
		}

		_, err = v.TransactionProcessor().Process(txn)
		if err != nil {
			logger.Warnf("Failed to process anchor[%s]: %s", txn.AnchorString, err.Error())

			continue
		}

		logger.Debugf("Successfully processed anchor[%s]", txn.AnchorString)
	}
}
