/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"sync"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
)

// MockAnchorWriter mocks anchor writer for testing purposes.
type MockAnchorWriter struct {
	sync.RWMutex
	namespace string
	anchors   []string
	err       error
}

// NewMockAnchorWriter creates mock anchor writer.
func NewMockAnchorWriter(err error) *MockAnchorWriter {
	return &MockAnchorWriter{err: err, namespace: DefaultNS}
}

// WriteAnchor writes the anchor string as a transaction to anchoring system.
func (m *MockAnchorWriter) WriteAnchor(anchor string, _ []*protocol.AnchorDocument, _ []*operation.Reference, _ uint64) error {
	if m.err != nil {
		return m.err
	}

	m.Lock()
	defer m.Unlock()

	m.anchors = append(m.anchors, anchor)

	return nil
}

// Read reads transactions since transaction number.
func (m *MockAnchorWriter) Read(sinceTransactionNumber int) (bool, *txn.SidetreeTxn) {
	m.RLock()
	defer m.RUnlock()
	moreTransactions := false
	if len(m.anchors) > 0 && sinceTransactionNumber < len(m.anchors)-2 {
		moreTransactions = true
	}

	if len(m.anchors) > 0 && sinceTransactionNumber < len(m.anchors)-1 {
		hashIndex := sinceTransactionNumber + 1

		txn := &txn.SidetreeTxn{
			Namespace:         m.namespace,
			TransactionTime:   uint64(hashIndex),
			TransactionNumber: uint64(hashIndex),
			AnchorString:      m.anchors[hashIndex],
		}

		return moreTransactions, txn
	}

	return moreTransactions, nil
}

// GetAnchors returns anchors.
func (m *MockAnchorWriter) GetAnchors() []string {
	m.RLock()
	defer m.RUnlock()

	return m.anchors
}
