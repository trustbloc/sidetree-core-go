/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"sync"

	"github.com/trustbloc/sidetree-core-go/pkg/observer"
)

// MockBlockchainClient mocks blockchain client for testing purposes.
type MockBlockchainClient struct {
	sync.RWMutex
	anchors []string
	err     error
}

// NewMockBlockchainClient creates mock client
func NewMockBlockchainClient(err error) *MockBlockchainClient {
	return &MockBlockchainClient{err: err}
}

// WriteAnchor writes the anchor file hash as a transaction to blockchain.
func (m *MockBlockchainClient) WriteAnchor(anchorFileHash string) error {

	if m.err != nil {
		return m.err
	}

	m.Lock()
	defer m.Unlock()

	m.anchors = append(m.anchors, anchorFileHash)

	return nil
}

func (m *MockBlockchainClient) Read(sinceTransactionNumber int) (bool, *observer.SidetreeTxn) {
	m.RLock()
	defer m.RUnlock()
	moreTransactions := false
	if len(m.anchors) > 0 && sinceTransactionNumber < len(m.anchors)-2 {
		moreTransactions = true
	}

	if len(m.anchors) > 0 && sinceTransactionNumber < len(m.anchors)-1 {
		hashIndex := sinceTransactionNumber + 1
		return moreTransactions, &observer.SidetreeTxn{TransactionTime: uint64(hashIndex), TransactionNumber: uint64(hashIndex), AnchorAddress: m.anchors[hashIndex]}
	}
	return moreTransactions, nil
}

// GetAnchors returns anchors
func (m *MockBlockchainClient) GetAnchors() []string {

	m.RLock()
	defer m.RUnlock()

	return m.anchors
}
