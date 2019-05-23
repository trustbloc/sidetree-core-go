/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import "sync"

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

// GetAnchors returns anchors
func (m *MockBlockchainClient) GetAnchors() []string {

	m.RLock()
	defer m.RUnlock()

	return m.anchors
}
