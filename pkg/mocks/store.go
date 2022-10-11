/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"errors"
	"sync"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
)

// MockOperationStore mocks store for testing purposes.
type MockOperationStore struct {
	mutex      sync.RWMutex
	operations map[string][]*operation.AnchoredOperation
	Err        error
	Validate   bool
}

// NewMockOperationStore creates mock operations store.
func NewMockOperationStore(err error) *MockOperationStore {
	return &MockOperationStore{operations: make(map[string][]*operation.AnchoredOperation), Err: err, Validate: true}
}

// Put mocks storing operation.
func (m *MockOperationStore) Put(op *operation.AnchoredOperation) error {
	if m.Err != nil {
		return m.Err
	}

	var opsSize int
	m.mutex.RLock()
	opsSize = len(m.operations[op.UniqueSuffix])
	m.mutex.RUnlock()

	if m.Validate && op.Type == operation.TypeCreate && opsSize > 0 {
		// Nothing to do; already created
		return nil
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.operations[op.UniqueSuffix] = append(m.operations[op.UniqueSuffix], op)

	return nil
}

// Get mocks retrieving operations from the store.
func (m *MockOperationStore) Get(uniqueSuffix string) ([]*operation.AnchoredOperation, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if ops, ok := m.operations[uniqueSuffix]; ok {
		return ops, nil
	}

	return nil, errors.New("uniqueSuffix not found in the store")
}
