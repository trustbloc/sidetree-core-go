/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/trustbloc/sidetree-core-go/pkg/encoder"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
)

const sha2_256 = 18

// MockCasClient mocks CAS for testing purposes.
type MockCasClient struct {
	mutex sync.RWMutex
	m     map[string][]byte
	err   error
}

// NewMockCasClient creates mock client.
func NewMockCasClient(err error) *MockCasClient {
	return &MockCasClient{m: make(map[string][]byte), err: err}
}

// Write writes the given content to CAS.
// returns the SHA256 hash in base64url encoding which represents the address of the content.
func (m *MockCasClient) Write(content []byte) (string, error) {
	err := m.GetError()
	if err != nil {
		return "", err
	}
	hash, err := hashing.ComputeMultihash(sha2_256, content)
	if err != nil {
		return "", err
	}

	key := encoder.EncodeToString(hash)

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.m[key] = content

	return key, nil
}

// Read reads the content of the given address in CAS.
// returns the content of the given address.
func (m *MockCasClient) Read(address string) ([]byte, error) {
	err := m.GetError()
	if err != nil {
		return nil, err
	}

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	value, ok := m.m[address]
	if !ok {
		return nil, fmt.Errorf("not found")
	}

	// decode address to verify hashes
	decoded, err := encoder.DecodeString(address)
	if err != nil {
		return nil, err
	}

	valueHash, err := hashing.ComputeMultihash(sha2_256, value)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(valueHash, decoded) {
		return nil, fmt.Errorf("hashes don't match")
	}

	return value, nil
}

// SetError injects an error into the mock client.
func (m *MockCasClient) SetError(err error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.err = err
}

// GetError returns the injected error.
func (m *MockCasClient) GetError() error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.err
}
