/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
)

const sha2_256 = 18

// MockCasClient mocks CAS for testing purposes.
type MockCasClient struct {
	sync.RWMutex
	m   map[string][]byte
	err error
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

	key := base64.URLEncoding.EncodeToString(hash)

	m.Lock()
	defer m.Unlock()

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

	m.RLock()
	defer m.RUnlock()

	value, ok := m.m[address]
	if !ok {
		return nil, fmt.Errorf("not found")
	}

	// decode address to verify hashes
	decoded, err := base64.URLEncoding.DecodeString(address)
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
	m.Lock()
	defer m.Unlock()

	m.err = err
}

// GetError returns the injected error.
func (m *MockCasClient) GetError() error {
	m.RLock()
	defer m.RUnlock()

	return m.err
}
