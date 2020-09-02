/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
)

// DefaultNS is default namespace used in mocks
const DefaultNS = "did:sidetree"

// maximum batch files size in bytes
const maxBatchFileSize = 20000

const maxOperationByteSize = 2000

// MockProtocolClient mocks protocol for testing purposes.
type MockProtocolClient struct {
	Protocol protocol.Protocol // current version (separated for easier testing)
	Versions []protocol.Protocol
	Err      error
}

// NewMockProtocolClient creates mock protocol client
func NewMockProtocolClient() *MockProtocolClient {
	//nolint:gomnd
	latest := protocol.Protocol{
		GenesisTime:                  0,
		HashAlgorithmInMultiHashCode: sha2_256,
		MaxOperationCount:            2,
		MaxOperationSize:             maxOperationByteSize,
		CompressionAlgorithm:         "GZIP",
		MaxChunkFileSize:             maxBatchFileSize,
		MaxMapFileSize:               maxBatchFileSize,
		MaxAnchorFileSize:            maxBatchFileSize,
		SignatureAlgorithms:          []string{"EdDSA", "ES256"},
		KeyAlgorithms:                []string{"Ed25519", "P-256"},
	}

	// has to be sorted for mock client to work
	versions := []protocol.Protocol{latest}

	return &MockProtocolClient{
		Protocol: latest,
		Versions: versions,
	}
}

// Current mocks getting last protocol version
func (m *MockProtocolClient) Current() (protocol.Protocol, error) {
	if m.Err != nil {
		return protocol.Protocol{}, m.Err
	}

	return m.Protocol, nil
}

// Get mocks getting protocol version based on blockchain(transaction) time
func (m *MockProtocolClient) Get(transactionTime uint64) (protocol.Protocol, error) {
	if m.Err != nil {
		return protocol.Protocol{}, m.Err
	}

	for i := len(m.Versions) - 1; i >= 0; i-- {
		if transactionTime >= m.Versions[i].GenesisTime {
			return m.Versions[i], nil
		}
	}

	return protocol.Protocol{}, fmt.Errorf("protocol parameters are not defined for blockchain time: %d", transactionTime)
}

// NewMockProtocolClientProvider creates new mock protocol client provider
func NewMockProtocolClientProvider() *MockProtocolClientProvider {
	m := make(map[string]protocol.Client)

	m[DefaultNS] = NewMockProtocolClient()
	return &MockProtocolClientProvider{
		ProtocolClients: m,
	}
}

// MockProtocolClientProvider implements mock protocol client provider
type MockProtocolClientProvider struct {
	ProtocolClients map[string]protocol.Client
}

// ForNamespace will return protocol client for that namespace
func (m *MockProtocolClientProvider) ForNamespace(namespace string) (protocol.Client, error) {
	pc, ok := m.ProtocolClients[namespace]
	if !ok {
		return nil, errors.Errorf("protocol client not found for namespace [%s]", namespace)
	}

	return pc, nil
}
