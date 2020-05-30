/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"github.com/pkg/errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
)

// DefaultNS is default namespace used in mocks
const DefaultNS = "did:sidetree"

// MockProtocolClient mocks protocol for testing purposes.
type MockProtocolClient struct {
	Protocol protocol.Protocol
}

// NewMockProtocolClient creates mocks protocol client
func NewMockProtocolClient() *MockProtocolClient {
	return &MockProtocolClient{
		//nolint:gomnd // mock values are defined below.
		Protocol: protocol.Protocol{
			StartingBlockChainTime:       0,
			HashAlgorithmInMultiHashCode: sha2_256,
			MaxOperationsPerBatch:        2,
			MaxDeltaByteSize:             2000,
		},
	}
}

// Current mocks getting last protocol version
func (m *MockProtocolClient) Current() protocol.Protocol {
	return m.Protocol
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
