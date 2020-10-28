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

const (

	// DefaultNS is default namespace used in mocks.
	DefaultNS = "did:sidetree"

	// MaxBatchFileSize is maximum batch files size in bytes.
	MaxBatchFileSize = 20000

	// MaxOperationByteSize is maximum operation size in bytes.
	MaxOperationByteSize = 2000

	// CurrentVersion is the current protocol version.
	CurrentVersion = "0.1"
)

// MockProtocolClient mocks protocol for testing purposes.
type MockProtocolClient struct {
	Protocol       protocol.Protocol // current version (separated for easier testing)
	CurrentVersion *ProtocolVersion
	Versions       []*ProtocolVersion
	Err            error
	CasClient      *MockCasClient
}

// NewMockProtocolClient creates mock protocol client.
func NewMockProtocolClient() *MockProtocolClient {
	//nolint:gomnd
	latest := protocol.Protocol{
		GenesisTime:          0,
		MultihashAlgorithm:   sha2_256,
		HashAlgorithm:        5, // crypto code for sha256 hash function
		MaxOperationCount:    2,
		MaxOperationSize:     MaxOperationByteSize,
		CompressionAlgorithm: "GZIP",
		MaxChunkFileSize:     MaxBatchFileSize,
		MaxMapFileSize:       MaxBatchFileSize,
		MaxAnchorFileSize:    MaxBatchFileSize,
		SignatureAlgorithms:  []string{"EdDSA", "ES256"},
		KeyAlgorithms:        []string{"Ed25519", "P-256"},
		Patches:              []string{"add-public-keys", "remove-public-keys", "add-services", "remove-services", "ietf-json-patch"},
	}

	latestVersion := GetProtocolVersion(latest)

	// has to be sorted for mock client to work
	versions := []*ProtocolVersion{latestVersion}

	return &MockProtocolClient{
		Protocol:       latest,
		CurrentVersion: latestVersion,
		Versions:       versions,
	}
}

// Current mocks getting last protocol version.
func (m *MockProtocolClient) Current() (protocol.Version, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return m.CurrentVersion, nil
}

// Get mocks getting protocol version based on blockchain(transaction) time.
func (m *MockProtocolClient) Get(transactionTime uint64) (protocol.Version, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	for i := len(m.Versions) - 1; i >= 0; i-- {
		if transactionTime >= m.Versions[i].Protocol().GenesisTime {
			return m.Versions[i], nil
		}
	}

	return nil, fmt.Errorf("protocol parameters are not defined for blockchain time: %d", transactionTime)
}

// NewMockProtocolClientProvider creates new mock protocol client provider.
func NewMockProtocolClientProvider() *MockProtocolClientProvider {
	m := make(map[string]protocol.Client)

	m[DefaultNS] = NewMockProtocolClient()

	return &MockProtocolClientProvider{
		ProtocolClients: m,
	}
}

// MockProtocolClientProvider implements mock protocol client provider.
type MockProtocolClientProvider struct {
	ProtocolClients map[string]protocol.Client
}

// WithProtocolClient sets the protocol client.
func (m *MockProtocolClientProvider) WithProtocolClient(ns string, pc protocol.Client) *MockProtocolClientProvider {
	m.ProtocolClients[ns] = pc

	return m
}

// ForNamespace will return protocol client for that namespace.
func (m *MockProtocolClientProvider) ForNamespace(namespace string) (protocol.Client, error) {
	pc, ok := m.ProtocolClients[namespace]
	if !ok {
		return nil, errors.Errorf("protocol client not found for namespace [%s]", namespace)
	}

	return pc, nil
}

// GetProtocolVersion returns mock protocol version.
func GetProtocolVersion(p protocol.Protocol) *ProtocolVersion {
	v := &ProtocolVersion{}
	v.VersionReturns(CurrentVersion)
	v.OperationApplierReturns(&OperationApplier{})
	v.OperationParserReturns(&OperationParser{})
	v.DocumentComposerReturns(&DocumentComposer{})
	v.DocumentValidatorReturns(&DocumentValidator{})

	v.ProtocolReturns(p)

	return v
}
