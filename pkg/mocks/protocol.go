/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"github.com/trustbloc/sidetree-core-go/pkg/api"
)

// MockProtocolClient mocks protocol for testing purposes.
type MockProtocolClient struct {
	Protocol api.Protocol
}

// NewMockProtocolClient creates mocks protocol client
func NewMockProtocolClient() *MockProtocolClient {

	return &MockProtocolClient{
		Protocol: api.Protocol{
			StartingBlockChainTime:       0,
			HashAlgorithmInMultiHashCode: 18,
			MaxOperationsPerBatch:        2,
			MaxOperationByteSize:         2000,
		},
	}

}

// Current mocks getting last protocol version
func (m *MockProtocolClient) Current() api.Protocol {
	return m.Protocol
}
