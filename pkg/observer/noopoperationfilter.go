/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
)

// NoopOperationFilterProvider is an operation filter provider that does not filter operations
type NoopOperationFilterProvider struct {
}

// Get returns a noop operation filter
func (m *NoopOperationFilterProvider) Get(string) OperationFilter {
	return &noopOperationFilter{}
}

type noopOperationFilter struct {
}

// Filter simply returns the provided operations without filtering them
func (m *noopOperationFilter) Filter(_ string, ops []*batch.Operation) ([]*batch.Operation, error) {
	return ops, nil
}
