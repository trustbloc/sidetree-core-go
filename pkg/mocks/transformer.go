/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"github.com/trustbloc/sidetree-core-go/pkg/document"
)

// MockDocumentTransformer is responsible for validating operations, original document and transforming to external document
type MockDocumentTransformer struct {
	Err error
}

// NewDocumentTransformer creates a new mock document transformer
func NewDocumentTransformer() *MockDocumentTransformer {
	return &MockDocumentTransformer{}
}

// TransformDocument mocks transformation from internal to external document
func (m *MockDocumentTransformer) TransformDocument(internal document.Document) (*document.ResolutionResult, error) {
	resolutionResult := &document.ResolutionResult{
		Document:       internal,
		MethodMetadata: document.MethodMetadata{},
	}

	if m.Err != nil {
		return nil, m.Err
	}

	return resolutionResult, nil
}
