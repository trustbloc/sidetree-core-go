/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"github.com/trustbloc/sidetree-core-go/pkg/document"
)

// MockDocumentValidator is responsible for validating operations, original document and transforming to external document
type MockDocumentValidator struct {
	IsValidPayloadErr          error
	IsValidOriginalDocumentErr error
	TransformDocumentErr       error
}

// New creates a new mock document validator
func New() *MockDocumentValidator {
	return &MockDocumentValidator{}
}

// IsValidPayload mocks check that the given payload is a valid Sidetree specific payload
// that can be accepted by the Sidetree update operations
func (m *MockDocumentValidator) IsValidPayload(payload []byte) error {
	return m.IsValidPayloadErr
}

// IsValidOriginalDocument  mocks check that the given payload is a valid Sidetree specific document that can be accepted by the Sidetree create operation.
func (m *MockDocumentValidator) IsValidOriginalDocument(payload []byte) error {
	return m.IsValidOriginalDocumentErr
}

// TransformDocument mocks transformation from internal to external document
func (m *MockDocumentValidator) TransformDocument(internal document.Document) (*document.ResolutionResult, error) {
	resolutionResult := &document.ResolutionResult{
		Document:       internal,
		MethodMetadata: document.MethodMetadata{},
	}

	if m.TransformDocumentErr != nil {
		return nil, m.TransformDocumentErr
	}

	return resolutionResult, nil
}
