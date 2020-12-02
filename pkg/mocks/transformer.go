/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
)

// MockDocumentTransformer is responsible for validating operations, original document and transforming to external document.
type MockDocumentTransformer struct {
	Err error
}

// NewDocumentTransformer creates a new mock document transformer.
func NewDocumentTransformer() *MockDocumentTransformer {
	return &MockDocumentTransformer{}
}

// TransformDocument mocks transformation from internal to external document.
func (m *MockDocumentTransformer) TransformDocument(internal *protocol.ResolutionModel, info protocol.TransformationInfo) (*document.ResolutionResult, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	internal.Doc[document.IDProperty] = info[document.IDProperty]

	metadata := make(document.Metadata)
	metadata[document.PublishedProperty] = info[document.PublishedProperty]
	metadata[document.RecoveryCommitmentProperty] = internal.RecoveryCommitment
	metadata[document.UpdateCommitmentProperty] = internal.UpdateCommitment

	return &document.ResolutionResult{
		Document:       internal.Doc,
		MethodMetadata: metadata,
	}, nil
}
