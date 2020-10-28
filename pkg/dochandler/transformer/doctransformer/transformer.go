/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package doctransformer

import (
	"github.com/trustbloc/sidetree-core-go/pkg/document"
)

// Transformer is responsible for transforming internal to external document.
type Transformer struct {
}

// New creates a new document transformer.
func New() *Transformer {
	return &Transformer{}
}

// TransformDocument takes internal representation of document and transforms it to required representation.
func (v *Transformer) TransformDocument(internal document.Document) (*document.ResolutionResult, error) {
	resolutionResult := &document.ResolutionResult{
		Document:       internal,
		MethodMetadata: document.MethodMetadata{},
	}

	return resolutionResult, nil
}
