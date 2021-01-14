/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package doctransformer

import (
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/doctransformer"
)

// Transformer is responsible for transforming internal to external document.
type Transformer struct {
}

// New creates a new document transformer.
func New() *Transformer {
	return &Transformer{}
}

// TransformDocument takes internal resolution model and transformation info and creates
// external representation of document (resolution result).
func (v *Transformer) TransformDocument(rm *protocol.ResolutionModel, info protocol.TransformationInfo) (*document.ResolutionResult, error) {
	docMetadata, err := doctransformer.CreateDocumentMetadata(rm, info)
	if err != nil {
		return nil, err
	}

	id, ok := info[document.IDProperty]
	if !ok {
		return nil, errors.New("id is required for document transformation")
	}

	rm.Doc[document.IDProperty] = id

	result := &document.ResolutionResult{
		Document:         rm.Doc,
		DocumentMetadata: docMetadata,
	}

	return result, nil
}
