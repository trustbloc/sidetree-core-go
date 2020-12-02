/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package doctransformer

import (
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
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
	if rm == nil || rm.Doc == nil {
		return nil, errors.New("resolution model is required for document transformation")
	}

	if info == nil {
		return nil, errors.New("transformation info is required for document transformation")
	}

	id, ok := info[document.IDProperty]
	if !ok {
		return nil, errors.New("id is required for document transformation")
	}

	published, ok := info[document.PublishedProperty]
	if !ok {
		return nil, errors.New("published is required for document transformation")
	}

	rm.Doc[document.IDProperty] = id

	methodMetadata := make(document.Metadata)
	methodMetadata[document.PublishedProperty] = published
	methodMetadata[document.RecoveryCommitmentProperty] = rm.RecoveryCommitment
	methodMetadata[document.UpdateCommitmentProperty] = rm.UpdateCommitment

	result := &document.ResolutionResult{
		Document:       rm.Doc,
		MethodMetadata: methodMetadata,
	}

	docMetadata := make(document.Metadata)

	canonicalID, ok := info[document.CanonicalIDProperty]
	if ok {
		docMetadata[document.CanonicalIDProperty] = canonicalID
	}

	if len(docMetadata) > 0 {
		result.DocumentMetadata = docMetadata
	}

	return result, nil
}
