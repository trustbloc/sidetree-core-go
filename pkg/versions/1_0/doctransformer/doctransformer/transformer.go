/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package doctransformer

import (
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/doctransformer/metadata"
)

// Transformer is responsible for transforming internal to external document.
type Transformer struct {
	includePublishedOperations   bool
	includeUnpublishedOperations bool
}

// Option is a registry instance option.
type Option func(opts *Transformer)

// New creates a new document transformer.
func New(opts ...Option) *Transformer {
	transformer := &Transformer{}

	// apply options
	for _, opt := range opts {
		opt(transformer)
	}

	return transformer
}

// WithIncludePublishedOperations sets optional include published operations flag.
func WithIncludePublishedOperations(enabled bool) Option {
	return func(opts *Transformer) {
		opts.includePublishedOperations = enabled
	}
}

// WithIncludeUnpublishedOperations sets optional include unpublished operations flag.
func WithIncludeUnpublishedOperations(enabled bool) Option {
	return func(opts *Transformer) {
		opts.includeUnpublishedOperations = enabled
	}
}

// TransformDocument takes internal resolution model and transformation info and creates
// external representation of document (resolution result).
func (v *Transformer) TransformDocument(rm *protocol.ResolutionModel,
	info protocol.TransformationInfo) (*document.ResolutionResult, error) {
	docMetadata, err := metadata.New(
		metadata.WithIncludeUnpublishedOperations(v.includeUnpublishedOperations),
		metadata.WithIncludePublishedOperations(v.includePublishedOperations)).
		CreateDocumentMetadata(rm, info)
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
