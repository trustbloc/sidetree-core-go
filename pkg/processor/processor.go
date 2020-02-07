/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package processor

import (
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

// OperationProcessor will process document operations in chronological order and create final document during resolution.
// It uses operation store client to retrieve all operations that are related to requested document.
type OperationProcessor struct {
	store OperationStoreClient
}

// OperationStoreClient defines interface for retrieving all operations related to document
type OperationStoreClient interface {

	// Get retrieves all operations related to document
	Get(uniqueSuffix string) ([]batch.Operation, error)
	// Put storing operation
	Put(op batch.Operation) error
}

// New returns new operation processor
func New(store OperationStoreClient) *OperationProcessor {
	return &OperationProcessor{store: store}
}

// Resolve document based on the given unique suffix
// Parameters:
// uniqueSuffix - unique portion of ID to resolve. for example "abc123" in "did:sidetree:abc123"
func (s *OperationProcessor) Resolve(uniqueSuffix string) (document.Document, error) {
	ops, err := s.store.Get(uniqueSuffix)
	if err != nil {
		return nil, err
	}

	// Apply each operation in chronological order to build latest document
	var doc document.Document
	for i := 0; i < len(ops); i++ {
		if doc, err = s.processOperation(i, ops, doc); err != nil {
			return nil, err
		}
	}

	return doc, nil
}

func (s *OperationProcessor) processOperation(index int, operations []batch.Operation, doc document.Document) (document.Document, error) {
	operation := operations[index]
	switch operation.Type {
	case batch.OperationTypeCreate:
		if index != 0 {
			return nil, errors.New("create has to be the first operation")
		}
		return s.getInitialDocument(operation)
	case batch.OperationTypeUpdate:
		if index == 0 {
			return nil, errors.New("update cannot be first operation")
		}
		return s.applyPatch(operation, doc)
	default:
		return nil, errors.New("operation type not supported for process operation")
	}
}

func (s *OperationProcessor) getInitialDocument(operation batch.Operation) (document.Document, error) {
	decodedBytes, err := docutil.DecodeString(operation.EncodedPayload)
	if err != nil {
		return nil, err
	}

	return document.FromBytes(decodedBytes)
}

func (s *OperationProcessor) applyPatch(operation batch.Operation, currentDoc document.Document) (document.Document, error) {
	docBytes, err := currentDoc.Bytes()
	if err != nil {
		return nil, err
	}

	updatedDocBytes, err := operation.Patch.Apply(docBytes)
	if err != nil {
		return nil, err
	}

	return document.FromBytes(updatedDocBytes)
}
