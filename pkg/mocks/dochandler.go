/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/composer"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/request"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// NewMockDocumentHandler returns a new mock document handler
func NewMockDocumentHandler() *MockDocumentHandler {
	return &MockDocumentHandler{
		client: NewMockProtocolClient(),
		store:  make(map[string]document.Document),
	}
}

// MockDocumentHandler mocks the document handler
type MockDocumentHandler struct {
	err       error
	namespace string
	client    protocol.Client
	store     map[string]document.Document
}

// WithNamespace sets the namespace
func (m *MockDocumentHandler) WithNamespace(ns string) *MockDocumentHandler {
	m.namespace = ns
	return m
}

// WithError injects an error into the mock handler
func (m *MockDocumentHandler) WithError(err error) *MockDocumentHandler {
	m.err = err
	return m
}

// WithProtocolClient sets the protocol client
func (m *MockDocumentHandler) WithProtocolClient(client protocol.Client) *MockDocumentHandler {
	m.client = client
	return m
}

// Namespace returns the namespace
func (m *MockDocumentHandler) Namespace() string {
	return m.namespace
}

// Protocol returns the Protocol
func (m *MockDocumentHandler) Protocol() protocol.Client {
	return m.client
}

// ProcessOperation mocks process operation
func (m *MockDocumentHandler) ProcessOperation(operation *batch.Operation) (*document.ResolutionResult, error) {
	if m.err != nil {
		return nil, m.err
	}

	if operation.Type == batch.OperationTypeDeactivate {
		m.store[operation.ID] = nil
		return nil, nil
	}

	doc := m.store[operation.ID]
	doc, err := composer.ApplyPatches(doc, operation.Delta.Patches)
	if err != nil {
		return nil, err
	}

	doc = applyID(doc, operation.ID)

	m.store[operation.ID] = doc

	return &document.ResolutionResult{
		Document: doc,
	}, nil
}

//ResolveDocument mocks resolve document
func (m *MockDocumentHandler) ResolveDocument(idOrDocument string) (*document.ResolutionResult, error) {
	if m.err != nil {
		return nil, m.err
	}

	if strings.Contains(idOrDocument, request.GetInitialStateParam(m.namespace)) {
		return m.resolveWithInitialState(idOrDocument)
	}

	if _, ok := m.store[idOrDocument]; !ok {
		return nil, errors.New("not found")
	}

	if m.store[idOrDocument] == nil {
		return nil, errors.New("was deactivated")
	}

	return &document.ResolutionResult{
		Document: m.store[idOrDocument],
	}, nil
}

// helper function to insert ID into document
func applyID(doc document.Document, id string) document.Document {
	// apply id to document
	doc["id"] = id
	return doc
}

func (m *MockDocumentHandler) resolveWithInitialState(idOrDocument string) (*document.ResolutionResult, error) {
	id, initialState, err := request.GetParts(m.namespace, idOrDocument)
	if err != nil {
		return nil, err
	}

	decodedDelta, err := docutil.DecodeString(initialState.Delta)
	if err != nil {
		return nil, err
	}

	var delta model.DeltaModel
	err = json.Unmarshal(decodedDelta, &delta)
	if err != nil {
		return nil, err
	}

	doc, err := composer.ApplyPatches(nil, delta.Patches)
	if err != nil {
		return nil, err
	}

	doc = applyID(doc, id)
	return &document.ResolutionResult{
		Document: doc,
	}, nil
}
