/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/request"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/doccomposer"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
)

// NewMockDocumentHandler returns a new mock document handler.
func NewMockDocumentHandler() *MockDocumentHandler {
	return &MockDocumentHandler{
		client: NewMockProtocolClient(),
		store:  make(map[string]document.Document),
	}
}

// MockDocumentHandler mocks the document handler.
type MockDocumentHandler struct {
	err       error
	namespace string
	client    protocol.Client
	store     map[string]document.Document
}

// WithNamespace sets the namespace.
func (m *MockDocumentHandler) WithNamespace(ns string) *MockDocumentHandler {
	m.namespace = ns

	return m
}

// WithError injects an error into the mock handler.
func (m *MockDocumentHandler) WithError(err error) *MockDocumentHandler {
	m.err = err

	return m
}

// WithProtocolClient sets the protocol client.
func (m *MockDocumentHandler) WithProtocolClient(client protocol.Client) *MockDocumentHandler {
	m.client = client

	return m
}

// Namespace returns the namespace.
func (m *MockDocumentHandler) Namespace() string {
	return m.namespace
}

// Protocol returns the Protocol.
func (m *MockDocumentHandler) Protocol() protocol.Client {
	return m.client
}

// Operation is used for parsing operation request.
type Operation struct {
	// Operation defines operation type
	Operation batch.OperationType `json:"type,omitempty"`

	// SuffixData object
	SuffixData *model.SuffixDataModel `json:"suffix_data,omitempty"`

	// Delta object
	Delta *model.DeltaModel `json:"delta,omitempty"`

	// DidSuffix is the suffix of the DID
	DidSuffix string `json:"did_suffix"`
}

// ProcessOperation mocks process operation.
func (m *MockDocumentHandler) ProcessOperation(operationBuffer []byte, _ uint64) (*document.ResolutionResult, error) {
	if m.err != nil {
		return nil, m.err
	}

	var operation Operation
	err := json.Unmarshal(operationBuffer, &operation)
	if err != nil {
		return nil, fmt.Errorf("bad request: %s", err.Error())
	}

	var suffix string
	switch operation.Operation {
	case batch.OperationTypeCreate:
		suffix, err = docutil.CalculateModelMultihash(operation.SuffixData, sha2_256)
		if err != nil {
			return nil, err
		}
	case batch.OperationTypeUpdate, batch.OperationTypeDeactivate, batch.OperationTypeRecover:
		suffix = operation.DidSuffix
	default:
		return nil, fmt.Errorf("bad request: operation type [%s] not supported", operation.Operation)
	}

	id := m.namespace + docutil.NamespaceDelimiter + suffix

	if operation.Operation == batch.OperationTypeDeactivate {
		m.store[id] = nil

		return nil, nil
	}

	doc, ok := m.store[id]
	if !ok { // create operation
		doc = make(document.Document)
	}

	doc, err = doccomposer.New().ApplyPatches(doc, operation.Delta.Patches)
	if err != nil {
		return nil, err
	}

	doc = applyID(doc, id)

	m.store[id] = doc

	return &document.ResolutionResult{
		Document: doc,
	}, nil
}

// ResolveDocument mocks resolve document.
func (m *MockDocumentHandler) ResolveDocument(didOrDocument string) (*document.ResolutionResult, error) {
	if m.err != nil {
		return nil, m.err
	}

	const badRequest = "bad request"
	if !strings.HasPrefix(didOrDocument, m.namespace) {
		return nil, fmt.Errorf("%s: must start with supported namespace", badRequest)
	}

	did, initial, err := request.GetParts(m.namespace, didOrDocument)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", badRequest, err.Error())
	}

	if initial != nil {
		return m.resolveWithInitialState(did, initial)
	}

	if _, ok := m.store[didOrDocument]; !ok {
		return nil, errors.New("not found")
	}

	if m.store[didOrDocument] == nil {
		return nil, errors.New("was deactivated")
	}

	return &document.ResolutionResult{
		Document: m.store[didOrDocument],
	}, nil
}

// helper function to insert ID into document.
func applyID(doc document.Document, id string) document.Document {
	// apply id to document
	doc["id"] = id

	return doc
}

func (m *MockDocumentHandler) resolveWithInitialState(did string, initial []byte) (*document.ResolutionResult, error) {
	var createReq model.CreateRequest
	err := json.Unmarshal(initial, &createReq)
	if err != nil {
		return nil, err
	}

	doc, err := doccomposer.New().ApplyPatches(make(document.Document), createReq.Delta.Patches)
	if err != nil {
		return nil, err
	}

	doc = applyID(doc, did)

	return &document.ResolutionResult{
		Document: doc,
	}, nil
}
