/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package dochandler performs document operation processing and document resolution.
//
// During operation processing it will use configured validator to validate document operation and then it will call
// batch writer to add it to the batch.
//
// Document resolution is based on ID or encoded original document.
// 1) ID - the latest document will be returned if found.
//
// 2) Encoded original document - The encoded document is hashed using the current supported hashing algorithm to
// compute ID, after which the resolution is done against the computed ID. If a document cannot be found,
// the supplied document is used directly to generate and return a resolved document. In this case the supplied document
// is subject to the same validation as an original document in a create operation.
package dochandler

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/composer"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/request"
	"github.com/trustbloc/sidetree-core-go/pkg/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

var logger = log.New("sidetree-core-dochandler")

const (
	keyID = "id"

	badRequest = "bad request"
)

// DocumentHandler implements document handler
type DocumentHandler struct {
	protocol  protocol.Client
	processor OperationProcessor
	writer    BatchWriter
	validator DocumentValidator
	namespace string
	composer  docComposer
}

// OperationProcessor is an interface which resolves the document based on the ID
type OperationProcessor interface {
	Resolve(uniqueSuffix string) (*document.ResolutionResult, error)
}

// BatchWriter is an interface to add an operation to the batch
type BatchWriter interface {
	Add(operation *batch.OperationInfo) error
}

// DocumentValidator is an interface for validating document operations
type DocumentValidator interface {
	IsValidOriginalDocument(payload []byte) error
	IsValidPayload(payload []byte) error
	TransformDocument(doc document.Document) (*document.ResolutionResult, error)
}

type docComposer interface {
	ApplyPatches(doc document.Document, patches []patch.Patch) (document.Document, error)
}

// New creates a new requestHandler with the context
func New(namespace string, protocol protocol.Client, validator DocumentValidator, writer BatchWriter, processor OperationProcessor) *DocumentHandler {
	return &DocumentHandler{
		protocol:  protocol,
		processor: processor,
		writer:    writer,
		validator: validator,
		namespace: namespace,
		composer:  composer.New(),
	}
}

// Namespace returns the namespace of the document handler
func (r *DocumentHandler) Namespace() string {
	return r.namespace
}

// Protocol returns the protocol provider
func (r *DocumentHandler) Protocol() protocol.Client {
	return r.protocol
}

//ProcessOperation validates operation and adds it to the batch
func (r *DocumentHandler) ProcessOperation(operation *batch.Operation) (*document.ResolutionResult, error) {
	// perform validation for operation request
	if err := r.validateOperation(operation); err != nil {
		logger.Warnf("Failed to validate operation: %s", err.Error())
		return nil, err
	}

	// validated operation will be added to the batch
	if err := r.addToBatch(operation); err != nil {
		logger.Errorf("Failed to add operation to batch: %s", err.Error())
		return nil, err
	}

	logger.Infof("[%s] operation added to the batch", operation.ID)

	// create operation will also return document
	if operation.Type == batch.OperationTypeCreate {
		return r.getCreateResponse(operation)
	}

	return nil, nil
}

func (r *DocumentHandler) getCreateResponse(operation *batch.Operation) (*document.ResolutionResult, error) {
	doc, err := r.getInitialDocument(operation.DeltaModel.Patches)
	if err != nil {
		return nil, err
	}

	externalResult, err := r.transformToExternalDoc(doc, operation.ID)
	if err != nil {
		return nil, err
	}

	externalResult.MethodMetadata.Published = false
	externalResult.MethodMetadata.RecoveryCommitment = operation.SuffixDataModel.RecoveryCommitment
	externalResult.MethodMetadata.UpdateCommitment = operation.DeltaModel.UpdateCommitment

	return externalResult, nil
}

// ResolveDocument fetches the latest DID Document of a DID. Two forms of string can be passed in the URI:
//
// 1. Standard DID format: did:METHOD:<did-suffix>
//
// 2. DID with initial-state DID parameter (Long-Form DID URIs)
// did:METHOD:<did-suffix>?initial-state=<create-suffix-data-object>.<create-delta-object>
//
// Standard resolution is performed if the DID is found to be registered on the blockchain.
// If the DID Document cannot be found, the <create-suffix-data-object> and <create-delta-object> given
// in the initial-state DID parameter are used to generate and return resolved DID Document. In this case the supplied
// encoded delta and suffix objects are subject to the same validation as during processing create operation.
func (r *DocumentHandler) ResolveDocument(idOrInitialDoc string) (*document.ResolutionResult, error) {
	if !strings.HasPrefix(idOrInitialDoc, r.namespace+docutil.NamespaceDelimiter) {
		return nil, errors.New("must start with configured namespace")
	}

	// extract did and optional initial document value
	id, initial, err := request.GetParts(r.namespace, idOrInitialDoc)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", badRequest, err.Error())
	}

	uniquePortion, err := getSuffix(r.namespace, id)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", badRequest, err.Error())
	}

	// resolve document from the blockchain
	doc, err := r.resolveRequestWithID(uniquePortion)
	if err == nil {
		return doc, nil
	}

	// if document was not found on the blockchain and initial value has been provided resolve using initial value
	if initial != nil && strings.Contains(err.Error(), "not found") {
		return r.resolveRequestWithInitialState(id, initial)
	}

	return nil, err
}

func (r *DocumentHandler) resolveRequestWithID(uniquePortion string) (*document.ResolutionResult, error) {
	internalResult, err := r.processor.Resolve(uniquePortion)
	if err != nil {
		logger.Errorf("Failed to resolve uniquePortion[%s]: %s", uniquePortion, err.Error())
		return nil, err
	}

	externalResult, err := r.transformToExternalDoc(internalResult.Document, r.namespace+docutil.NamespaceDelimiter+uniquePortion)
	if err != nil {
		return nil, err
	}

	externalResult.MethodMetadata.Published = true
	externalResult.MethodMetadata.RecoveryCommitment = internalResult.MethodMetadata.RecoveryCommitment
	externalResult.MethodMetadata.UpdateCommitment = internalResult.MethodMetadata.UpdateCommitment

	return externalResult, nil
}

func (r *DocumentHandler) resolveRequestWithInitialState(id string, initial *model.CreateRequest) (*document.ResolutionResult, error) {
	initialBytes, err := json.Marshal(initial)
	if err != nil {
		return nil, fmt.Errorf("%s: marshal initial state: %s", badRequest, err.Error())
	}

	currentProtocol, err := r.protocol.Current()
	if err != nil {
		return nil, err
	}

	// verify size of create request does not exceed the maximum allowed limit
	if len(initialBytes) > int(currentProtocol.MaxOperationSize) {
		return nil, fmt.Errorf("%s: operation byte size exceeds protocol max operation byte size", badRequest)
	}

	op, err := operation.ParseCreateOperation(initialBytes, currentProtocol)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", badRequest, err.Error())
	}

	op.ID = r.namespace + docutil.NamespaceDelimiter + op.UniqueSuffix
	if id != op.ID {
		return nil, fmt.Errorf("%s: provided did doesn't match did created from initial state", badRequest)
	}

	err = r.validateInitialDocument(op.DeltaModel.Patches)
	if err != nil {
		return nil, fmt.Errorf("%s: validate initial document: %s", badRequest, err.Error())
	}

	result, err := r.getCreateResponse(op)
	if err != nil {
		return nil, fmt.Errorf("failed to transform create with initial state to external document: %s", err.Error())
	}

	result.MethodMetadata.InitialState = request.GetInitialState(initial)

	return result, nil
}

// helper function to transform internal into external document and return resolution result
func (r *DocumentHandler) transformToExternalDoc(internal document.Document, id string) (*document.ResolutionResult, error) {
	if internal == nil {
		return nil, errors.New("internal document is nil")
	}

	// apply id to document so it can be added to all keys and services
	internal[keyID] = id

	return r.validator.TransformDocument(internal)
}

// helper namespace for adding operations to the batch
func (r *DocumentHandler) addToBatch(operation *batch.Operation) error {
	return r.writer.Add(&batch.OperationInfo{
		Namespace:    r.namespace,
		UniqueSuffix: operation.UniqueSuffix,
		Data:         operation.OperationBuffer,
	})
}

// validateOperation validates the operation
func (r *DocumentHandler) validateOperation(operation *batch.Operation) error {
	currentProtocol, err := r.protocol.Current()
	if err != nil {
		return err
	}

	// check maximum operation size against protocol
	if len(operation.OperationBuffer) > int(currentProtocol.MaxOperationSize) {
		return errors.New("operation byte size exceeds protocol max operation byte size")
	}

	if operation.Type == batch.OperationTypeCreate {
		return r.validateInitialDocument(operation.DeltaModel.Patches)
	}

	return r.validator.IsValidPayload(operation.OperationBuffer)
}

func (r *DocumentHandler) validateInitialDocument(patches []patch.Patch) error {
	doc, err := r.getInitialDocument(patches)
	if err != nil {
		return err
	}

	docBytes, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	return r.validator.IsValidOriginalDocument(docBytes)
}

// getSuffix fetches unique portion of ID which is string after namespace
func getSuffix(namespace, idOrDocument string) (string, error) {
	ns := namespace + docutil.NamespaceDelimiter
	pos := strings.Index(idOrDocument, ns)
	if pos == -1 {
		return "", errors.New("did must start with configured namespace")
	}

	adjustedPos := pos + len(ns)
	if adjustedPos >= len(idOrDocument) {
		return "", errors.New("did suffix is empty")
	}

	return idOrDocument[adjustedPos:], nil
}

func (r *DocumentHandler) getInitialDocument(patches []patch.Patch) (document.Document, error) {
	return r.composer.ApplyPatches(make(document.Document), patches)
}
