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
	"errors"
	"fmt"
	"strings"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

var logger = log.New("sidetree-core-dochandler")

const (
	keyID = "id"

	badRequest = "bad request"
)

// DocumentHandler implements document handler.
type DocumentHandler struct {
	protocol    protocol.Client
	processor   OperationProcessor
	writer      BatchWriter
	transformer DocumentTransformer
	namespace   string
	aliases     []string // namespace aliases
}

// OperationProcessor is an interface which resolves the document based on the ID.
type OperationProcessor interface {
	Resolve(uniqueSuffix string) (*document.ResolutionResult, error)
}

// BatchWriter is an interface to add an operation to the batch.
type BatchWriter interface {
	Add(operation *operation.QueuedOperation, protocolGenesisTime uint64) error
}

// DocumentTransformer transforms a document from internal to external form.
type DocumentTransformer interface {
	TransformDocument(doc document.Document) (*document.ResolutionResult, error)
}

// New creates a new requestHandler with the context.
func New(namespace string, aliases []string, pc protocol.Client, transformer DocumentTransformer, writer BatchWriter, processor OperationProcessor) *DocumentHandler {
	return &DocumentHandler{
		protocol:    pc,
		processor:   processor,
		writer:      writer,
		transformer: transformer,
		namespace:   namespace,
		aliases:     aliases,
	}
}

// Namespace returns the namespace of the document handler.
func (r *DocumentHandler) Namespace() string {
	return r.namespace
}

// ProcessOperation validates operation and adds it to the batch.
func (r *DocumentHandler) ProcessOperation(operationBuffer []byte, protocolGenesisTime uint64) (*document.ResolutionResult, error) {
	pv, err := r.protocol.Get(protocolGenesisTime)
	if err != nil {
		return nil, err
	}

	op, err := pv.OperationParser().Parse(r.namespace, operationBuffer)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", badRequest, err.Error())
	}

	// perform validation for operation request
	if err := r.validateOperation(op, pv); err != nil {
		logger.Warnf("Failed to validate operation: %s", err.Error())

		return nil, err
	}

	// validated operation will be added to the batch
	if err := r.addToBatch(op, pv.Protocol().GenesisTime); err != nil {
		logger.Errorf("Failed to add operation to batch: %s", err.Error())

		return nil, err
	}

	logger.Infof("[%s] operation added to the batch", op.ID)

	// create operation will also return document
	if op.Type == operation.TypeCreate {
		return r.getCreateResponse(op, pv)
	}

	return nil, nil
}

func (r *DocumentHandler) getCreateResult(op *operation.Operation, pv protocol.Version) (*protocol.ResolutionModel, error) {
	// we can use operation applier to generate create response even though operation is not anchored yet
	anchored := &operation.AnchoredOperation{
		Type:            op.Type,
		UniqueSuffix:    op.UniqueSuffix,
		OperationBuffer: op.OperationBuffer,
	}

	rm := &protocol.ResolutionModel{}
	rm, err := pv.OperationApplier().Apply(anchored, rm)
	if err != nil {
		return nil, err
	}

	return rm, nil
}

func (r *DocumentHandler) getCreateResponse(op *operation.Operation, pv protocol.Version) (*document.ResolutionResult, error) {
	rm, err := r.getCreateResult(op, pv)
	if err != nil {
		return nil, err
	}

	externalResult, err := r.transformToExternalDoc(rm.Doc, op.ID)
	if err != nil {
		return nil, err
	}

	externalResult.MethodMetadata.Published = false
	externalResult.MethodMetadata.RecoveryCommitment = rm.RecoveryCommitment
	externalResult.MethodMetadata.UpdateCommitment = rm.UpdateCommitment

	return externalResult, nil
}

// ResolveDocument fetches the latest DID Document of a DID. Two forms of string can be passed in the URI:
//
// 1. Standard DID format: did:METHOD:<did-suffix>
//
// 2. Long Form DID format:
// did:METHOD:<did-suffix>:Base64url(JCS({suffix-data-object, delta-object}))
//
// Standard resolution is performed if the DID is found to be registered on the blockchain.
// If the DID Document cannot be found, the <suffix-data-object> and <delta-object> are used
// to generate and return resolved DID Document. In this case the supplied delta and suffix objects
// are subject to the same validation as during processing create operation.
func (r *DocumentHandler) ResolveDocument(shortOrLongFormDID string) (*document.ResolutionResult, error) {
	ns, err := r.getNamespace(shortOrLongFormDID)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", badRequest, err.Error())
	}

	pv, err := r.protocol.Current()
	if err != nil {
		return nil, err
	}

	// extract did and optional initial document value
	shortFormDID, createReq, err := pv.OperationParser().ParseDID(ns, shortOrLongFormDID)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", badRequest, err.Error())
	}

	uniquePortion, err := getSuffix(ns, shortFormDID)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", badRequest, err.Error())
	}

	// resolve document from the blockchain
	doc, err := r.resolveRequestWithID(ns, uniquePortion)
	if err == nil {
		return doc, nil
	}

	// if document was not found on the blockchain and initial value has been provided resolve using initial value
	if createReq != nil && strings.Contains(err.Error(), "not found") {
		return r.resolveRequestWithInitialState(uniquePortion, shortOrLongFormDID, createReq, pv)
	}

	return nil, err
}

func (r *DocumentHandler) getNamespace(shortOrLongFormDID string) (string, error) {
	// check namespace
	if strings.HasPrefix(shortOrLongFormDID, r.namespace+docutil.NamespaceDelimiter) {
		return r.namespace, nil
	}

	// check aliases
	for _, ns := range r.aliases {
		if strings.HasPrefix(shortOrLongFormDID, ns+docutil.NamespaceDelimiter) {
			return ns, nil
		}
	}

	return "", fmt.Errorf("did must start with configured namespace[%s] or aliases%v", r.namespace, r.aliases)
}

func (r *DocumentHandler) resolveRequestWithID(namespace, uniquePortion string) (*document.ResolutionResult, error) {
	internalResult, err := r.processor.Resolve(uniquePortion)
	if err != nil {
		logger.Errorf("Failed to resolve uniquePortion[%s]: %s", uniquePortion, err.Error())

		return nil, err
	}

	externalResult, err := r.transformToExternalDoc(internalResult.Document, namespace+docutil.NamespaceDelimiter+uniquePortion)
	if err != nil {
		return nil, err
	}

	if r.namespace != namespace {
		// we got here using alias; suggest using namespace
		externalResult.MethodMetadata.CanonicalID = r.namespace + docutil.NamespaceDelimiter + uniquePortion
	}

	externalResult.MethodMetadata.Published = true
	externalResult.MethodMetadata.RecoveryCommitment = internalResult.MethodMetadata.RecoveryCommitment
	externalResult.MethodMetadata.UpdateCommitment = internalResult.MethodMetadata.UpdateCommitment

	return externalResult, nil
}

func (r *DocumentHandler) resolveRequestWithInitialState(uniqueSuffix, longFormDID string, initialBytes []byte, pv protocol.Version) (*document.ResolutionResult, error) {
	// verify size of create request does not exceed the maximum allowed limit
	if len(initialBytes) > int(pv.Protocol().MaxOperationSize) {
		return nil, fmt.Errorf("%s: operation byte size exceeds protocol max operation byte size", badRequest)
	}

	op, err := pv.OperationParser().Parse(r.namespace, initialBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", badRequest, err.Error())
	}

	if uniqueSuffix != op.UniqueSuffix {
		return nil, fmt.Errorf("%s: provided did doesn't match did created from initial state", badRequest)
	}

	rm, err := r.getCreateResult(op, pv)
	if err != nil {
		return nil, err
	}

	docBytes, err := canonicalizer.MarshalCanonical(rm.Doc)
	if err != nil {
		return nil, err
	}

	err = pv.DocumentValidator().IsValidOriginalDocument(docBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: validate initial document: %s", badRequest, err.Error())
	}

	externalResult, err := r.transformToExternalDoc(rm.Doc, longFormDID)
	if err != nil {
		return nil, fmt.Errorf("failed to transform create with initial state to external document: %s", err.Error())
	}

	externalResult.MethodMetadata.Published = false
	externalResult.MethodMetadata.RecoveryCommitment = rm.RecoveryCommitment
	externalResult.MethodMetadata.UpdateCommitment = rm.UpdateCommitment

	return externalResult, nil
}

// helper function to transform internal into external document and return resolution result.
func (r *DocumentHandler) transformToExternalDoc(internal document.Document, id string) (*document.ResolutionResult, error) {
	if internal == nil {
		return nil, errors.New("internal document is nil")
	}

	// apply id to document so it can be added to all keys and services
	internal[keyID] = id

	return r.transformer.TransformDocument(internal)
}

// helper for adding operations to the batch.
func (r *DocumentHandler) addToBatch(op *operation.Operation, genesisTime uint64) error {
	return r.writer.Add(
		&operation.QueuedOperation{
			Namespace:       r.namespace,
			UniqueSuffix:    op.UniqueSuffix,
			OperationBuffer: op.OperationBuffer,
		}, genesisTime)
}

func (r *DocumentHandler) validateOperation(op *operation.Operation, pv protocol.Version) error {
	// check maximum operation size against protocol
	if len(op.OperationBuffer) > int(pv.Protocol().MaxOperationSize) {
		return errors.New("operation byte size exceeds protocol max operation byte size")
	}

	if op.Type == operation.TypeCreate {
		return r.validateCreateDocument(op, pv)
	}

	// TODO: Change interface for IsValidPayload to batch.Operation (impacts fabric)
	return pv.DocumentValidator().IsValidPayload(op.OperationBuffer)
}

func (r *DocumentHandler) validateCreateDocument(op *operation.Operation, pv protocol.Version) error {
	rm, err := r.getCreateResult(op, pv)
	if err != nil {
		return err
	}

	docBytes, err := canonicalizer.MarshalCanonical(rm.Doc)
	if err != nil {
		return err
	}

	return pv.DocumentValidator().IsValidOriginalDocument(docBytes)
}

// getSuffix fetches unique portion of ID which is string after namespace.
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
