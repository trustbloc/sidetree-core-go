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
	protocol  protocol.Client
	processor OperationProcessor
	writer    BatchWriter
	namespace string
	aliases   []string // namespace aliases
	domain    string
	label     string
}

// OperationProcessor is an interface which resolves the document based on the ID.
type OperationProcessor interface {
	Resolve(uniqueSuffix string) (*protocol.ResolutionModel, error)
}

// BatchWriter is an interface to add an operation to the batch.
type BatchWriter interface {
	Add(operation *operation.QueuedOperation, protocolGenesisTime uint64) error
}

// Option is an option for document handler.
type Option func(opts *DocumentHandler)

// WithDomain sets optional domain hint for unpublished/interim documents.
func WithDomain(domain string) Option {
	return func(opts *DocumentHandler) {
		opts.domain = domain
	}
}

// WithLabel sets optional label for unpublished/interim documents.
func WithLabel(label string) Option {
	return func(opts *DocumentHandler) {
		opts.label = label
	}
}

// New creates a new document handler with the context.
func New(namespace string, aliases []string, pc protocol.Client, writer BatchWriter, processor OperationProcessor, opts ...Option) *DocumentHandler {
	dh := &DocumentHandler{
		protocol:  pc,
		processor: processor,
		writer:    writer,
		namespace: namespace,
		aliases:   aliases,
	}

	// apply options
	for _, opt := range opts {
		opt(dh)
	}

	return dh
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

	logger.Debugf("[%s] operation added to the batch", op.ID)

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

	// if returned document is empty (e.g. applying patches failed) we can reject this request at API level
	if len(rm.Doc.JSONLdObject()) == 0 {
		return nil, errors.New("applying delta resulted in an empty document (most likely due to an invalid patch)")
	}

	return rm, nil
}

func (r *DocumentHandler) getCreateResponse(op *operation.Operation, pv protocol.Version) (*document.ResolutionResult, error) {
	rm, err := r.getCreateResult(op, pv)
	if err != nil {
		return nil, err
	}

	ti := r.getTransformationInfoForUnpublished(op.UniqueSuffix, "")

	return pv.DocumentTransformer().TransformDocument(rm, ti)
}

func (r *DocumentHandler) getTransformationInfoForUnpublished(suffix string, createRequestJCS string) protocol.TransformationInfo {
	ti := make(protocol.TransformationInfo)
	ti[document.PublishedProperty] = false

	id := fmt.Sprintf("%s:%s", r.namespace, suffix)

	// For interim/unpublished documents we should set optional label if specified.
	if r.label != "" {
		id = fmt.Sprintf("%s:%s:%s", r.namespace, r.label, suffix)
	}

	var equivalentIDs []string

	if createRequestJCS != "" {
		// we should always set short form equivalent id for long form resolution
		equivalentIDs = append(equivalentIDs, id)
	}

	// Also, if optional domain is specified, we should set equivalent id with domain hint
	if r.label != "" && r.domain != "" {
		equivalentID := fmt.Sprintf("%s:%s:%s:%s", r.namespace, r.domain, r.label, suffix)
		equivalentIDs = append(equivalentIDs, equivalentID)
	}

	if len(equivalentIDs) > 0 {
		ti[document.EquivalentIDProperty] = equivalentIDs
	}

	if createRequestJCS != "" {
		id = fmt.Sprintf("%s:%s", id, createRequestJCS)
	}

	ti[document.IDProperty] = id

	return ti
}

// ResolveDocument fetches the latest DID Document of a DID. Two forms of string can be passed in the URI:
//
// 1. Standard DID format: did:METHOD:<did-suffix>
//
// 2. Long Form DID format:
// did:METHOD:<did-suffix>:Base64url(JCS({suffix-data-object, delta-object}))
//
// Standard resolution is performed if the DID is found to be registered on the anchoring system.
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
	doc, err := r.resolveRequestWithID(shortFormDID, uniquePortion, pv)
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
	// check aliases first (if configured)
	for _, ns := range r.aliases {
		if strings.HasPrefix(shortOrLongFormDID, ns+docutil.NamespaceDelimiter) {
			return ns, nil
		}
	}

	// check namespace
	if strings.HasPrefix(shortOrLongFormDID, r.namespace+docutil.NamespaceDelimiter) {
		return r.namespace, nil
	}

	return "", fmt.Errorf("did must start with configured namespace[%s] or aliases%v", r.namespace, r.aliases)
}

func (r *DocumentHandler) resolveRequestWithID(shortFormDid, uniquePortion string, pv protocol.Version) (*document.ResolutionResult, error) {
	internalResult, err := r.processor.Resolve(uniquePortion)
	if err != nil {
		logger.Debugf("Failed to resolve uniquePortion[%s]: %s", uniquePortion, err.Error())

		return nil, err
	}

	ti := make(protocol.TransformationInfo)
	ti[document.IDProperty] = shortFormDid
	ti[document.PublishedProperty] = true

	canonicalRef := ""
	if internalResult.CanonicalReference != "" {
		canonicalRef = docutil.NamespaceDelimiter + internalResult.CanonicalReference
	}

	canonicalID := r.namespace + canonicalRef + docutil.NamespaceDelimiter + uniquePortion

	// we should always set canonical id if document has been published
	ti[document.CanonicalIDProperty] = canonicalID

	equivalentIDs := []string{canonicalID}
	if len(internalResult.EquivalentReferences) > 0 {
		for _, eqRef := range internalResult.EquivalentReferences {
			equivalentID := r.namespace + docutil.NamespaceDelimiter + eqRef + docutil.NamespaceDelimiter + uniquePortion
			equivalentIDs = append(equivalentIDs, equivalentID)
		}
	}

	// equivalent ids should always include canonical id (if specified)
	ti[document.EquivalentIDProperty] = equivalentIDs

	return pv.DocumentTransformer().TransformDocument(internalResult, ti)
}

func (r *DocumentHandler) resolveRequestWithInitialState(uniqueSuffix, longFormDID string, initialBytes []byte, pv protocol.Version) (*document.ResolutionResult, error) {
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

	createRequestJCS := longFormDID[strings.LastIndex(longFormDID, docutil.NamespaceDelimiter)+1:]

	ti := r.getTransformationInfoForUnpublished(uniqueSuffix, createRequestJCS)

	externalResult, err := pv.DocumentTransformer().TransformDocument(rm, ti)
	if err != nil {
		return nil, fmt.Errorf("failed to transform create with initial state to external document: %s", err.Error())
	}

	return externalResult, nil
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
	if op.Type == operation.TypeCreate {
		return r.validateCreateDocument(op, pv)
	}

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

	lastDelimiter := strings.LastIndex(idOrDocument, docutil.NamespaceDelimiter)

	adjustedPos := lastDelimiter + 1
	if adjustedPos >= len(idOrDocument) {
		return "", errors.New("did suffix is empty")
	}

	return idOrDocument[adjustedPos:], nil
}
