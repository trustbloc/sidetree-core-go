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
	"encoding/base64"
	"errors"
	"strings"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"

	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

// DocumentHandler implements document handler
type DocumentHandler struct {
	protocol  protocol.Client
	processor OperationProcessor
	writer    BatchWriter
	validator DocumentValidator
	namespace string
}

// OperationProcessor is an interface which resolves the document based on the ID
type OperationProcessor interface {
	Resolve(uniqueSuffix string) (document.Document, error)
}

// BatchWriter is an interface to add an operation to the batch
type BatchWriter interface {
	Add(operation []byte) error
}

// DocumentValidator is an interface for validating document operations
type DocumentValidator interface {
	IsValidOriginalDocument(payload []byte) error
	IsValidPayload(payload []byte) error
}

// New creates a new requestHandler with the context
func New(namespace string, protocol protocol.Client, validator DocumentValidator, writer BatchWriter, processor OperationProcessor) *DocumentHandler {

	return &DocumentHandler{
		protocol:  protocol,
		processor: processor,
		writer:    writer,
		validator: validator,
		namespace: namespace,
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
func (r *DocumentHandler) ProcessOperation(operation batch.Operation) (document.Document, error) {

	// perform validation for operation request
	if err := r.validateOperation(operation); err != nil {
		log.Warnf("Failed to validate operation: %s", err.Error())
		return nil, err
	}

	// validated operation will be added to the batch
	if err := r.addToBatch(operation); err != nil {
		log.Errorf("Failed to add operation to batch: %s", err.Error())
		return nil, err
	}

	// create operation will also return document
	if operation.Type == batch.OperationTypeCreate {
		return r.getDoc(operation.EncodedPayload)
	}

	return nil, nil
}

// ResolveDocument returns document based on passed in ID or Document
func (r *DocumentHandler) ResolveDocument(idOrDocument string) (document.Document, error) {

	if !strings.HasPrefix(idOrDocument, r.namespace) {
		return nil, errors.New("must start with configured namespace")
	}

	// Figure out if the given parameter contains a ID or Document
	uniquePortion, err := getUniquePortion(r.namespace, idOrDocument)
	if err != nil {
		return nil, err
	}

	parameterIsID := docutil.IsSupportedMultihash(uniquePortion)
	if parameterIsID {
		return r.resolveRequestWithID(uniquePortion)
	}

	return r.resolveRequestWithDocument(uniquePortion)
}

func (r *DocumentHandler) resolveRequestWithID(uniquePortion string) (document.Document, error) {
	doc, err := r.processor.Resolve(uniquePortion)
	if err != nil {
		log.Errorf("Failed to resolve uniquePortion[%s]: %s", uniquePortion, err.Error())
		return nil, err
	}
	return applyID(doc, r.namespace+uniquePortion), nil

}

func (r *DocumentHandler) resolveRequestWithDocument(encodedDocument string) (document.Document, error) {

	docBytes, err := docutil.DecodeString(encodedDocument)
	if err != nil {
		return nil, err
	}

	// verify size of each operation does not exceed the maximum allowed limit
	if len(docBytes) > int(r.protocol.Current().MaxOperationByteSize) {
		return nil, errors.New("operation byte size exceeds protocol max operation byte size")
	}

	// Verify that the document passes both Sidetree and document validation
	if err = r.validator.IsValidOriginalDocument(docBytes); err != nil {
		return nil, err
	}

	return r.getDoc(encodedDocument)
}

// helper function to insert id into document
func applyID(doc document.Document, id string) document.Document {
	if doc == nil {
		return nil
	}

	// apply id to document
	doc["id"] = id
	return doc
}

// helper namespace for adding operations to the batch
func (r *DocumentHandler) addToBatch(operation batch.Operation) error {

	opBytes, err := docutil.MarshalCanonical(operation)
	if err != nil {
		return err
	}
	return r.writer.Add(opBytes)
}

func (r *DocumentHandler) getDoc(encodedPayload string) (document.Document, error) {

	id, err := docutil.CalculateID(r.namespace, encodedPayload, r.protocol.Current().HashAlgorithmInMultiHashCode)
	if err != nil {
		return nil, err
	}

	decodedBytes, err := docutil.DecodeString(encodedPayload)
	if err != nil {
		return nil, err
	}

	doc, err := document.FromBytes(decodedBytes)
	if err != nil {
		return nil, err
	}

	return applyID(doc, id), nil
}

// validateOperation validates the operation
func (r *DocumentHandler) validateOperation(operation batch.Operation) error {

	// decode encoded payload
	payload, err := base64.StdEncoding.DecodeString(operation.EncodedPayload)
	if err != nil {
		return err
	}

	// check maximum operation size against protocol
	if len(payload) > int(r.protocol.Current().MaxOperationByteSize) {
		return errors.New("operation byte size exceeds protocol max operation byte size")
	}

	if operation.Type == batch.OperationTypeCreate {
		return r.validator.IsValidOriginalDocument(payload)
	}

	return r.validator.IsValidPayload(payload)

}

// getUniquePortion fetches unique portion of ID which is string after namespace
func getUniquePortion(namespace, idOrDocument string) (string, error) {
	pos := strings.Index(idOrDocument, namespace)
	if pos == -1 {
		return "", errors.New("ID must start with configured namespace")
	}

	adjustedPos := pos + len(namespace)
	if adjustedPos >= len(idOrDocument) {
		return "", errors.New("unique portion is empty")
	}

	return idOrDocument[adjustedPos:], nil
}
