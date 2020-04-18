/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didvalidator

import (
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
)

const (
	didUniqueSuffix      = "didUniqueSuffix"
	didContext           = "https://w3id.org/did/v1"
	didResolutionContext = "https://www.w3.org/ns/did-resolution/v1"
)

// Validator is responsible for validating did operations and sidetree rules
type Validator struct {
	store OperationStoreClient
}

// OperationStoreClient defines interface for retrieving all operations related to document
type OperationStoreClient interface {

	// Get retrieves all operations related to document
	Get(uniqueSuffix string) ([]*batch.Operation, error)
}

// New creates a new did validator
func New(store OperationStoreClient) *Validator {
	return &Validator{
		store: store,
	}
}

// IsValidPayload verifies that the given payload is a valid Sidetree specific payload
// that can be accepted by the Sidetree update operations
func (v *Validator) IsValidPayload(payload []byte) error {
	doc, err := document.FromBytes(payload)
	if err != nil {
		return err
	}

	didUniqueSuffix := doc.GetStringValue(didUniqueSuffix)
	if didUniqueSuffix == "" {
		return errors.New("missing did unique suffix")
	}

	// did document has to exist in the store for all operations except for create
	docs, err := v.store.Get(didUniqueSuffix)
	if err != nil {
		return err
	}

	if len(docs) == 0 {
		return errors.New("missing did document operations")
	}

	return nil
}

// IsValidOriginalDocument verifies that the given payload is a valid Sidetree specific did document that can be accepted by the Sidetree create operation.
func (v *Validator) IsValidOriginalDocument(payload []byte) error {
	didDoc, err := document.DidDocumentFromBytes(payload)
	if err != nil {
		return err
	}

	// Sidetree rule: The document must NOT have the id property
	if didDoc.ID() != "" {
		return errors.New("document must NOT have the id property")
	}

	// Sidetree rule: validate public keys
	if err := document.ValidatePublicKeys(didDoc.PublicKeys()); err != nil {
		return err
	}

	// Sidetree rule: add service validation

	// Sidetree rule: must not have context
	ctx := didDoc.Context()
	if len(ctx) != 0 {
		return errors.New("document must NOT have context")
	}

	return nil
}

// TransformDocument takes internal representation of document and transforms it to required representation
func (v *Validator) TransformDocument(doc document.Document) (*document.ResolutionResult, error) {
	internal := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())

	// start with empty document
	external := document.DidDocumentFromJSONLDObject(make(document.DIDDocument))

	// add context and id
	external[document.ContextProperty] = []interface{}{didContext}
	external[document.IDProperty] = internal.ID()

	result := &document.ResolutionResult{
		Context:        didResolutionContext,
		Document:       external.JSONLdObject(),
		MethodMetadata: document.MethodMetadata{},
	}

	// add keys
	processKeys(internal, result)

	// add services
	processServices(internal, result)

	return result, nil
}

// processServices will process services and add them to external document
func processServices(internal document.DIDDocument, resolutionResult *document.ResolutionResult) {
	if len(internal.Services()) == 0 {
		return
	}

	// add did to service id
	for _, sv := range internal.Services() {
		sv[document.IDProperty] = internal.ID() + "#" + sv.ID()
	}

	resolutionResult.Document[document.ServiceProperty] = internal.Services()
}

// processKeys will process keys according to Sidetree rules bellow and add them to external document
// -- general: the key is to be included in the publicKeys section of the resolved DID Document.
// -- auth: the key is to be included in the authentication section of the resolved DID Document as follows:
// If the general usage value IS NOT present in the usage array,
// the key descriptor object will be included directly in the authentication section of the resolved DID Document.
// If the general usage value IS present in the usage array,
// the key descriptor object will be directly included in the publicKeys section of the resolved DID Document,
// and included by reference in the authentication section.
// -- assertion: the key MUST be included in the assertionMethod section of the resolved DID Document
// (same rules as for auth)
// -- ops: the key is allowed to generate DID operations for the DID and will be included in method metadata
func processKeys(internal document.DIDDocument, resolutionResult *document.ResolutionResult) { //nolint: gocyclo
	var authentication []interface{}
	var assertionMethod []interface{}

	var publicKeys []document.PublicKey
	var operationPublicKeys []document.PublicKey

	// add controller to public key
	for _, pk := range internal.PublicKeys() {
		pk[document.ControllerProperty] = internal[document.IDProperty]
		// construct relative DID URL for inclusion in authentication and assertion method
		relativeID := "#" + pk.ID()
		pk[document.IDProperty] = internal.ID() + relativeID

		usages := pk.Usage()
		// remove usage property from external document
		delete(pk, document.UsageProperty)

		if document.IsOperationsKey(usages) {
			operationPublicKeys = append(operationPublicKeys, pk)
		}

		if document.IsGeneralKey(usages) {
			publicKeys = append(publicKeys, pk)

			// add into authentication by reference if the key has both auth and general usage
			if document.IsAuthenticationKey(usages) {
				authentication = append(authentication, relativeID)
			}
			// add into assertionMethod by reference if the key has both assertion and general usage
			if document.IsAssertionKey(usages) {
				assertionMethod = append(assertionMethod, relativeID)
			}
		} else if document.IsAuthenticationKey(usages) {
			authentication = append(authentication, pk)
		} else if document.IsAssertionKey(usages) {
			assertionMethod = append(assertionMethod, pk)
		}
	}

	if len(publicKeys) > 0 {
		resolutionResult.Document[document.PublicKeyProperty] = publicKeys
	}

	if len(authentication) > 0 {
		resolutionResult.Document[document.AuthenticationProperty] = authentication
	}

	if len(assertionMethod) > 0 {
		resolutionResult.Document[document.AssertionMethodProperty] = assertionMethod
	}

	resolutionResult.MethodMetadata.OperationPublicKeys = operationPublicKeys
}
