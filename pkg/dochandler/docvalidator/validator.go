/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package docvalidator

import (
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
)

const didSuffix = "did_suffix"

// Validator is responsible for validating document operations and sidetree rules
type Validator struct {
	store OperationStoreClient
}

// OperationStoreClient defines interface for retrieving all operations related to document
type OperationStoreClient interface {

	// Get retrieves all operations related to document
	Get(uniqueSuffix string) ([]*batch.AnchoredOperation, error)
}

// New creates a new document validator
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

	uniqueSuffix := doc.GetStringValue(didSuffix)
	if uniqueSuffix == "" {
		return errors.New("missing unique suffix")
	}

	// document has to exist in the store for all operations except for create
	docs, err := v.store.Get(uniqueSuffix)
	if err != nil {
		return err
	}

	if len(docs) == 0 {
		return errors.New("missing document operations")
	}

	return nil
}

// IsValidOriginalDocument verifies that the given payload is a valid Sidetree specific document that can be accepted by the Sidetree create operation.
func (v *Validator) IsValidOriginalDocument(payload []byte) error {
	doc, err := document.FromBytes(payload)
	if err != nil {
		return err
	}

	// The document must NOT have the id property
	if doc.ID() != "" {
		return errors.New("document must NOT have the id property")
	}

	// Sidetree rule: validate public keys
	if err := document.ValidatePublicKeys(doc.PublicKeys()); err != nil {
		return err
	}

	return nil
}

// TransformDocument takes internal representation of document and transforms it to required representation
func (v *Validator) TransformDocument(internal document.Document) (*document.ResolutionResult, error) {
	resolutionResult := &document.ResolutionResult{
		Document:       internal,
		MethodMetadata: document.MethodMetadata{},
	}

	processKeys(internal)

	return resolutionResult, nil
}

// generic documents will most likely not contain keys
func processKeys(internal document.Document) {
	var pubKeysKeys []document.PublicKey

	for _, pk := range internal.PublicKeys() {
		relativeID := "#" + pk.ID()

		externalPK := make(document.PublicKey)
		externalPK[document.IDProperty] = internal.ID() + relativeID
		externalPK[document.TypeProperty] = pk.Type()
		externalPK[document.ControllerProperty] = internal[document.IDProperty]
		externalPK[document.PublicKeyJwkProperty] = pk.JWK()

		pubKeysKeys = append(pubKeysKeys, externalPK)
	}

	if len(pubKeysKeys) > 0 {
		internal[document.PublicKeyProperty] = pubKeysKeys
	} else {
		delete(internal, document.PublicKeyProperty)
	}
}
