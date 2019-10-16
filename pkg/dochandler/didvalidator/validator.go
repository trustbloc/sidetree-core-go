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
	didUniqueSuffix = "didUniqueSuffix"
	didContext      = "https://w3id.org/did/v1"
)

// Validator is responsible for validating did operations and sidetree rules
type Validator struct {
	store OperationStoreClient
}

// OperationStoreClient defines interface for retrieving all operations related to document
type OperationStoreClient interface {

	// Get retrieves all operations related to document
	Get(uniqueSuffix string) ([]batch.Operation, error)
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

	// Sidetree rule: The document must contain at least 1 entry in the publicKey array property
	if err := validatePublicKeys(didDoc); err != nil {
		return err
	}

	// Sidetree rule: add service validation

	// generic did document validation - must have context
	if didDoc.Context() != didContext {
		return errors.New("context is invalid or absent")
	}

	return nil
}

func validatePublicKeys(didDoc document.DIDDocument) error {

	// The document must contain at least 1 entry in the publicKey array property
	publicKeyArray := didDoc.PublicKeys()
	if len(publicKeyArray) == 0 {
		return errors.New("document must contain at least one public key")
	}

	return nil
}
