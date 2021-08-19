/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didvalidator

import (
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
)

const didSuffix = "didSuffix"

// Validator is responsible for validating did operations and sidetree rules.
type Validator struct {
}

// New creates a new did validator.
func New() *Validator {
	return &Validator{}
}

// IsValidPayload verifies that the given payload is a valid Sidetree specific payload
// that can be accepted by the Sidetree update operations.
func (v *Validator) IsValidPayload(payload []byte) error {
	doc, err := document.FromBytes(payload)
	if err != nil {
		return err
	}

	didSuffix := doc.GetStringValue(didSuffix)
	if didSuffix == "" {
		return errors.New("missing did unique suffix")
	}

	// checking for previous operation existence has been pushed to handler
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

	// Sidetree rule: must not have context
	ctx := didDoc.Context()
	if len(ctx) != 0 {
		return errors.New("document must NOT have context")
	}

	return nil
}
