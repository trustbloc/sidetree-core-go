/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package docvalidator

import (
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
)

const didSuffix = "didSuffix"

// Validator is responsible for validating document operations and Sidetree rules.
type Validator struct {
}

// New creates a new document validator.
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

	uniqueSuffix := doc.GetStringValue(didSuffix)
	if uniqueSuffix == "" {
		return errors.New("missing unique suffix")
	}

	// checking for previous operation existence has been pushed to handler

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

	return nil
}
