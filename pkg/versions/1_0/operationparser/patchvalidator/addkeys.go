/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package patchvalidator

import (
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

// NewAddPublicKeysValidator creates new validator.
func NewAddPublicKeysValidator() *AddPublicKeysValidator {
	return &AddPublicKeysValidator{}
}

// AddPublicKeysValidator implements validator for "add-public-keys" patch.
type AddPublicKeysValidator struct {
}

// Validate validates patch.
func (v *AddPublicKeysValidator) Validate(p patch.Patch) error {
	value, err := p.GetValue()
	if err != nil {
		return err
	}

	_, err = getRequiredArray(value)
	if err != nil {
		return fmt.Errorf("invalid add public keys value: %s", err.Error())
	}

	publicKeys := document.ParsePublicKeys(value)

	return validatePublicKeys(publicKeys)
}
