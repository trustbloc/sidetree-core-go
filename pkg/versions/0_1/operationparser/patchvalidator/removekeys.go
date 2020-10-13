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

// NewRemovePublicKeysValidator creates validator for "remove-public-keys" patch.
func NewRemovePublicKeysValidator() *RemovePublicKeysValidator {
	return &RemovePublicKeysValidator{}
}

// RemovePublicKeysValidator implements validator for "remove-public-keys" patch.
type RemovePublicKeysValidator struct {
}

// Validate validates patch.
func (v *RemovePublicKeysValidator) Validate(p patch.Patch) error {
	value, err := p.GetValue()
	if err != nil {
		return err
	}

	genericArr, err := getRequiredArray(value)
	if err != nil {
		return fmt.Errorf("invalid remove public keys value: %s", err.Error())
	}

	return validateIds(document.StringArray(genericArr))
}
