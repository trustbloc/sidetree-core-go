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

// NewRemoveServicesValidator creates new validator.
func NewRemoveServicesValidator() *RemoveServicesValidator {
	return &RemoveServicesValidator{}
}

// RemoveServicesValidator implements validator for "remove-service-endpoints" patch.
type RemoveServicesValidator struct {
}

// Validate validates patch.
func (v *RemoveServicesValidator) Validate(p patch.Patch) error {
	value, err := p.GetValue()
	if err != nil {
		return err
	}

	genericArr, err := getRequiredArray(value)
	if err != nil {
		return fmt.Errorf("invalid remove services value: %s", err.Error())
	}

	return validateIds(document.StringArray(genericArr))
}
