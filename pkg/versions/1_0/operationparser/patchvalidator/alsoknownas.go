/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package patchvalidator

import (
	"fmt"
	"net/url"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

// NewAlsoKnownAsValidator creates new validator.
func NewAlsoKnownAsValidator() *AlsoKnownAsValidator {
	return &AlsoKnownAsValidator{}
}

// AlsoKnownAsValidator implements validator for custom "-add-also-known-as" and "-remove-also-known-as" patches.
// Both patches take have as value URIs so the validation for both add and remove are the same.
type AlsoKnownAsValidator struct {
}

// Validate validates patch.
func (v *AlsoKnownAsValidator) Validate(p patch.Patch) error {
	action, err := p.GetAction()
	if err != nil {
		return err
	}

	value, err := p.GetValue()
	if err != nil {
		return fmt.Errorf("%s", err)
	}

	_, err = getRequiredArray(value)
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}

	uris := document.StringArray(value)

	if err := validate(uris); err != nil {
		return fmt.Errorf("%s: validate URIs: %w", action, err)
	}

	return nil
}

// validateURIs validates URIs.
func validate(uris []string) error {
	ids := make(map[string]bool)
	for _, uri := range uris {
		u, err := url.Parse(uri)
		if err != nil {
			return fmt.Errorf("failed to parse URI: %w", err)
		}

		if _, ok := ids[u.String()]; ok {
			return fmt.Errorf("duplicate uri: %s", u.String())
		}

		ids[u.String()] = true
	}

	return nil
}
