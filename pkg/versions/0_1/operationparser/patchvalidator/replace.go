/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package patchvalidator

import (
	"errors"
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

// NewReplaceValidator creates new validator.
func NewReplaceValidator() *ReplaceValidator {
	return &ReplaceValidator{}
}

// ReplaceValidator implements validator for "replace" patch.
type ReplaceValidator struct {
}

// Validate validates patch.
func (v *ReplaceValidator) Validate(p patch.Patch) error {
	value, err := p.GetValue()
	if err != nil {
		return err
	}

	entryMap, err := getRequiredMap(value)
	if err != nil {
		return err
	}

	doc := document.ReplaceDocumentFromJSONLDObject(entryMap)

	allowedKeys := []string{document.ReplaceServiceProperty, document.ReplacePublicKeyProperty}

	for key := range doc {
		if !contains(allowedKeys, key) {
			return fmt.Errorf("key '%s' is not allowed in replace document", key)
		}
	}

	if err := validatePublicKeys(doc.PublicKeys()); err != nil {
		return fmt.Errorf("failed to validate public keys for replace document: %s", err.Error())
	}

	if err := validateServices(doc.Services()); err != nil {
		return fmt.Errorf("failed to validate services for replace document: %s", err.Error())
	}

	return nil
}

func getRequiredMap(entry interface{}) (map[string]interface{}, error) {
	required, ok := entry.(map[string]interface{})
	if !ok {
		return nil, errors.New("unexpected interface for document")
	}

	return required, nil
}
