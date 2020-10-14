/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package patchvalidator

import (
	"encoding/json"
	"fmt"
	"strings"

	jsonpatch "github.com/evanphx/json-patch"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

// NewJSONValidator creates new validator.
func NewJSONValidator() *JSONValidator {
	return &JSONValidator{}
}

// JSONValidator implements validator for "ietf-json-patch" patch.
type JSONValidator struct {
}

// Validate validates patch.
func (v *JSONValidator) Validate(p patch.Patch) error {
	value, err := p.GetValue()
	if err != nil {
		return err
	}

	patches, err := getRequiredArray(value)
	if err != nil {
		return fmt.Errorf("invalid json patch value: %s", err.Error())
	}

	patchesBytes, err := json.Marshal(patches)
	if err != nil {
		return err
	}

	return validateJSONPatches(patchesBytes)
}

func validateJSONPatches(patches []byte) error {
	jsonPatches, err := jsonpatch.DecodePatch(patches)
	if err != nil {
		return fmt.Errorf("%s: %s", patch.JSONPatch, err.Error())
	}

	for _, p := range jsonPatches {
		pathMsg, ok := p["path"]
		if !ok {
			return fmt.Errorf("%s: path not found", patch.JSONPatch)
		}

		var path string
		if err := json.Unmarshal(*pathMsg, &path); err != nil {
			return fmt.Errorf("%s: invalid path", patch.JSONPatch)
		}

		if strings.HasPrefix(path, "/"+document.ServiceProperty) {
			return fmt.Errorf("%s: cannot modify services", patch.JSONPatch)
		}

		if strings.HasPrefix(path, "/"+document.PublicKeyProperty) {
			return fmt.Errorf("%s: cannot modify public keys", patch.JSONPatch)
		}
	}

	return nil
}
