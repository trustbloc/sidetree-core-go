/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package patch

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

// Action defines action of document patch
type Action string

const (
	// Replace captures enum value "replace"
	Replace Action = "replace"

	// JSONPatch captures enum value "json-patch"
	JSONPatch Action = "ietf-json-patch"
)

// Key defines key that will be used to get document patch information
type Key string

const (

	// DocumentKey captures  "document" key
	DocumentKey Key = "document"

	// PatchesKey captures "patches" key
	PatchesKey Key = "patches"

	// ActionKey captures "action" key
	ActionKey Key = "action"
)

// Patch defines generic patch structure
type Patch map[Key]interface{}

// NewReplacePatch creates new replace patch
func NewReplacePatch(document string) Patch {
	patch := make(Patch)
	patch[ActionKey] = Replace
	patch[DocumentKey] = document

	return patch
}

// NewJSONPatch creates new generic update patch (will be used for generic updates)
func NewJSONPatch(patches string) Patch {
	patch := make(Patch)
	patch[ActionKey] = JSONPatch
	patch[PatchesKey] = patches

	return patch
}

// GetStringValue returns string value for specified key or "" if not found or wrong type
func (p Patch) GetStringValue(key Key) string {
	return stringEntry(p[key])
}

// GetValue returns value for specified key or nil if not found
func (p Patch) GetValue(key Key) interface{} {
	return p[key]
}

// GetAction returns string value for specified key or "" if not found or wrong type
func (p Patch) GetAction() Action {
	entry := p[ActionKey]
	actionStr, ok := entry.(string)
	if ok {
		return Action(actionStr)
	}

	return p[ActionKey].(Action)
}

// Bytes returns byte representation of patch
func (p Patch) Bytes() ([]byte, error) {
	return docutil.MarshalCanonical(p)
}

// Validate validates patch
func (p Patch) Validate() error {
	entry := p.GetValue(ActionKey)
	if entry == nil {
		return errors.New("patch is missing action property")
	}

	actionStr, ok := entry.(string)
	if !ok {
		return errors.New("action is not string value")
	}

	// action is valid string; now validate other keys
	action := Action(actionStr)
	switch action {
	case Replace:
		if p.GetValue(DocumentKey) == nil {
			return fmt.Errorf("%s patch is missing %s", action, DocumentKey)
		}
	case JSONPatch:
		if p.GetValue(PatchesKey) == nil {
			return fmt.Errorf("%s patch is missing %s", action, PatchesKey)
		}
	default:
		return fmt.Errorf("action '%s' is not supported", action)
	}

	return nil
}

// JSONLdObject returns map that represents JSON LD Object
func (p Patch) JSONLdObject() map[Key]interface{} {
	return p
}

// FromBytes parses provided data into document patch
func FromBytes(data []byte) (Patch, error) {
	patch := make(Patch)
	err := json.Unmarshal(data, &patch)
	if err != nil {
		return nil, err
	}

	if err := patch.Validate(); err != nil {
		return nil, err
	}

	return patch, nil
}

func stringEntry(entry interface{}) string {
	if entry == nil {
		return ""
	}
	id, ok := entry.(string)
	if !ok {
		return ""
	}
	return id
}
