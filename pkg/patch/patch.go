/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package patch

import (
	"encoding/json"
	"errors"
	"fmt"

	jsonpatch "github.com/evanphx/json-patch"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

// Action defines action of document patch
type Action string

const (
	// Replace captures enum value "replace"
	Replace Action = "replace"

	// AddPublicKeys captures enum value "add-public-keys"
	AddPublicKeys Action = "add-public-keys"

	// RemovePublicKeys captures enum value "remove-public-keys"
	RemovePublicKeys Action = "remove-public-keys"

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

	// PublicKeys captures "publicKeys" key
	PublicKeys Key = "publicKeys"

	// ActionKey captures "action" key
	ActionKey Key = "action"
)

// Patch defines generic patch structure
type Patch map[Key]interface{}

// NewReplacePatch creates new replace patch
func NewReplacePatch(doc string) (Patch, error) {
	parsed, err := document.FromBytes([]byte(doc))
	if err != nil {
		return nil, err
	}

	if err := validateDocument(parsed); err != nil {
		return nil, err
	}

	patch := make(Patch)
	patch[ActionKey] = Replace
	patch[DocumentKey] = doc

	return patch, nil
}

// NewJSONPatch creates new generic update patch (will be used for generic updates)
func NewJSONPatch(patches string) (Patch, error) {
	if err := validatePatches([]byte(patches)); err != nil {
		return nil, err
	}

	patch := make(Patch)
	patch[ActionKey] = JSONPatch
	patch[PatchesKey] = patches

	return patch, nil
}

// NewAddPublicKeysPatch creates new patch for adding public keys
func NewAddPublicKeysPatch(publicKeys string) (Patch, error) {
	patch := make(Patch)
	patch[ActionKey] = AddPublicKeys
	patch[PublicKeys] = publicKeys

	return patch, nil
}

// NewRemovePublicKeysPatch creates new patch for removing public keys
func NewRemovePublicKeysPatch(publicKeyIds string) (Patch, error) {
	patch := make(Patch)
	patch[ActionKey] = RemovePublicKeys
	patch[PublicKeys] = publicKeyIds

	return patch, nil
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
		doc, err := p.getRequiredMap(DocumentKey)
		if err != nil {
			return err
		}
		return validateDocument(document.FromJSONLDObject(doc))
	case JSONPatch:
		patches, err := p.getRequiredArray(PatchesKey)
		if err != nil {
			return err
		}
		patchesBytes, err := json.Marshal(patches)
		if err != nil {
			return err
		}
		return validatePatches(patchesBytes)
	case AddPublicKeys, RemovePublicKeys:
		_, err := p.getRequiredArray(PublicKeys)
		return err
	}

	return fmt.Errorf("action '%s' is not supported", action)
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

func validateDocument(doc document.Document) error {
	if doc.ID() != "" {
		return errors.New("document must NOT have the id property")
	}

	return nil
}

func validatePatches(patches []byte) error {
	_, err := jsonpatch.DecodePatch(patches)
	if err != nil {
		return err
	}

	// TODO: We should probably not allow updating keys and services using this patch #175

	return nil
}

func (p Patch) getRequiredMap(key Key) (map[string]interface{}, error) {
	entry := p.GetValue(key)
	if entry == nil {
		return nil, fmt.Errorf("%s patch is missing %s", p.GetAction(), key)
	}

	return entry.(map[string]interface{}), nil
}

func (p Patch) getRequiredArray(key Key) ([]interface{}, error) {
	entry := p.GetValue(key)
	if entry == nil {
		return nil, fmt.Errorf("%s patch is missing %s", p.GetAction(), key)
	}

	return entry.([]interface{}), nil
}
