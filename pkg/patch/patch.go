/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package patch

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

const jsonPatchAddTemplate = `{ "op": "add", "path": "/%s", "value": %s }`

// Action defines action of document patch.
type Action string

const (

	// Replace captures enum value "replace".
	Replace Action = "replace"

	// AddPublicKeys captures enum value "add-public-keys".
	AddPublicKeys Action = "add-public-keys"

	// RemovePublicKeys captures enum value "remove-public-keys".
	RemovePublicKeys Action = "remove-public-keys"

	// AddServiceEndpoints captures "add-services".
	AddServiceEndpoints Action = "add-services"

	// RemoveServiceEndpoints captures "remove-services".
	RemoveServiceEndpoints Action = "remove-services"

	// JSONPatch captures enum value "json-patch".
	JSONPatch Action = "ietf-json-patch"

	// AddAlsoKnownAs captures "add-also-known-as".
	AddAlsoKnownAs Action = "add-also-known-as"

	// RemoveAlsoKnownAs captures "remove-also-known-as".
	RemoveAlsoKnownAs Action = "remove-also-known-as"
)

// Key defines key that will be used to get document patch information.
type Key string

const (

	// DocumentKey captures  "document" key.
	DocumentKey Key = "document"

	// PatchesKey captures "patches" key.
	PatchesKey Key = "patches"

	// PublicKeys captures "publicKeys" key.
	PublicKeys Key = "publicKeys"

	// ServicesKey captures "services" key.
	ServicesKey Key = "services"

	// IdsKey captures "ids" key.
	IdsKey Key = "ids"

	// ActionKey captures "action" key.
	ActionKey Key = "action"

	// UrisKey captures "uris" key.
	UrisKey Key = "uris"
)

var actionConfig = map[Action]Key{
	AddPublicKeys:          PublicKeys,
	RemovePublicKeys:       IdsKey,
	AddServiceEndpoints:    ServicesKey,
	RemoveServiceEndpoints: IdsKey,
	JSONPatch:              PatchesKey,
	Replace:                DocumentKey,
	AddAlsoKnownAs:         UrisKey,
	RemoveAlsoKnownAs:      UrisKey,
}

// Patch defines generic patch structure.
type Patch map[Key]interface{}

// PatchesFromDocument creates patches from opaque document.
func PatchesFromDocument(doc string) ([]Patch, error) {
	parsed, err := document.FromBytes([]byte(doc))
	if err != nil {
		return nil, err
	}

	if err := validateDocument(parsed); err != nil {
		return nil, err
	}

	var docPatches []Patch
	var jsonPatches []string

	for key, value := range parsed {
		jsonBytes, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}

		var docPatch Patch
		switch key {
		case document.PublicKeyProperty:
			docPatch, err = NewAddPublicKeysPatch(string(jsonBytes))
		case document.ServiceProperty:
			docPatch, err = NewAddServiceEndpointsPatch(string(jsonBytes))
		case document.AlsoKnownAs:
			docPatch, err = NewAddAlsoKnownAs(string(jsonBytes))
		default:
			jsonPatches = append(jsonPatches, fmt.Sprintf(jsonPatchAddTemplate, key, string(jsonBytes)))
		}

		if err != nil {
			return nil, err
		}

		if docPatch != nil {
			docPatches = append(docPatches, docPatch)
		}
	}

	if len(jsonPatches) > 0 {
		combinedJSONPatch, err := NewJSONPatch(fmt.Sprintf("[%s]", strings.Join(jsonPatches, ",")))
		if err != nil {
			return nil, err
		}

		docPatches = append(docPatches, combinedJSONPatch)
	}

	return docPatches, nil
}

// NewReplacePatch creates new replace patch.
func NewReplacePatch(doc string) (Patch, error) {
	parsed, err := document.ReplaceDocumentFromBytes([]byte(doc))
	if err != nil {
		return nil, err
	}

	if err := validateReplaceDocument(parsed); err != nil {
		return nil, err
	}

	patch := make(Patch)
	patch[ActionKey] = Replace
	patch[DocumentKey] = parsed.JSONLdObject()

	return patch, nil
}

// NewJSONPatch creates new generic update patch (will be used for generic updates).
func NewJSONPatch(patches string) (Patch, error) {
	var generic []interface{}
	err := json.Unmarshal([]byte(patches), &generic)
	if err != nil {
		return nil, err
	}

	patch := make(Patch)
	patch[ActionKey] = JSONPatch
	patch[PatchesKey] = generic

	return patch, nil
}

// NewAddPublicKeysPatch creates new patch for adding public keys.
func NewAddPublicKeysPatch(publicKeys string) (Patch, error) {
	pubKeys, err := getPublicKeys(publicKeys)
	if err != nil {
		return nil, err
	}

	patch := make(Patch)
	patch[ActionKey] = AddPublicKeys
	patch[PublicKeys] = pubKeys

	return patch, nil
}

// NewRemovePublicKeysPatch creates new patch for removing public keys.
func NewRemovePublicKeysPatch(publicKeyIds string) (Patch, error) {
	ids, err := getStringArray(publicKeyIds)
	if err != nil {
		return nil, fmt.Errorf("public key ids not string array: %s", err.Error())
	}

	if len(ids) == 0 {
		return nil, errors.New("missing public key ids")
	}

	patch := make(Patch)
	patch[ActionKey] = RemovePublicKeys
	patch[IdsKey] = getGenericArray(ids)

	return patch, nil
}

// NewAddServiceEndpointsPatch creates new patch for adding service endpoints.
func NewAddServiceEndpointsPatch(serviceEndpoints string) (Patch, error) {
	services, err := getServices(serviceEndpoints)
	if err != nil {
		return nil, err
	}

	patch := make(Patch)
	patch[ActionKey] = AddServiceEndpoints
	patch[ServicesKey] = services

	return patch, nil
}

// NewRemoveServiceEndpointsPatch creates new patch for removing service endpoints.
func NewRemoveServiceEndpointsPatch(serviceEndpointIds string) (Patch, error) {
	ids, err := getStringArray(serviceEndpointIds)
	if err != nil {
		return nil, fmt.Errorf("service ids not string array: %s", err.Error())
	}

	if len(ids) == 0 {
		return nil, errors.New("missing service ids")
	}

	patch := make(Patch)
	patch[ActionKey] = RemoveServiceEndpoints
	patch[IdsKey] = getGenericArray(ids)

	return patch, nil
}

// NewAddAlsoKnownAs creates new patch for adding also-known-as property.
func NewAddAlsoKnownAs(uris string) (Patch, error) {
	urisToAdd, err := getStringArray(uris)
	if err != nil {
		return nil, fmt.Errorf("also known as uris is not string array: %s", err.Error())
	}

	if len(urisToAdd) == 0 {
		return nil, errors.New("missing also known as uris")
	}

	patch := make(Patch)
	patch[ActionKey] = AddAlsoKnownAs
	patch[UrisKey] = getGenericArray(urisToAdd)

	return patch, nil
}

// NewRemoveAlsoKnownAs creates new patch for removing also-known-as URI.
func NewRemoveAlsoKnownAs(uris string) (Patch, error) {
	urisToRemove, err := getStringArray(uris)
	if err != nil {
		return nil, fmt.Errorf("also known as uris is not string array: %s", err.Error())
	}

	if len(urisToRemove) == 0 {
		return nil, errors.New("missing also known as uris")
	}

	patch := make(Patch)
	patch[ActionKey] = RemoveAlsoKnownAs
	patch[UrisKey] = getGenericArray(urisToRemove)

	return patch, nil
}

// GetValue returns patch value.
func (p Patch) GetValue() (interface{}, error) {
	action, err := p.GetAction()
	if err != nil {
		return nil, err
	}

	valueKey, ok := actionConfig[action]
	if !ok {
		return nil, fmt.Errorf("action '%s' is not supported", action)
	}

	entry, ok := p[valueKey]
	if !ok {
		return nil, fmt.Errorf("%s patch is missing key: %s", action, valueKey)
	}

	return entry, nil
}

// GetAction returns string value for specified key or "" if not found or wrong type.
func (p Patch) GetAction() (Action, error) {
	entry, ok := p[ActionKey]
	if !ok {
		return "", fmt.Errorf("patch is missing %s key", ActionKey)
	}

	var action Action
	switch v := entry.(type) {
	case Action:
		action = v
	case string:
		action = Action(v)
	default:
		return "", fmt.Errorf("action type not supported: %s", v)
	}

	_, ok = actionConfig[action]
	if !ok {
		return "", fmt.Errorf("action '%s' is not supported", action)
	}

	return action, nil
}

// Bytes returns byte representation of patch.
func (p Patch) Bytes() ([]byte, error) {
	return docutil.MarshalCanonical(p)
}

// JSONLdObject returns map that represents JSON LD Object.
func (p Patch) JSONLdObject() map[Key]interface{} {
	return p
}

// FromBytes parses provided data into document patch.
func FromBytes(data []byte) (Patch, error) {
	patch := make(Patch)
	err := json.Unmarshal(data, &patch)
	if err != nil {
		return nil, err
	}

	_, err = patch.GetAction()
	if err != nil {
		return nil, err
	}

	_, err = patch.GetValue()
	if err != nil {
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

func validateReplaceDocument(doc document.ReplaceDocument) error {
	allowedKeys := []string{document.ReplaceServiceProperty, document.ReplacePublicKeyProperty}

	for key := range doc {
		if !contains(allowedKeys, key) {
			return fmt.Errorf("key '%s' is not allowed in replace document", key)
		}
	}

	return nil
}

func contains(keys []string, key string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}

	return false
}

func validateDocument(doc document.Document) error {
	if doc.ID() != "" {
		return errors.New("document must NOT have the id property")
	}

	return nil
}

func getPublicKeys(publicKeys string) (interface{}, error) {
	// create an empty did document with public keys
	pkDoc, err := document.DidDocumentFromBytes([]byte(fmt.Sprintf(`{%q:%s}`, document.PublicKeyProperty, publicKeys)))
	if err != nil {
		return nil, fmt.Errorf("public keys invalid: %s", err.Error())
	}

	return pkDoc[document.PublicKeyProperty], nil
}

func getServices(serviceEndpoints string) (interface{}, error) {
	// create an empty did document with service endpoints
	svcDocStr := fmt.Sprintf(`{%q:%s}`, document.ServiceProperty, serviceEndpoints)
	svcDoc, err := document.DidDocumentFromBytes([]byte(svcDocStr))
	if err != nil {
		return nil, fmt.Errorf("services invalid: %s", err.Error())
	}

	return svcDoc[document.ServiceProperty], nil
}

func getStringArray(arr string) ([]string, error) {
	var values []string
	err := json.Unmarshal([]byte(arr), &values)
	if err != nil {
		return nil, err
	}

	return values, nil
}

func getGenericArray(arr []string) []interface{} {
	var values []interface{}
	for _, v := range arr {
		values = append(values, v)
	}

	return values
}
