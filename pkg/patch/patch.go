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

	jsonpatch "github.com/evanphx/json-patch"

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

	// AddServiceEndpoints captures "add-service-endpoints".
	AddServiceEndpoints Action = "add-service-endpoints"

	// RemoveServiceEndpoints captures "remove-service-endpoints".
	RemoveServiceEndpoints Action = "remove-service-endpoints"

	// JSONPatch captures enum value "json-patch".
	JSONPatch Action = "ietf-json-patch"
)

// Key defines key that will be used to get document patch information.
type Key string

const (

	// DocumentKey captures  "document" key.
	DocumentKey Key = "document"

	// PatchesKey captures "patches" key.
	PatchesKey Key = "patches"

	// PublicKeys captures "public_keys" key.
	PublicKeys Key = "public_keys"

	// ServiceEndpointsKey captures "service_endpoints" key.
	ServiceEndpointsKey Key = "service_endpoints"

	// ServiceEndpointIdsKey captures "ids" key.
	ServiceEndpointIdsKey Key = "ids"

	// ActionKey captures "action" key.
	ActionKey Key = "action"
)

// Patch defines generic patch structure.
type Patch map[Key]interface{}

// PatchesFromDocument creates patches from opaque document.
func PatchesFromDocument(doc string) ([]Patch, error) { //nolint:gocyclo
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
	if err := validateJSONPatches([]byte(patches)); err != nil {
		return nil, err
	}

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

	if err := validateIds(ids); err != nil {
		return nil, err
	}

	patch := make(Patch)
	patch[ActionKey] = RemovePublicKeys
	patch[PublicKeys] = getGenericArray(ids)

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
	patch[ServiceEndpointsKey] = services

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

	if err := validateIds(ids); err != nil {
		return nil, err
	}

	patch := make(Patch)
	patch[ActionKey] = RemoveServiceEndpoints
	patch[ServiceEndpointIdsKey] = getGenericArray(ids)

	return patch, nil
}

// GetValue returns value for specified key or nil if not found.
func (p Patch) GetValue(key Key) interface{} {
	return p[key]
}

// GetAction returns string value for specified key or "" if not found or wrong type.
func (p Patch) GetAction() Action {
	entry := p[ActionKey]
	actionStr, ok := entry.(string)
	if ok {
		return Action(actionStr)
	}

	return p[ActionKey].(Action)
}

// Bytes returns byte representation of patch.
func (p Patch) Bytes() ([]byte, error) {
	return docutil.MarshalCanonical(p)
}

// Validate validates patch.
func (p Patch) Validate() error {
	action, err := p.parseAction()
	if err != nil {
		return err
	}

	switch action {
	case Replace:
		return p.validateReplace()
	case JSONPatch:
		return p.validateJSON()
	case AddPublicKeys:
		return p.validateAddPublicKeys()
	case RemovePublicKeys:
		return p.validateRemovePublicKeys()
	case AddServiceEndpoints:
		return p.validateAddServiceEndpoints()
	case RemoveServiceEndpoints:
		return p.validateRemoveServiceEndpoints()
	}

	return fmt.Errorf("action '%s' is not supported", action)
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

func validateReplaceDocument(doc document.ReplaceDocument) error {
	allowedKeys := []string{document.ReplaceServiceProperty, document.ReplacePublicKeyProperty}

	for key := range doc {
		if !contains(allowedKeys, key) {
			return fmt.Errorf("key '%s' is not allowed in replace document", key)
		}
	}

	if err := document.ValidatePublicKeys(doc.PublicKeys()); err != nil {
		return fmt.Errorf("failed to validate public keys for replace document: %s", err.Error())
	}

	if err := document.ValidateServices(doc.Services()); err != nil {
		return fmt.Errorf("failed to validate services for replace document: %s", err.Error())
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

func validateJSONPatches(patches []byte) error {
	jsonPatches, err := jsonpatch.DecodePatch(patches)
	if err != nil {
		return fmt.Errorf("%s: %s", JSONPatch, err.Error())
	}

	for _, p := range jsonPatches {
		pathMsg, ok := p["path"]
		if !ok {
			return fmt.Errorf("%s: path not found", JSONPatch)
		}

		var path string
		if err := json.Unmarshal(*pathMsg, &path); err != nil {
			return fmt.Errorf("%s: invalid path", JSONPatch)
		}

		if strings.HasPrefix(path, "/"+document.ServiceProperty) {
			return fmt.Errorf("%s: cannot modify services", JSONPatch)
		}

		if strings.HasPrefix(path, "/"+document.PublicKeyProperty) {
			return fmt.Errorf("%s: cannot modify public keys", JSONPatch)
		}
	}

	return nil
}

func getPublicKeys(publicKeys string) (interface{}, error) {
	// create an empty did document with public keys
	pkDoc, err := document.DidDocumentFromBytes([]byte(fmt.Sprintf(`{"%s":%s}`, document.PublicKeyProperty, publicKeys)))
	if err != nil {
		return nil, fmt.Errorf("public keys invalid: %s", err.Error())
	}

	pubKeys := pkDoc.PublicKeys()
	err = document.ValidatePublicKeys(pubKeys)
	if err != nil {
		return nil, err
	}

	return pkDoc[document.PublicKeyProperty], nil
}

func getServices(serviceEndpoints string) (interface{}, error) {
	// create an empty did document with service endpoints
	svcDocStr := fmt.Sprintf(`{"%s":%s}`, document.ServiceProperty, serviceEndpoints)
	svcDoc, err := document.DidDocumentFromBytes([]byte(svcDocStr))
	if err != nil {
		return nil, fmt.Errorf("services invalid: %s", err.Error())
	}

	services := svcDoc.Services()
	err = document.ValidateServices(services)
	if err != nil {
		return nil, err
	}

	return svcDoc[document.ServiceProperty], nil
}

func (p *Patch) parseAction() (Action, error) {
	entry := p.GetValue(ActionKey)
	if entry == nil {
		return "", errors.New("patch is missing action property")
	}

	switch v := entry.(type) {
	case Action:
		return v, nil
	case string:
		return Action(v), nil
	default:
		return "", fmt.Errorf("action type not supported: %s", v)
	}
}

func (p Patch) getRequiredArray(key Key) ([]interface{}, error) {
	entry := p.GetValue(key)
	if entry == nil {
		return nil, fmt.Errorf("%s patch is missing %s", p.GetAction(), key)
	}

	arr, ok := entry.([]interface{})
	if !ok {
		return nil, errors.New("expected array of interfaces")
	}

	if len(arr) == 0 {
		return nil, errors.New("required array is empty")
	}

	return arr, nil
}

func (p Patch) validateReplace() error {
	doc, err := p.getRequiredMap(DocumentKey)
	if err != nil {
		return err
	}

	return validateReplaceDocument(document.ReplaceDocumentFromJSONLDObject(doc))
}

func (p Patch) validateJSON() error {
	patches, err := p.getRequiredArray(PatchesKey)
	if err != nil {
		return err
	}

	patchesBytes, err := json.Marshal(patches)
	if err != nil {
		return err
	}

	return validateJSONPatches(patchesBytes)
}

func (p Patch) validateAddPublicKeys() error {
	_, err := p.getRequiredArray(PublicKeys)
	if err != nil {
		return err
	}

	publicKeys := document.ParsePublicKeys(p.GetValue(PublicKeys))

	return document.ValidatePublicKeys(publicKeys)
}

func (p Patch) validateRemovePublicKeys() error {
	genericArr, err := p.getRequiredArray(PublicKeys)
	if err != nil {
		return err
	}

	return validateIds(document.StringArray(genericArr))
}

func (p Patch) validateAddServiceEndpoints() error {
	_, err := p.getRequiredArray(ServiceEndpointsKey)
	if err != nil {
		return err
	}

	services := document.ParseServices(p.GetValue(ServiceEndpointsKey))

	return document.ValidateServices(services)
}

func (p Patch) validateRemoveServiceEndpoints() error {
	genericArr, err := p.getRequiredArray(ServiceEndpointIdsKey)
	if err != nil {
		return err
	}

	return validateIds(document.StringArray(genericArr))
}

func validateIds(ids []string) error {
	for _, id := range ids {
		if err := document.ValidateID(id); err != nil {
			return err
		}
	}

	return nil
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

func (p Patch) getRequiredMap(key Key) (map[string]interface{}, error) {
	entry := p.GetValue(key)
	if entry == nil {
		return nil, fmt.Errorf("%s patch is missing %s", p.GetAction(), key)
	}

	required, ok := entry.(map[string]interface{})
	if !ok {
		return nil, errors.New("unexpected interface for document")
	}

	return required, nil
}
