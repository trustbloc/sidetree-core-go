/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package doccomposer

import (
	"encoding/json"
	"fmt"

	jsonpatch "github.com/evanphx/json-patch"

	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	logfields "github.com/trustbloc/sidetree-core-go/pkg/internal/log"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

var logger = log.New("sidetree-core-composer")

// DocumentComposer applies patches to the document.
type DocumentComposer struct {
}

// New creates new document composer.
func New() *DocumentComposer {
	return &DocumentComposer{}
}

// ApplyPatches applies patches to the document.
func (c *DocumentComposer) ApplyPatches(doc document.Document, patches []patch.Patch) (document.Document, error) {
	result, err := deepCopy(doc)
	if err != nil {
		return nil, err
	}

	for _, p := range patches {
		result, err = applyPatch(result, p)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// applyPatch applies a patch to the document.
func applyPatch(doc document.Document, p patch.Patch) (document.Document, error) {
	action, err := p.GetAction()
	if err != nil {
		return nil, err
	}

	value, err := p.GetValue()
	if err != nil {
		return nil, err
	}

	switch action {
	case patch.Replace:
		return applyRecover(value)
	case patch.JSONPatch:
		return applyJSON(doc, value)
	case patch.AddPublicKeys:
		return applyAddPublicKeys(doc, value)
	case patch.RemovePublicKeys:
		return applyRemovePublicKeys(doc, value)
	case patch.AddServiceEndpoints:
		return applyAddServiceEndpoints(doc, value)
	case patch.RemoveServiceEndpoints:
		return applyRemoveServiceEndpoints(doc, value)
	case patch.AddAlsoKnownAs:
		return applyAddAlsoKnownAs(doc, value)
	case patch.RemoveAlsoKnownAs:
		return applyRemoveAlsoKnownAs(doc, value)
	}

	return nil, fmt.Errorf("action '%s' is not supported", action)
}

func applyJSON(doc document.Document, entry interface{}) (document.Document, error) {
	logger.Debug("Applying JSON patch", logfields.WithPatch(entry))

	bytes, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}

	jsonPatches, err := jsonpatch.DecodePatch(bytes)
	if err != nil {
		return nil, err
	}

	docBytes, err := doc.Bytes()
	if err != nil {
		return nil, err
	}

	docBytes, err = jsonPatches.Apply(docBytes)
	if err != nil {
		return nil, err
	}

	return document.FromBytes(docBytes)
}

func applyRecover(replaceDoc interface{}) (document.Document, error) {
	logger.Debug("Applying replace patch", logfields.WithPatch(replaceDoc))

	docBytes, err := json.Marshal(replaceDoc)
	if err != nil {
		return nil, err
	}

	replace, err := document.ReplaceDocumentFromBytes(docBytes)
	if err != nil {
		return nil, err
	}

	doc := make(document.Document)
	doc[document.PublicKeyProperty] = replace[document.ReplacePublicKeyProperty]
	doc[document.ServiceProperty] = replace[document.ReplaceServiceProperty]

	return doc, nil
}

// adds public keys to document.
func applyAddPublicKeys(doc document.Document, entry interface{}) (document.Document, error) {
	logger.Debug("Applying add public keys patch", logfields.WithPatch(entry))

	addPublicKeys := document.ParsePublicKeys(entry)
	existingPublicKeysMap := sliceToMapPK(doc.PublicKeys())

	var newPublicKeys []document.PublicKey
	newPublicKeys = append(newPublicKeys, doc.PublicKeys()...)

	for _, key := range addPublicKeys {
		_, ok := existingPublicKeysMap[key.ID()]
		if ok {
			// if a key ID already exists, we will just replace the existing key
			updateKey(newPublicKeys, key)
		} else {
			// new key - append it to existing keys
			newPublicKeys = append(newPublicKeys, key)
		}
	}

	doc[document.PublicKeyProperty] = convertPublicKeys(newPublicKeys)

	return doc, nil
}

func updateKey(keys []document.PublicKey, key document.PublicKey) {
	for index, pk := range keys {
		if pk.ID() == key.ID() {
			keys[index] = key
		}
	}
}

func convertPublicKeys(pubKeys []document.PublicKey) []interface{} {
	var values []interface{}
	for _, pk := range pubKeys {
		values = append(values, pk.JSONLdObject())
	}

	return values
}

// remove public keys from the document.
func applyRemovePublicKeys(doc document.Document, entry interface{}) (document.Document, error) {
	logger.Debug("Applying remove public keys patch", logfields.WithPatch(entry))

	keysToRemove := sliceToMap(document.StringArray(entry))

	var newPublicKeys []interface{}

	for _, key := range doc.PublicKeys() {
		_, ok := keysToRemove[key.ID()]
		if !ok {
			// not in remove list so add to resulting public keys
			newPublicKeys = append(newPublicKeys, key.JSONLdObject())
		}
	}

	doc[document.PublicKeyProperty] = newPublicKeys

	return doc, nil
}

func sliceToMap(ids []string) map[string]bool {
	// convert slice to map
	values := make(map[string]bool)
	for _, id := range ids {
		values[id] = true
	}

	return values
}

func sliceToMapPK(publicKeys []document.PublicKey) map[string]document.PublicKey {
	// convert slice to map
	values := make(map[string]document.PublicKey)
	for _, pk := range publicKeys {
		values[pk.ID()] = pk
	}

	return values
}

// adds service endpoints to document.
func applyAddServiceEndpoints(doc document.Document, entry interface{}) (document.Document, error) {
	logger.Debug("Applying add service endpoints patch", logfields.WithPatch(entry))

	didDoc := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())

	addServices := document.ParseServices(entry)
	existingServicesMap := sliceToMapServices(didDoc.Services())

	var newServices []document.Service
	newServices = append(newServices, didDoc.Services()...)

	for _, service := range addServices {
		_, ok := existingServicesMap[service.ID()]
		if ok {
			// if a service ID already exists, we will just replace the existing service
			updateService(newServices, service)
		} else {
			// new service - append it to existing services
			newServices = append(newServices, service)
		}
	}

	doc[document.ServiceProperty] = convertServices(newServices)

	return doc, nil
}

func updateService(services []document.Service, service document.Service) {
	for index, s := range services {
		if s.ID() == service.ID() {
			services[index] = service
		}
	}
}

func convertServices(services []document.Service) []interface{} {
	var values []interface{}
	for _, service := range services {
		values = append(values, service.JSONLdObject())
	}

	return values
}

func applyRemoveServiceEndpoints(doc document.Document, entry interface{}) (document.Document, error) {
	logger.Debug("Applying remove service endpoints patch", logfields.WithPatch(entry))

	didDoc := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())
	servicesToRemove := sliceToMap(document.StringArray(entry))

	var newServices []interface{}

	for _, service := range didDoc.Services() {
		_, ok := servicesToRemove[service.ID()]
		if !ok {
			// not in remove list so add to resulting services
			newServices = append(newServices, service.JSONLdObject())
		}
	}

	doc[document.ServiceProperty] = newServices

	return doc, nil
}

func sliceToMapServices(services []document.Service) map[string]document.Service {
	// convert slice to map
	values := make(map[string]document.Service)
	for _, svc := range services {
		values[svc.ID()] = svc
	}

	return values
}

// adds also-known-as to document.
func applyAddAlsoKnownAs(doc document.Document, entry interface{}) (document.Document, error) {
	logger.Debug("applying add also-known-as patch", logfields.WithPatch(entry))

	didDoc := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())

	addURIs := document.StringArray(entry)
	existingURIs := sliceToMap(didDoc.AlsoKnownAs())

	var newURIs []string
	newURIs = append(newURIs, didDoc.AlsoKnownAs()...)

	for _, uri := range addURIs {
		_, ok := existingURIs[uri]
		if !ok {
			// new URI - append it to existing URIs
			newURIs = append(newURIs, uri)
		}
	}

	doc[document.AlsoKnownAs] = interfaceArray(newURIs)

	return doc, nil
}

func interfaceArray(values []string) []interface{} {
	var iArr []interface{}
	for _, v := range values {
		iArr = append(iArr, v)
	}

	return iArr
}

func applyRemoveAlsoKnownAs(doc document.Document, entry interface{}) (document.Document, error) {
	logger.Debug("Applying remove also-known-as patch", logfields.WithPatch(entry))

	didDoc := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())
	urisToRemove := sliceToMap(document.StringArray(entry))

	var newURIs []interface{}

	for _, uri := range didDoc.AlsoKnownAs() {
		_, ok := urisToRemove[uri]
		if !ok {
			// not in remove list so add to resulting services
			newURIs = append(newURIs, uri)
		}
	}

	doc[document.AlsoKnownAs] = newURIs

	return doc, nil
}

// deepCopy returns deep copy of JSON object.
func deepCopy(doc document.Document) (document.Document, error) {
	bytes, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}

	var result document.Document
	err = json.Unmarshal(bytes, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}
