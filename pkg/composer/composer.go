/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composer

import (
	"encoding/json"
	"fmt"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

var logger = log.New("sidetree-core-composer")

// DocumentComposer applies patches to the document
type DocumentComposer struct {
}

// New creates new document composer
func New() *DocumentComposer {
	return &DocumentComposer{}
}

// ApplyPatches applies patches to the document
func (c *DocumentComposer) ApplyPatches(doc document.Document, patches []patch.Patch) (document.Document, error) {
	var err error

	for _, p := range patches {
		doc, err = applyPatch(doc, p)
		if err != nil {
			return nil, err
		}
	}

	return doc, nil
}

// applyPatch applies a patch to the document
func applyPatch(doc document.Document, p patch.Patch) (document.Document, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	action := p.GetAction()
	switch action {
	case patch.Replace:
		return applyRecover(p.GetValue(patch.DocumentKey))
	case patch.JSONPatch:
		return applyJSON(doc, p.GetValue(patch.PatchesKey))
	case patch.AddPublicKeys:
		return applyAddPublicKeys(doc, p.GetValue(patch.PublicKeys))
	case patch.RemovePublicKeys:
		return applyRemovePublicKeys(doc, p.GetValue(patch.PublicKeys))
	case patch.AddServiceEndpoints:
		return applyAddServiceEndpoints(doc, p.GetValue(patch.ServiceEndpointsKey))
	case patch.RemoveServiceEndpoints:
		return applyRemoveServiceEndpoints(doc, p.GetValue(patch.ServiceEndpointIdsKey))
	}

	return nil, fmt.Errorf("action '%s' is not supported", action)
}

func applyJSON(doc document.Document, entry interface{}) (document.Document, error) {
	logger.Debugf("applying JSON patch: %v", entry)

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
	logger.Debugf("applying replace patch: %v", replaceDoc)
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

// adds public keys to document
func applyAddPublicKeys(doc document.Document, entry interface{}) (document.Document, error) {
	logger.Debugf("applying add public keys patch: %v", entry)

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

// remove public keys from the document
func applyRemovePublicKeys(doc document.Document, entry interface{}) (document.Document, error) {
	logger.Debugf("applying remove public keys patch: %v", entry)

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

// adds service endpoints to document
func applyAddServiceEndpoints(doc document.Document, entry interface{}) (document.Document, error) {
	logger.Debugf("applying add service endpoints patch: %v", entry)

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
	logger.Debugf("applying remove service endpoints patch: %v", entry)

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
