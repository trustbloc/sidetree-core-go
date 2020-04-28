/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composer

import (
	"encoding/json"
	"fmt"

	jsonpatch "github.com/evanphx/json-patch"
	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

// ApplyPatches applies patches to the document
func ApplyPatches(doc document.Document, patches []patch.Patch) (document.Document, error) {
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
	log.Debugf("applying JSON patch: %v", entry)

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

// adds public keys to document
func applyAddPublicKeys(doc document.Document, entry interface{}) (document.Document, error) {
	log.Debugf("applying add public keys patch: %v", entry)

	newPublicKeyArr := document.ParsePublicKeys(entry)
	newPublicKeys := sliceToMapPK(newPublicKeyArr)

	existingPublicKeys := doc.PublicKeys()
	for _, existing := range existingPublicKeys {
		// NOTE: If a key ID already exists, we will just replace the existing key
		// so new public keys will retain new version
		if _, ok := newPublicKeys[existing.ID()]; !ok {
			newPublicKeys[existing.ID()] = existing
		}
	}

	doc[document.PublicKeyProperty] = mapToSlicePK(newPublicKeys)

	return doc, nil
}

// remove public keys from the document
func applyRemovePublicKeys(doc document.Document, entry interface{}) (document.Document, error) {
	log.Debugf("applying remove public keys patch: %v", entry)

	newPublicKeys := sliceToMapPK(doc.PublicKeys())

	keysToRemove := document.StringArray(entry)
	for _, key := range keysToRemove {
		delete(newPublicKeys, key)
	}

	doc[document.PublicKeyProperty] = mapToSlicePK(newPublicKeys)

	return doc, nil
}

func sliceToMapPK(publicKeys []document.PublicKey) map[string]document.PublicKey {
	// convert slice to map
	values := make(map[string]document.PublicKey)
	for _, pk := range publicKeys {
		values[pk.ID()] = pk
	}

	return values
}

func mapToSlicePK(mapValues map[string]document.PublicKey) []interface{} {
	// convert map to slice of values
	var values []interface{}
	for _, pk := range mapValues {
		values = append(values, pk.JSONLdObject())
	}

	return values
}

// adds service endpoints to document
func applyAddServiceEndpoints(doc document.Document, entry interface{}) (document.Document, error) {
	log.Debugf("applying add service endpoints patch: %v", entry)

	didDoc := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())

	newServiceArr := document.ParseServices(entry)

	// create an empty did document with service endpoints
	newServices := sliceToMapServices(newServiceArr)

	existingServices := didDoc.Services()
	for _, existing := range existingServices {
		// NOTE: If a service ID already exists, we will just replace the existing service
		// so new service endpoints will retain new version
		if _, ok := newServices[existing.ID()]; !ok {
			newServices[existing.ID()] = existing
		}
	}

	doc[document.ServiceProperty] = mapToSliceServices(newServices)

	return doc, nil
}

func applyRemoveServiceEndpoints(doc document.Document, entry interface{}) (document.Document, error) {
	log.Debugf("applying remove service endpoints patch: %v", entry)

	diddoc := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())
	newServices := sliceToMapServices(diddoc.Services())

	servicesToRemove := document.StringArray(entry)
	for _, svc := range servicesToRemove {
		delete(newServices, svc)
	}

	doc[document.ServiceProperty] = mapToSliceServices(newServices)

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

func mapToSliceServices(mapValues map[string]document.Service) []interface{} {
	// convert map to slice of values
	var values []interface{}
	for _, svc := range mapValues {
		values = append(values, svc.JSONLdObject())
	}

	return values
}
