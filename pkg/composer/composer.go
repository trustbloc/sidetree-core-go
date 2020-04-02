/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composer

import (
	"encoding/json"
	"fmt"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

const (
	jsonldPublicKey = "publicKey"
	jsonldService   = "service"
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
	action := p.GetAction()
	switch action {
	case patch.Replace:
		return applyRecover(p.GetStringValue(patch.DocumentKey))
	case patch.JSONPatch:
		return applyJSON(doc, p.GetStringValue(patch.PatchesKey))
	case patch.AddPublicKeys:
		return applyAddPublicKeys(doc, p.GetStringValue(patch.PublicKeys))
	case patch.RemovePublicKeys:
		return applyRemovePublicKeys(doc, p.GetStringValue(patch.PublicKeys))
	case patch.AddServiceEndpoints:
		return applyAddServiceEndpoints(doc, p.GetStringValue(patch.ServiceEndpointsKey))
	case patch.RemoveServiceEndpoints:
		return applyRemoveServiceEndpoints(doc, p.GetStringValue(patch.ServiceEndpointIdsKey))
	}

	return nil, fmt.Errorf("action '%s' is not supported", action)
}

func applyRecover(newDoc string) (document.Document, error) {
	log.Debugf("applying recover patch: %s", newDoc)
	return document.FromBytes([]byte(newDoc))
}

func applyJSON(doc document.Document, patches string) (document.Document, error) {
	log.Debugf("applying JSON patch: %s", patches)

	jsonPatches, err := jsonpatch.DecodePatch([]byte(patches))
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
func applyAddPublicKeys(doc document.Document, publicKeys string) (document.Document, error) {
	log.Debugf("applying add public keys patch: %s", publicKeys)

	// create an empty did document with public keys
	pkDoc, err := document.DidDocumentFromBytes([]byte(fmt.Sprintf(`{"%s":%s}`, jsonldPublicKey, publicKeys)))
	if err != nil {
		return nil, errors.Errorf("public keys invalid: %s", err.Error())
	}

	diddoc := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())

	newPublicKeys := sliceToMapPK(pkDoc.PublicKeys())

	existingPublicKeys := diddoc.PublicKeys()
	for _, existing := range existingPublicKeys {
		// NOTE: If a key ID already exists, we will just replace the existing key
		// so new public keys will retain new version
		if _, ok := newPublicKeys[existing.ID()]; !ok {
			newPublicKeys[existing.ID()] = existing
		}
	}

	doc[jsonldPublicKey] = mapToSlicePK(newPublicKeys)

	return doc, nil
}

// remove public keys from the document
func applyRemovePublicKeys(doc document.Document, removeKeyIDs string) (document.Document, error) {
	log.Debugf("applying remove public keys patch: %s", removeKeyIDs)

	var keysToRemove []string
	err := json.Unmarshal([]byte(removeKeyIDs), &keysToRemove)
	if err != nil {
		return nil, err
	}

	diddoc := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())
	newPublicKeys := sliceToMapPK(diddoc.PublicKeys())

	for _, key := range keysToRemove {
		delete(newPublicKeys, key)
	}

	doc[jsonldPublicKey] = mapToSlicePK(newPublicKeys)

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
func applyAddServiceEndpoints(doc document.Document, serviceEnpoints string) (document.Document, error) {
	log.Debugf("applying add service endpoints patch: %s", serviceEnpoints)

	diddoc := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())

	// create an empty did document with service endpoints
	svcDocStr := fmt.Sprintf(`{"%s":%s}`, jsonldService, serviceEnpoints)

	svcDoc, err := document.DidDocumentFromBytes([]byte(svcDocStr))
	if err != nil {
		return nil, errors.Errorf("services invalid: %s", err.Error())
	}

	newServices := sliceToMapServices(svcDoc.Services())

	existingServices := diddoc.Services()
	for _, existing := range existingServices {
		// NOTE: If a service ID already exists, we will just replace the existing service
		// so new service endpoints will retain new version
		if _, ok := newServices[existing.ID()]; !ok {
			newServices[existing.ID()] = existing
		}
	}

	doc[jsonldService] = mapToSliceServices(newServices)

	return doc, nil
}

func applyRemoveServiceEndpoints(doc document.Document, serviceIDs string) (document.Document, error) {
	log.Debugf("applying remove service endpoints patch: %s", serviceIDs)

	var servicesToRemove []string
	err := json.Unmarshal([]byte(serviceIDs), &servicesToRemove)
	if err != nil {
		return nil, err
	}

	diddoc := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())
	newServices := sliceToMapServices(diddoc.Services())

	for _, svc := range servicesToRemove {
		delete(newServices, svc)
	}

	doc[jsonldService] = mapToSliceServices(newServices)

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
