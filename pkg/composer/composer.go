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

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

const (
	jsonldPublicKey = "publicKey"
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
	}

	return nil, fmt.Errorf("action '%s' is not supported", action)
}

func applyRecover(newDoc string) (document.Document, error) {
	return document.FromBytes([]byte(newDoc))
}

func applyJSON(doc document.Document, patches string) (document.Document, error) {
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
	// create an empty did document with public keys
	pkDoc, err := document.DidDocumentFromBytes([]byte(fmt.Sprintf(`{"%s":%s}`, jsonldPublicKey, publicKeys)))
	if err != nil {
		return nil, errors.Errorf("public keys invalid: %s", err.Error())
	}

	diddoc := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())

	newPublicKeys := sliceToMapPK(pkDoc.PublicKeys())

	existingPublicKeys := diddoc.PublicKeys()
	for _, existing := range existingPublicKeys {
		// if key already exists just replace it with old one
		newPublicKeys[existing.ID()] = existing
	}

	doc[jsonldPublicKey] = mapToSlicePK(newPublicKeys)

	return doc, nil
}

// remove public keys from the document
func applyRemovePublicKeys(doc document.Document, removeKeyIDs string) (document.Document, error) {
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
