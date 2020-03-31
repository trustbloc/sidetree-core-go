/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composer

import (
	"fmt"

	jsonpatch "github.com/evanphx/json-patch"

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
	action := p.GetAction()
	switch action {
	case patch.Replace:
		return applyRecover(p.GetStringValue(patch.DocumentKey))
	case patch.JSONPatch:
		return applyJSON(doc, p.GetStringValue(patch.PatchesKey))
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
