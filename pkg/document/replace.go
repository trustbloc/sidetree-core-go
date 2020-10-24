/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

import (
	"encoding/json"
)

const (

	// ReplaceServiceProperty defines key for service property.
	ReplaceServiceProperty = "services"

	// ReplacePublicKeyProperty defines key for public key property.
	ReplacePublicKeyProperty = "publicKeys"
)

// ReplaceDocument defines replace document data structure.
type ReplaceDocument map[string]interface{}

// ReplaceDocumentFromBytes creates an instance of replace document (for 'replace' patch, may be used for replace action).
func ReplaceDocumentFromBytes(data []byte) (ReplaceDocument, error) {
	doc := make(ReplaceDocument)
	err := json.Unmarshal(data, &doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

// ReplaceDocumentFromJSONLDObject creates an instance of ReplaceDocument from json ld object.
func ReplaceDocumentFromJSONLDObject(jsonldObject map[string]interface{}) ReplaceDocument {
	return jsonldObject
}

// PublicKeys returns public keys for replace document.
func (doc ReplaceDocument) PublicKeys() []PublicKey {
	return ParsePublicKeys(doc[ReplacePublicKeyProperty])
}

// Services returns services for replace document.
func (doc ReplaceDocument) Services() []Service {
	return ParseServices(doc[ReplaceServiceProperty])
}

// JSONLdObject returns map that represents JSON LD Object.
func (doc ReplaceDocument) JSONLdObject() map[string]interface{} {
	return doc
}
