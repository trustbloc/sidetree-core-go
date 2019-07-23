/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

import (
	"encoding/json"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

const jsonldID = "id"

// Document defines generic document data structure
type Document map[string]interface{}

// FromBytes creates an instance of Document by reading a JSON document from bytes
func FromBytes(data []byte) (Document, error) {

	doc := make(Document)
	err := json.Unmarshal(data, &doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

// ID is document identifier
func (doc *Document) ID() string {
	return stringEntry((*doc)[jsonldID])
}

// GetStringValue returns string value for specified key or "" if not found or wrong type
func (doc *Document) GetStringValue(key string) string {
	return stringEntry((*doc)[key])
}

// Bytes returns byte representation of did document
func (doc *Document) Bytes() ([]byte, error) {
	return docutil.MarshalCanonical(doc)
}

// JSONLdObject returns map that represents JSON LD Object
func (doc Document) JSONLdObject() map[string]interface{} {
	return doc
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
