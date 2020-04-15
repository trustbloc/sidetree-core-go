/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

import (
	"encoding/json"
	"io"
	"io/ioutil"
)

const (
	jsonldContext = "@context"

	jsonldType = "type"

	jsonldService      = "service"
	jsonldServicePoint = "serviceEndpoint"

	jsonldPublicKey  = "publicKey"
	jsonldController = "controller"

	// various public key encodings
	jsonldPublicKeyBase64 = "publicKeyBase64"
	jsonldPublicKeyBase58 = "publicKeyBase58"
	jsonldPublicKeyHex    = "publicKeyHex"
	jsonldPublicKeyPem    = "publicKeyPem"
	jsonldPublicKeyJwk    = "publicKeyJwk"

	// key usage
	jsonldPublicKeyUsage = "usage"
)

// DIDDocument Defines DID Document data structure used by Sidetree for basic type safety checks.
type DIDDocument map[string]interface{}

// ID is identifier for DID subject (what DID Document is about)
func (doc DIDDocument) ID() string {
	return stringEntry(doc[jsonldID])
}

// Context is the context of did document
func (doc DIDDocument) Context() []string {
	return stringArray(doc[jsonldContext])
}

// PublicKeys are used for digital signatures, encryption and other cryptographic operations
func (doc DIDDocument) PublicKeys() []PublicKey {
	entry, ok := doc[jsonldPublicKey]
	if !ok {
		return nil
	}

	typedEntry, ok := entry.([]interface{})
	if !ok {
		return nil
	}

	var result []PublicKey
	for _, e := range typedEntry {
		emap, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		result = append(result, NewPublicKey(emap))
	}
	return result
}

// Services is an array of service endpoints
func (doc DIDDocument) Services() []Service {
	entry, ok := doc[jsonldService]
	if !ok {
		return nil
	}

	typedEntry, ok := entry.([]interface{})
	if !ok {
		return nil
	}

	var result []Service
	for _, e := range typedEntry {
		emap, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		result = append(result, NewService(emap))
	}
	return result
}

// JSONLdObject returns map that represents JSON LD Object
func (doc DIDDocument) JSONLdObject() map[string]interface{} {
	return doc
}

// DIDDocumentFromReader creates an instance of DIDDocument by reading a JSON document from Reader
func DIDDocumentFromReader(r io.Reader) (DIDDocument, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return DidDocumentFromBytes(data)
}

// DidDocumentFromBytes creates an instance of DIDDocument by reading a JSON document from bytes
func DidDocumentFromBytes(data []byte) (DIDDocument, error) {
	doc := make(DIDDocument)
	err := json.Unmarshal(data, &doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

// DidDocumentFromJSONLDObject creates an instance of DIDDocument from json ld object
func DidDocumentFromJSONLDObject(jsonldObject map[string]interface{}) DIDDocument {
	return jsonldObject
}
