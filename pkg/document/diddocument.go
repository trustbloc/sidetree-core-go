/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

import (
	"encoding/json"
	"io"
	"io/ioutil"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
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
)

// DIDDocument Defines DID Document data structure used by Sidetree for basic type safety checks.
type DIDDocument map[string]interface{}

// ID is identifier for DID subject (what DID Document is about)
func (doc DIDDocument) ID() string {
	return stringEntry(doc[jsonldID])
}

// Context is the context of did document
func (doc DIDDocument) Context() []string {
	return arrayStringEntry(doc[jsonldContext])
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
		if !ok || !isValidPublicKey(emap) {
			continue
		}
		result = append(result, NewPublicKey(emap))
	}
	return result
}

func isValidPublicKey(pubKey map[string]interface{}) bool {
	if isEmpty(pubKey[jsonldID]) || isEmpty(pubKey[jsonldType]) {
		return false
	}
	return true
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
		if !ok || !isValidService(emap) {
			continue
		}
		result = append(result, NewService(emap))
	}
	return result
}

func isValidService(service map[string]interface{}) bool {
	if isEmpty(service[jsonldID]) || isEmpty(service[jsonldType]) || service[jsonldServicePoint] == nil {
		return false
	}
	return true
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

// String returns string representation of did document
func (doc DIDDocument) String() string {
	s, err := docutil.MarshalIndentCanonical(doc, "", "  ")
	if err != nil {
		return "<ERROR marshalling DIDDocument>"
	}
	return string(s)
}

// Bytes returns byte representation of did document
func (doc DIDDocument) Bytes() []byte {
	s, err := docutil.MarshalCanonical(doc)
	if err != nil {
		return []byte("<ERROR marshalling DIDDocument>")
	}
	return s
}

func isEmpty(entry interface{}) bool {
	return stringEntry(entry) == ""
}
