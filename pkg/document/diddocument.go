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

	// ContextProperty defines key for context property
	ContextProperty = "@context"

	// ServiceProperty defines key for service property
	ServiceProperty = "service"

	// PublicKeyProperty defines key for public key property
	PublicKeyProperty = "publicKey"

	// AuthenticationProperty defines key for authentication property
	AuthenticationProperty = "authentication"

	// AssertionMethodProperty defines key for assertion method property
	AssertionMethodProperty = "assertionMethod"

	// AgreementKeyProperty defines key for agreement key property
	AgreementKeyProperty = "agreementKey"

	// ControllerProperty defines key for controller
	ControllerProperty = "controller"

	// UsageProperty describes key usage property
	UsageProperty = "usage"

	// PublicKeyJwkProperty describes external public key JWK
	PublicKeyJwkProperty = "publicKeyJwk"

	// JwkProperty describes internal public key JWK
	JwkProperty = "jwk"

	// TypeProperty describes type
	TypeProperty = "type"

	jsonldServicePoint = "serviceEndpoint"
)

// DIDDocument Defines DID Document data structure used by Sidetree for basic type safety checks.
type DIDDocument map[string]interface{}

// ID is identifier for DID subject (what DID Document is about)
func (doc DIDDocument) ID() string {
	return stringEntry(doc[IDProperty])
}

// Context is the context of did document
func (doc DIDDocument) Context() []string {
	return StringArray(doc[ContextProperty])
}

// PublicKeys are used for digital signatures, encryption and other cryptographic operations
func (doc DIDDocument) PublicKeys() []PublicKey {
	return ParsePublicKeys(doc[PublicKeyProperty])
}

// ParsePublicKeys is helper function for parsing public keys
func ParsePublicKeys(entry interface{}) []PublicKey {
	if entry == nil {
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
	return ParseServices(doc[ServiceProperty])
}

// ParseServices is utility for parsing array of service endpoints
func ParseServices(entry interface{}) []Service {
	if entry == nil {
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

// Authentication returns authentication array (mixture of strings and objects)
func (doc DIDDocument) Authentication() []interface{} {
	return interfaceArray(doc[AuthenticationProperty])
}

// AssertionMethod returns assertion method array (mixture of strings and objects)
func (doc DIDDocument) AssertionMethod() []interface{} {
	return interfaceArray(doc[AssertionMethodProperty])
}

// AgreementKey returns agreement method array (mixture of strings and objects)
func (doc DIDDocument) AgreementKey() []interface{} {
	return interfaceArray(doc[AgreementKeyProperty])
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

// interfaceArray
func interfaceArray(entry interface{}) []interface{} {
	if entry == nil {
		return nil
	}

	entries, ok := entry.([]interface{})
	if !ok {
		return nil
	}

	return entries
}
