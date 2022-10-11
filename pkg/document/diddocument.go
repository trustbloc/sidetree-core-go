/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

import (
	"encoding/json"
	"io"
)

const (

	// ContextProperty defines key for context property.
	ContextProperty = "@context"

	// AlsoKnownAs defines also known as property.
	AlsoKnownAs = "alsoKnownAs"

	// ServiceProperty defines key for service property.
	ServiceProperty = "service"

	// PublicKeyProperty defines key for public key property.
	PublicKeyProperty = "publicKey"

	// VerificationMethodProperty defines key for verification method.
	VerificationMethodProperty = "verificationMethod"

	// AuthenticationProperty defines key for authentication property.
	AuthenticationProperty = "authentication"

	// AssertionMethodProperty defines key for assertion method property.
	AssertionMethodProperty = "assertionMethod"

	// KeyAgreementProperty defines key for key agreement property.
	KeyAgreementProperty = "keyAgreement"

	// DelegationKeyProperty defines key for delegation key property.
	DelegationKeyProperty = "capabilityDelegation"

	// InvocationKeyProperty defines key for invocation key property.
	InvocationKeyProperty = "capabilityInvocation"
)

// DIDDocument Defines DID Document data structure used by Sidetree for basic type safety checks.
type DIDDocument map[string]interface{}

// ID is identifier for DID subject (what DID Document is about).
func (doc DIDDocument) ID() string {
	return stringEntry(doc[IDProperty])
}

// Context is the context of did document.
func (doc DIDDocument) Context() []interface{} {
	return interfaceArray(doc[ContextProperty])
}

// PublicKeys are used for digital signatures, encryption and other cryptographic operations.
func (doc DIDDocument) PublicKeys() []PublicKey {
	return ParsePublicKeys(doc[PublicKeyProperty])
}

// VerificationMethods (formerly public keys) are used for digital signatures, encryption and other cryptographic operations.
func (doc DIDDocument) VerificationMethods() []PublicKey {
	return ParsePublicKeys(doc[VerificationMethodProperty])
}

// AlsoKnownAs are alternate identifiers for DID subject.
func (doc DIDDocument) AlsoKnownAs() []string {
	return StringArray(doc[AlsoKnownAs])
}

// ParsePublicKeys is helper function for parsing public keys.
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

// Services is an array of service endpoints.
func (doc DIDDocument) Services() []Service {
	return ParseServices(doc[ServiceProperty])
}

// ParseServices is utility for parsing array of service endpoints.
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

// JSONLdObject returns map that represents JSON LD Object.
func (doc DIDDocument) JSONLdObject() map[string]interface{} {
	return doc
}

// Authentications returns authentication array (mixture of strings and objects).
func (doc DIDDocument) Authentications() []interface{} {
	return interfaceArray(doc[AuthenticationProperty])
}

// AssertionMethods returns assertion method array (mixture of strings and objects).
func (doc DIDDocument) AssertionMethods() []interface{} {
	return interfaceArray(doc[AssertionMethodProperty])
}

// AgreementKeys returns agreement method array (mixture of strings and objects).
func (doc DIDDocument) AgreementKeys() []interface{} {
	return interfaceArray(doc[KeyAgreementProperty])
}

// DelegationKeys returns delegation method array (mixture of strings and objects).
func (doc DIDDocument) DelegationKeys() []interface{} {
	return interfaceArray(doc[DelegationKeyProperty])
}

// InvocationKeys returns invocation method array (mixture of strings and objects).
func (doc DIDDocument) InvocationKeys() []interface{} {
	return interfaceArray(doc[InvocationKeyProperty])
}

// DIDDocumentFromReader creates an instance of DIDDocument by reading a JSON document from Reader.
func DIDDocumentFromReader(r io.Reader) (DIDDocument, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return DidDocumentFromBytes(data)
}

// DidDocumentFromBytes creates an instance of DIDDocument by reading a JSON document from bytes.
func DidDocumentFromBytes(data []byte) (DIDDocument, error) {
	doc := make(DIDDocument)
	err := json.Unmarshal(data, &doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

// DidDocumentFromJSONLDObject creates an instance of DIDDocument from json ld object.
func DidDocumentFromJSONLDObject(jsonldObject map[string]interface{}) DIDDocument {
	return jsonldObject
}

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
