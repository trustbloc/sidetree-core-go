/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

const (

	// ControllerProperty defines key for controller.
	ControllerProperty = "controller"

	// PurposesProperty describes key purposes property.
	PurposesProperty = "purposes"

	// PublicKeyJwkProperty describes external public key JWK.
	PublicKeyJwkProperty = "publicKeyJwk"

	// TypeProperty describes type.
	TypeProperty = "type"

	// PublicKeyBase58Property defines base 58 encoding for public key.
	PublicKeyBase58Property = "publicKeyBase58"

	// PublicKeyMultibaseProperty defines base multibase for public key.
	PublicKeyMultibaseProperty = "publicKeyMultibase"
)

// KeyPurpose defines key purpose.
type KeyPurpose string

const (
	// KeyPurposeAuthentication defines key purpose as authentication key.
	KeyPurposeAuthentication = "authentication"
	// KeyPurposeAssertionMethod defines key purpose as assertion key.
	KeyPurposeAssertionMethod = "assertionMethod"
	// KeyPurposeKeyAgreement defines key purpose as agreement key.
	KeyPurposeKeyAgreement = "keyAgreement"
	// KeyPurposeCapabilityDelegation defines key purpose as delegation key.
	KeyPurposeCapabilityDelegation = "capabilityDelegation"
	// KeyPurposeCapabilityInvocation defines key purpose as invocation key.
	KeyPurposeCapabilityInvocation = "capabilityInvocation"
)

// PublicKey must include id and type properties, and exactly one value property.
type PublicKey map[string]interface{}

// NewPublicKey creates new public key.
func NewPublicKey(pk map[string]interface{}) PublicKey {
	return pk
}

// ID is public key ID.
func (pk PublicKey) ID() string {
	return stringEntry(pk[IDProperty])
}

// Type is public key type.
func (pk PublicKey) Type() string {
	return stringEntry(pk[TypeProperty])
}

// Controller identifies the entity that controls the corresponding private key.
func (pk PublicKey) Controller() string {
	return stringEntry(pk[ControllerProperty])
}

// PublicKeyJwk is value property for JWK.
func (pk PublicKey) PublicKeyJwk() JWK {
	entry, ok := pk[PublicKeyJwkProperty]
	if !ok {
		return nil
	}

	json, ok := entry.(map[string]interface{})
	if !ok {
		return nil
	}

	return NewJWK(json)
}

// PublicKeyBase58 is base58 encoded public key.
func (pk PublicKey) PublicKeyBase58() string {
	return stringEntry(pk[PublicKeyBase58Property])
}

// PublicKeyMultibase is multibase public key.
func (pk PublicKey) PublicKeyMultibase() string {
	return stringEntry(pk[PublicKeyMultibaseProperty])
}

// Purpose describes key purpose.
func (pk PublicKey) Purpose() []string {
	return StringArray(pk[PurposesProperty])
}

// JSONLdObject returns map that represents JSON LD Object.
func (pk PublicKey) JSONLdObject() map[string]interface{} {
	return pk
}
