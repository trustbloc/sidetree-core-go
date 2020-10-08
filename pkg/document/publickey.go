/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

const (

	// ControllerProperty defines key for controller.
	ControllerProperty = "controller"

	// PurposeProperty describes key purpose property.
	PurposeProperty = "purpose"

	// PublicKeyJwkProperty describes external public key JWK.
	PublicKeyJwkProperty = "publicKeyJwk"

	// JwkProperty describes internal public key JWK.
	JwkProperty = "jwk"

	// TypeProperty describes type.
	TypeProperty = "type"

	// PublicKeyBase58Property defines base 58 encoding for public key.
	PublicKeyBase58Property = "publicKeyBase58"
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

// JWK is value property of internal keys.
func (pk PublicKey) JWK() JWK {
	entry, ok := pk[JwkProperty]
	if !ok {
		return nil
	}

	json, ok := entry.(map[string]interface{})
	if !ok {
		return nil
	}

	return NewJWK(json)
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

// Purpose describes key purpose.
func (pk PublicKey) Purpose() []string {
	return StringArray(pk[PurposeProperty])
}

// JSONLdObject returns map that represents JSON LD Object.
func (pk PublicKey) JSONLdObject() map[string]interface{} {
	return pk
}
