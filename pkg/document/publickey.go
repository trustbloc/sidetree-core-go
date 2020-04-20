/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

// PublicKey must include id and type properties, and exactly one value property
type PublicKey map[string]interface{}

// NewPublicKey creates new public key
func NewPublicKey(pk map[string]interface{}) PublicKey {
	return pk
}

// ID is public key ID
func (pk PublicKey) ID() string {
	return stringEntry(pk[IDProperty])
}

// Type is public key type
func (pk PublicKey) Type() string {
	return stringEntry(pk[TypeProperty])
}

// Controller identifies the entity that controls the corresponding private key.
func (pk PublicKey) Controller() string {
	return stringEntry(pk[ControllerProperty])
}

// JWK is value property of internal keys
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

// PublicKeyJwk is value property for JWK
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

// Usage describes key usage
func (pk PublicKey) Usage() []string {
	return StringArray(pk[UsageProperty])
}

// JSONLdObject returns map that represents JSON LD Object
func (pk PublicKey) JSONLdObject() map[string]interface{} {
	return pk
}
