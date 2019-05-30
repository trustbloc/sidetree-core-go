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
func (pk *PublicKey) ID() string {
	return stringEntry((*pk)[jsonldID])
}

// Type is public key type
func (pk *PublicKey) Type() string {
	return stringEntry((*pk)[jsonldType])
}

// Controller identifies the entity that controls the corresponding private key.
func (pk *PublicKey) Controller() string {
	return stringEntry((*pk)[jsonldController])
}

//PublicKeyBase64 is value property
func (pk *PublicKey) PublicKeyBase64() string {
	return stringEntry((*pk)[jsonldPublicKeyBase64])
}

// PublicKeyBase58 is value property
func (pk *PublicKey) PublicKeyBase58() string {
	return stringEntry((*pk)[jsonldPublicKeyBase58])
}

// PublicKeyHex is value property
func (pk *PublicKey) PublicKeyHex() string {
	return stringEntry((*pk)[jsonldPublicKeyHex])
}

// PublicKeyPEM is value property
func (pk *PublicKey) PublicKeyPEM() string {
	return stringEntry((*pk)[jsonldPublicKeyPem])
}

// PublicKeyJWK is value property
func (pk *PublicKey) PublicKeyJWK() string {
	return stringEntry((*pk)[jsonldPublicKeyJwk])
}
