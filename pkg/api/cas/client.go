/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cas

// Client defines interface for accessing the underlying content addressable storage.
type Client interface {
	// Write writes the given content to CASClient.
	// returns the SHA256 hash in base64url encoding which represents the address of the content.
	Write(content []byte) (string, error)

	// Read reads the content of the given address in CASClient.
	// returns the content of the given address.
	Read(address string) ([]byte, error)
}
