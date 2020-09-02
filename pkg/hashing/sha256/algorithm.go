/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sha256

import (
	"crypto/sha256"
)

const algName = "SHA256"

// Algorithm implements SHA256 hashing
type Algorithm struct {
}

// New creates new gzip algorithm instance
func New() *Algorithm {
	return &Algorithm{}
}

// Hash will hash data using SHA256
func (a *Algorithm) Hash(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:]
}

// Accept algorithm
func (a *Algorithm) Accept(alg string) bool {
	return alg == algName
}

// Close closes open resources
func (a *Algorithm) Close() error {
	// nothing to do
	return nil
}
