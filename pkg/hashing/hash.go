/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package hashing

import (
	"crypto"
	"fmt"
)

// GetHash calculates hash of data using hash function identified by hash
func GetHash(hash crypto.Hash, data []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("hash function not available for: %d", hash)
	}

	h := hash.New()

	if _, hashErr := h.Write(data); hashErr != nil {
		return nil, hashErr
	}

	result := h.Sum(nil)

	return result, nil
}
