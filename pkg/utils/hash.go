/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"crypto"
	"fmt"
	"hash"

	multihash "github.com/multiformats/go-multihash"
)

const sha2_256 = 18

// ComputeMultihash will compute the hash for the supplied bytes using multihash code
func ComputeMultihash(multihashCode uint, bytes []byte) ([]byte, error) {

	if len(bytes) == 0 {
		return nil, fmt.Errorf("empty bytes")
	}

	h, err := GetHash(multihashCode)
	if err != nil {
		return nil, err
	}

	if _, hashErr := h.Write(bytes); hashErr != nil {
		return nil, hashErr
	}
	hash := h.Sum(nil)

	return multihash.Encode(hash, uint64(multihashCode))

}

// GetHash will return hash based on specified multihash code
func GetHash(multihashCode uint) (h hash.Hash, err error) {

	switch multihashCode {
	case sha2_256:
		h = crypto.SHA256.New()
	default:
		err = fmt.Errorf("algorithm not supported, unable to compute hash")
	}

	return h, err

}
