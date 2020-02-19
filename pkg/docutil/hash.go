/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package docutil

import (
	"crypto"
	"fmt"
	"hash"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"

	"github.com/multiformats/go-multihash"
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

//GetOperationHash gets the operation hash as encoded string
func GetOperationHash(o *batch.Operation) (string, error) {
	multihash, err := ComputeMultihash(o.HashAlgorithmInMultiHashCode, []byte(o.EncodedPayload))
	if err != nil {
		return "", err
	}
	return EncodeToString(multihash), nil
}

//IsSupportedMultihash checks to see if the given encoded hash has been hashed using valid multihash code
func IsSupportedMultihash(encodedMultihash string) bool {
	code, err := GetMultihashCode(encodedMultihash)
	if err != nil {
		return false
	}

	return multihash.ValidCode(code)
}

//GetMultihashCode returns multihash code from encoded multihash
func GetMultihashCode(encodedMultihash string) (uint64, error) {
	multihashBytes, err := DecodeString(encodedMultihash)
	if err != nil {
		return 0, err
	}

	mh, err := multihash.Decode(multihashBytes)
	if err != nil {
		return 0, err
	}

	return mh.Code, nil
}
