/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package docutil

import (
	"crypto"
	"errors"
	"fmt"
	"hash"

	"github.com/multiformats/go-multihash"

	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
)

const sha2_256 = 18

// ComputeMultihash will compute the hash for the supplied bytes using multihash code.
func ComputeMultihash(multihashCode uint, bytes []byte) ([]byte, error) {
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

// GetHash will return hash based on specified multihash code.
func GetHash(multihashCode uint) (h hash.Hash, err error) {
	switch multihashCode {
	case multihash.SHA2_256:
		h = crypto.SHA256.New()
	default:
		err = fmt.Errorf("algorithm not supported, unable to compute hash")
	}

	return h, err
}

// IsSupportedMultihash checks to see if the given encoded hash has been hashed using valid multihash code.
func IsSupportedMultihash(encodedMultihash string) bool {
	code, err := GetMultihashCode(encodedMultihash)
	if err != nil {
		return false
	}

	return multihash.ValidCode(code)
}

// IsComputedUsingMultihashAlgorithm checks to see if the given encoded hash has been hashed using multihash code.
func IsComputedUsingMultihashAlgorithm(encodedMultihash string, code uint64) bool {
	mhCode, err := GetMultihashCode(encodedMultihash)
	if err != nil {
		return false
	}

	return mhCode == code
}

// GetMultihashCode returns multihash code from encoded multihash.
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

// IsValidModelMultihash compares model with provided model multihash.
func IsValidModelMultihash(model interface{}, modelMultihash string) error {
	code, err := GetMultihashCode(modelMultihash)
	if err != nil {
		return err
	}

	encodedComputedMultihash, err := CalculateModelMultihash(model, uint(code))
	if err != nil {
		return err
	}

	if encodedComputedMultihash != modelMultihash {
		return errors.New("supplied hash doesn't match original content")
	}

	return nil
}

// CalculateModelMultihash calculates model multihash.
func CalculateModelMultihash(value interface{}, alg uint) (string, error) {
	bytes, err := canonicalizer.MarshalCanonical(value)
	if err != nil {
		return "", err
	}

	multiHashBytes, err := ComputeMultihash(alg, bytes)
	if err != nil {
		return "", err
	}

	return EncodeToString(multiHashBytes), nil
}
