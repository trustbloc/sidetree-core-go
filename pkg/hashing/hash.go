/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package hashing

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/multiformats/go-multihash"

	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/encoder"
)

// ComputeMultihash will compute the hash for the supplied bytes using multihash code.
func ComputeMultihash(multihashCode uint, bytes []byte) ([]byte, error) {
	hash, err := GetHashFromMultihash(multihashCode)
	if err != nil {
		return nil, err
	}

	hashedBytes, err := GetHash(hash, bytes)
	if err != nil {
		return nil, err
	}

	return multihash.Encode(hashedBytes, uint64(multihashCode))
}

// GetHashFromMultihash will return hash based on specified multihash code.
func GetHashFromMultihash(multihashCode uint) (h crypto.Hash, err error) {
	switch multihashCode {
	case multihash.SHA2_256:
		h = crypto.SHA256
	case multihash.SHA2_512:
		h = crypto.SHA512
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

// IsComputedUsingMultihashAlgorithms checks to see if the given encoded hash has been hashed using one of supplied code.
func IsComputedUsingMultihashAlgorithms(encodedMultihash string, codes []uint) bool {
	mhCode, err := GetMultihashCode(encodedMultihash)
	if err != nil {
		return false
	}

	for _, supported := range codes {
		if mhCode == uint64(supported) {
			return true
		}
	}

	return false
}

// GetMultihashCode returns multihash code from encoded multihash.
func GetMultihashCode(encodedMultihash string) (uint64, error) {
	mh, err := GetMultihash(encodedMultihash)
	if err != nil {
		return 0, fmt.Errorf("failed to get decoded multihash: %s", err.Error())
	}

	return mh.Code, nil
}

// GetMultihash returns decoded multihash from encoded multihash.
func GetMultihash(encodedMultihash string) (*multihash.DecodedMultihash, error) {
	multihashBytes, err := encoder.DecodeString(encodedMultihash)
	if err != nil {
		return nil, err
	}

	return multihash.Decode(multihashBytes)
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

	return encoder.EncodeToString(multiHashBytes), nil
}

// GetHash calculates hash of data using hash function identified by hash.
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
