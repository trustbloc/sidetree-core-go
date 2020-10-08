/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package docutil

import (
	"strings"

	"github.com/pkg/errors"

	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
)

// NamespaceDelimiter is the delimiter that separates the namespace from the unique suffix.
const NamespaceDelimiter = ":"

// CalculateID calculates the ID from an encoded value.
func CalculateID(namespace, encoded string, hashAlgorithmAsMultihashCode uint) (string, error) {
	uniqueSuffix, err := CalculateUniqueSuffix(encoded, hashAlgorithmAsMultihashCode)
	if err != nil {
		return "", err
	}

	didID := namespace + NamespaceDelimiter + uniqueSuffix

	return didID, nil
}

// CalculateUniqueSuffix calculates the unique suffix from an encoded value.
func CalculateUniqueSuffix(encoded string, hashAlgorithmAsMultihashCode uint) (string, error) {
	decoded, err := DecodeString(encoded)
	if err != nil {
		return "", err
	}

	multiHashBytes, err := ComputeMultihash(hashAlgorithmAsMultihashCode, decoded)
	if err != nil {
		return "", err
	}

	return EncodeToString(multiHashBytes), nil
}

// CalculateJCSID calculates the ID from an encoded value.
func CalculateJCSID(namespace string, value interface{}, hashAlgorithmAsMultihashCode uint) (string, error) {
	uniqueSuffix, err := CalculateJCSUniqueSuffix(value, hashAlgorithmAsMultihashCode)
	if err != nil {
		return "", err
	}

	didID := namespace + NamespaceDelimiter + uniqueSuffix

	return didID, nil
}

// CalculateJCSUniqueSuffix calculates the unique suffix from an JCS object.
func CalculateJCSUniqueSuffix(value interface{}, multihashAlg uint) (string, error) {
	bytes, err := canonicalizer.MarshalCanonical(value)
	if err != nil {
		return "", err
	}

	multiHashBytes, err := ComputeMultihash(multihashAlg, bytes)
	if err != nil {
		return "", err
	}

	return EncodeToString(multiHashBytes), nil
}

// GetNamespaceFromID returns namespace from ID.
func GetNamespaceFromID(id string) (string, error) {
	pos := strings.LastIndex(id, ":")
	if pos == -1 {
		return "", errors.Errorf("invalid ID [%s]", id)
	}

	return id[0:pos], nil
}
