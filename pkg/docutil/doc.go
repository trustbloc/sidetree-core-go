/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package docutil

// NamespaceDelimiter is the delimiter that separates the namespace from the unique suffix
const NamespaceDelimiter = ":"

//CalculateID calculates the ID from an encoded value
func CalculateID(namespace, encoded string, hashAlgorithmAsMultihashCode uint) (string, error) {
	uniqueSuffix, err := CalculateUniqueSuffix(encoded, hashAlgorithmAsMultihashCode)
	if err != nil {
		return "", err
	}

	didID := namespace + NamespaceDelimiter + uniqueSuffix
	return didID, nil
}

//CalculateUniqueSuffix calculates the unique suffix from an encoded value
func CalculateUniqueSuffix(encoded string, hashAlgorithmAsMultihashCode uint) (string, error) {
	value, err := DecodeString(encoded)
	if err != nil {
		return "", nil
	}

	multiHashBytes, err := ComputeMultihash(hashAlgorithmAsMultihashCode, value)
	if err != nil {
		return "", err
	}

	return EncodeToString(multiHashBytes), nil
}
