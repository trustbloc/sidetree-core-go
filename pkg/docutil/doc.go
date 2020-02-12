/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package docutil

// NamespaceDelimiter is the delimiter that separates the namespace from the unique suffix
const NamespaceDelimiter = ":"

//CalculateID calculates the ID from an encoded initial document (from create operation)
func CalculateID(namespace, encodedDocument string, hashAlgorithmAsMultihashCode uint) (string, error) {
	uniqueSuffix, err := CalculateUniqueSuffix(encodedDocument, hashAlgorithmAsMultihashCode)
	if err != nil {
		return "", err
	}

	didID := namespace + NamespaceDelimiter + uniqueSuffix
	return didID, nil
}

//CalculateUniqueSuffix calculates the unique from an encoded initial document (from create operation)
func CalculateUniqueSuffix(encodedDocument string, hashAlgorithmAsMultihashCode uint) (string, error) {
	multiHashBytes, err := ComputeMultihash(hashAlgorithmAsMultihashCode, []byte(encodedDocument))
	if err != nil {
		return "", err
	}

	return EncodeToString(multiHashBytes), nil
}
