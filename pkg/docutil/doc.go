/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package docutil

// NamespaceDelimiter is the delimiter that separates the namespace from the unique suffix
const NamespaceDelimiter = ":"

//CalculateID calculates the ID from an encoded initial document (from create operation)
func CalculateID(namespace, encodedDocument string, hashAlgorithmAsMultihashCode uint) (string, error) {
	didDocumentBytes := []byte(encodedDocument)
	multiHashBytes, err := ComputeMultihash(hashAlgorithmAsMultihashCode, didDocumentBytes)
	if err != nil {
		return "", err
	}

	didID := namespace + NamespaceDelimiter + EncodeToString(multiHashBytes)
	return didID, nil
}
