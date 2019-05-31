/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package docutil

//CalculateID calculates the ID from an encoded initial document (from create operation)
func CalculateID(namespace, encodedDocument string, hashAlgorithmAsMultihashCode uint) (string, error) {
	didDocumentBytes := []byte(encodedDocument)
	multiHashBytes, err := ComputeMultihash(hashAlgorithmAsMultihashCode, didDocumentBytes)
	if err != nil {
		return "", err
	}

	didID := namespace + EncodeToString(multiHashBytes)
	return didID, nil
}
