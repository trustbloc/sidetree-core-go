/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package docutil

import (
	"strings"

	"github.com/pkg/errors"

	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
)

// NamespaceDelimiter is the delimiter that separates the namespace from the unique suffix.
const NamespaceDelimiter = ":"

// CalculateID calculates the ID from model and namespace.
func CalculateID(namespace string, value interface{}, hashAlgorithmAsMultihashCode uint) (string, error) {
	uniqueSuffix, err := hashing.CalculateModelMultihash(value, hashAlgorithmAsMultihashCode)
	if err != nil {
		return "", err
	}

	didID := namespace + NamespaceDelimiter + uniqueSuffix

	return didID, nil
}

// GetNamespaceFromID returns namespace from ID.
func GetNamespaceFromID(id string) (string, error) {
	pos := strings.LastIndex(id, ":")
	if pos == -1 {
		return "", errors.Errorf("invalid ID [%s]", id)
	}

	return id[0:pos], nil
}
