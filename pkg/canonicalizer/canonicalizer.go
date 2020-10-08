/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package canonicalizer

import (
	"encoding/json"

	"github.com/trustbloc/sidetree-core-go/pkg/internal/jsoncanonicalizer"
)

// MarshalCanonical is using JCS RFC canonicalization.
func MarshalCanonical(value interface{}) ([]byte, error) {
	jsonLiteralValByte, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	return jsoncanonicalizer.Transform(jsonLiteralValByte)
}
