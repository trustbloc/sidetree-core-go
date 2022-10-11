/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package docutil

import (
	"bytes"
	"encoding/json"
)

// MarshalCanonical marshals the object into a canonical JSON format.
func MarshalCanonical(v interface{}) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	return getCanonicalContent(b)
}

// MarshalIndentCanonical is like MarshalCanonical but applies Indent to format the output.
// Each JSON element in the output will begin on a new line beginning with prefix
// followed by one or more copies of indent according to the indentation nesting.
func MarshalIndentCanonical(v interface{}, prefix, indent string) ([]byte, error) {
	b, err := MarshalCanonical(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = json.Indent(&buf, b, prefix, indent)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// getCanonicalContent ensures that fields in the JSON doc are marshaled in a deterministic order.
func getCanonicalContent(content []byte) ([]byte, error) {
	m, err := unmarshalJSONMap(content)
	if err != nil {
		a, e := unmarshalJSONArray(content)
		if e != nil {
			return nil, e
		}

		// Re-marshal it in order to ensure that the JSON fields are marshaled in a deterministic order.
		aBytes, e := marshalJSONArray(a)
		if e != nil {
			return nil, e
		}

		return aBytes, nil
	}

	// Re-marshal it in order to ensure that the JSON fields are marshaled in a deterministic order.
	mBytes, err := marshalJSONMap(m)
	if err != nil {
		return nil, err
	}

	return mBytes, nil
}

// marshalJSONMap marshals a JSON map. This variable may be overridden by unit tests.
var marshalJSONMap = func(m map[string]interface{}) ([]byte, error) {
	return json.Marshal(&m)
}

// unmarshalJSONMap unmarshals a JSON map from the given bytes. This variable may be overridden by unit tests.
var unmarshalJSONMap = func(bytes []byte) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	err := json.Unmarshal(bytes, &m)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// unmarshalJSONArray unmarshals an array of JSON maps from the given bytes. This variable may be overridden by unit tests.
var unmarshalJSONArray = func(bytes []byte) ([]map[string]interface{}, error) {
	var a []map[string]interface{}
	err := json.Unmarshal(bytes, &a)
	if err != nil {
		return nil, err
	}

	return a, nil
}

// marshalJSONArray marshals an array of JSON maps. This variable may be overridden by unit tests.
var marshalJSONArray = func(a []map[string]interface{}) ([]byte, error) {
	return json.Marshal(&a)
}
