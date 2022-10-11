//go:build testing

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package docutil

// SetJSONMarshaler sets the JSON map marshaler for unit tests.
// Returns a function that resets the marshaler to the previous value.
func SetJSONMarshaler(marshaler func(m map[string]interface{}) ([]byte, error)) func() {
	prevMarshaler := marshalJSONMap
	marshalJSONMap = marshaler

	return func() {
		marshalJSONMap = prevMarshaler
	}
}

// SetJSONUnmarshaler sets the JSON map unmarshaler for unit tests.
// Returns a function that resets the unmarshaler to the previous value.
func SetJSONUnmarshaler(unmarshaler func(bytes []byte) (map[string]interface{}, error)) func() {
	prevUnmarshaler := unmarshalJSONMap
	unmarshalJSONMap = unmarshaler

	return func() {
		unmarshalJSONMap = prevUnmarshaler
	}
}

// SetJSONArrayMarshaler sets the JSON array marshaler for unit tests.
// Returns a function that resets the marshaler to the previous value.
func SetJSONArrayMarshaler(marshaler func(m []map[string]interface{}) ([]byte, error)) func() {
	prevMarshaler := marshalJSONArray
	marshalJSONArray = marshaler

	return func() {
		marshalJSONArray = prevMarshaler
	}
}

// SetJSONArrayUnmarshaler sets the JSON array unmarshaler for unit tests.
// Returns a function that resets the unmarshaler to the previous value.
func SetJSONArrayUnmarshaler(unmarshaler func(bytes []byte) ([]map[string]interface{}, error)) func() {
	prevUnmarshaler := unmarshalJSONArray
	unmarshalJSONArray = unmarshaler

	return func() {
		unmarshalJSONArray = prevUnmarshaler
	}
}
