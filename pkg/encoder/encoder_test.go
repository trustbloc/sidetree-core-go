/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package encoder

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeAndDecodeAsString(t *testing.T) {
	data := "Hello World"
	encoded := EncodeToString([]byte(data))
	require.NotNil(t, encoded)

	decodedBytes, err := DecodeString(encoded)
	require.Nil(t, err)
	require.NotNil(t, decodedBytes)
	require.EqualValues(t, "Hello World", decodedBytes)
}
