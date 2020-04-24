/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jws

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHeader(t *testing.T) {
	headers := make(Headers)

	alg, ok := headers.Algorithm()
	require.False(t, ok)
	require.Empty(t, alg)

	kid, ok := headers.KeyID()
	require.False(t, ok)
	require.Empty(t, kid)

	headers = Headers(map[string]interface{}{
		"alg": "alg",
		"kid": "kid",
	})

	alg, ok = headers.Algorithm()
	require.True(t, ok)
	require.Equal(t, "alg", alg)

	kid, ok = headers.KeyID()
	require.True(t, ok)
	require.Equal(t, "kid", kid)
}
