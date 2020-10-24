/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	svc := NewService(map[string]interface{}{})
	require.Empty(t, svc.Type())

	svc = NewService(map[string]interface{}{
		"id":              "did:example:123456789abcdefghi;openid",
		"type":            "OpenIdConnectVersion3.1Service",
		"serviceEndpoint": "https://openid.example.com/",
	})
	require.Equal(t, "did:example:123456789abcdefghi;openid", svc.ID())
	require.Equal(t, "OpenIdConnectVersion3.1Service", svc.Type())
	require.Equal(t, "https://openid.example.com/", svc.ServiceEndpoint())

	require.NotEmpty(t, svc.JSONLdObject())
}
