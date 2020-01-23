/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package docutil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	multihashCode uint = 18
	didMethodName      = "did:sidetree:"
	expectedID         = "did:sidetree:EiDOQXC2GnoVyHwIRbjhLx_cNc6vmZaS04SZjZdlLLAPRg=="
	// encoded payload contains encoded document that corresponds to unique suffix above
	encodedPayload = "ewogICJAY29udGV4dCI6ICJodHRwczovL3czaWQub3JnL2RpZC92MSIsCiAgInB1YmxpY0tleSI6IFt7CiAgICAiaWQiOiAiI2tleTEiLAogICAgInR5cGUiOiAiU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOCIsCiAgICAicHVibGljS2V5SGV4IjogIjAyZjQ5ODAyZmIzZTA5YzZkZDQzZjE5YWE0MTI5M2QxZTBkYWQwNDRiNjhjZjgxY2Y3MDc5NDk5ZWRmZDBhYTlmMSIKICB9XSwKICAic2VydmljZSI6IFt7CiAgICAiaWQiOiAiSWRlbnRpdHlIdWIiLAogICAgInR5cGUiOiAiSWRlbnRpdHlIdWIiLAogICAgInNlcnZpY2VFbmRwb2ludCI6IHsKICAgICAgIkBjb250ZXh0IjogInNjaGVtYS5pZGVudGl0eS5mb3VuZGF0aW9uL2h1YiIsCiAgICAgICJAdHlwZSI6ICJVc2VyU2VydmljZUVuZHBvaW50IiwKICAgICAgImluc3RhbmNlIjogWyJkaWQ6YmFyOjQ1NiIsICJkaWQ6emF6Ojc4OSJdCiAgICB9CiAgfV0KfQo="
)

func TestCalculateDID(t *testing.T) {
	id, err := CalculateID(didMethodName, encodedPayload, multihashCode)
	require.Nil(t, err)
	require.Equal(t, expectedID, id)
}

func TestDidCalculationError(t *testing.T) {
	// non-supported mulithash code will cause an error
	id, err := CalculateID(didMethodName, encodedPayload, 5)
	require.NotNil(t, err)
	require.Empty(t, id)
	require.Contains(t, err.Error(), "algorithm not supported, unable to compute hash")
}
