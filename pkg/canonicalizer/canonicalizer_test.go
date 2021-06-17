/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package canonicalizer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMarshalCanonical(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		test := struct {
			Beta  string `json:"beta"`
			Alpha string `json:"alpha"`
		}{
			Beta:  "beta",
			Alpha: "alpha",
		}

		result, err := MarshalCanonical(test)
		require.NoError(t, err)
		require.Equal(t, string(result), `{"alpha":"alpha","beta":"beta"}`)
	})

	t.Run("success - accepts bytes", func(t *testing.T) {
		result, err := MarshalCanonical([]byte(`{"beta":"beta","alpha":"alpha"}`))
		require.NoError(t, err)
		require.Equal(t, string(result), `{"alpha":"alpha","beta":"beta"}`)
	})

	t.Run("marshal error", func(t *testing.T) {
		var c chan int
		result, err := MarshalCanonical(c)
		require.Error(t, err)
		require.Empty(t, result)
		require.Contains(t, err.Error(), "json: unsupported type: chan int")
	})
}
