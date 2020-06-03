/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnhandler

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseAnchorData(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ad, err := ParseAnchorData("101.anchor")
		require.NoError(t, err)
		require.NotNil(t, ad)

		require.Equal(t, ad.NumberOfOperations, 101)
		require.Equal(t, ad.AnchorAddress, "anchor")
	})

	t.Run("error - invalid number of parts", func(t *testing.T) {
		ad, err := ParseAnchorData("1.anchor.other")
		require.Error(t, err)
		require.Nil(t, ad)

		require.Contains(t, err.Error(), "expecting [2] parts, got [3] parts")
	})

	t.Run("error - invalid number of operations", func(t *testing.T) {
		ad, err := ParseAnchorData("abc.anchor")
		require.Error(t, err)
		require.Nil(t, ad)

		require.Contains(t, err.Error(), "number of operations must be positive integer")
	})

	t.Run("error - invalid number of operations starts with 0", func(t *testing.T) {
		ad, err := ParseAnchorData("01.anchor")
		require.Error(t, err)
		require.Nil(t, ad)

		require.Contains(t, err.Error(), "number of operations must be positive integer")
	})

	t.Run("error - number of operations is negative", func(t *testing.T) {
		ad, err := ParseAnchorData("-1.anchor")
		require.Error(t, err)
		require.Nil(t, ad)

		require.Contains(t, err.Error(), "number of operations must be positive integer")
	})
}
