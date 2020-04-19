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
	didMethodName      = "did:sidetree"
)

func TestCalculateDID(t *testing.T) {
	payload := []byte("{}")

	id, err := CalculateID(didMethodName, EncodeToString(payload), multihashCode)
	require.Nil(t, err)
	require.NotEmpty(t, id)
}

func TestDidCalculationError(t *testing.T) {
	payload := []byte("{}")

	// non-supported mulithash code will cause an error
	id, err := CalculateID(didMethodName, EncodeToString(payload), 55)
	require.NotNil(t, err)
	require.Empty(t, id)
	require.Contains(t, err.Error(), "algorithm not supported, unable to compute hash")
}
