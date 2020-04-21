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
	multihashCode  uint = 18
	didMethodName       = "did:sidetree"
	expectedSuffix      = "EiAd7Z1iVTK7P_I9QQyy-muHI2UGSvxjAIzqxW7odZX2-g"
)

func TestCalculateDID(t *testing.T) {
	payload := []byte(suffixDataString)

	did, err := CalculateID(didMethodName, EncodeToString(payload), multihashCode)
	require.Nil(t, err)
	require.Equal(t, did, didMethodName+NamespaceDelimiter+expectedSuffix)
}

func TestCalculateUniqueSuffix(t *testing.T) {
	payload := []byte(suffixDataString)

	suffix, err := CalculateUniqueSuffix(EncodeToString(payload), multihashCode)
	require.Nil(t, err)
	require.Equal(t, expectedSuffix, suffix)
}

func TestDidCalculationError(t *testing.T) {
	payload := []byte("{}")

	// non-supported mulithash code will cause an error
	id, err := CalculateID(didMethodName, EncodeToString(payload), 55)
	require.NotNil(t, err)
	require.Empty(t, id)
	require.Contains(t, err.Error(), "algorithm not supported, unable to compute hash")
}

const suffixDataString = `{"delta_hash":"EiD0ERt_0QnYAoHw0KqhwYyMbMjT_vlvW3C8BuilAWT1Kw","recovery_key":{"kty":"EC","crv":"secp256k1","x":"FDmlOfldNAm9ThIQTj2-UkaCajsfrJOU0wJ7kl3QJHg","y":"bAGx86GZ41PUbzk_bvOKlrW0rXdmnXQrSop7HQoC12Y"},"recovery_commitment":"EiDrKHSo11DLU1uel6fFxH0B-0BLlyu_OinGPmLNvHyVoA"}`
