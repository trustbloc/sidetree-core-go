/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
)

func TestGetOptions(t *testing.T) {
	const verTime = "2021-05-10T17:00:00Z"
	const verID = "ver"

	opts, err := GetResolutionOptions(WithAdditionalOperations([]*operation.AnchoredOperation{{Type: "create"}}),
		WithVersionID(verID), WithVersionTime(verTime))
	require.NoError(t, err)
	require.Equal(t, 1, len(opts.AdditionalOperations))
	require.Equal(t, verID, opts.VersionID)
	require.Equal(t, verTime, opts.VersionTime)
}
