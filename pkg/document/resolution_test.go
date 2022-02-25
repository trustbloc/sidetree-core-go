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
	opts, err := GetResolutionOptions(WithAdditionalOperations([]*operation.AnchoredOperation{{Type: "create"}}),
		WithVersionID("ver"))
	require.NoError(t, err)
	require.Equal(t, 1, len(opts.AdditionalOperations))
	require.Equal(t, "ver", opts.VersionID)
}
