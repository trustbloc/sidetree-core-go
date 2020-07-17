/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
)

func TestNoopOperationFilter_Filter(t *testing.T) {
	p := &NoopOperationFilterProvider{}

	const suffix = "1234"
	const ns = "did:sidetree"

	f, err := p.Get(ns)
	require.NoError(t, err)

	ops := []*batch.AnchoredOperation{
		{
			Type:         "create",
			UniqueSuffix: suffix,
		},
		{
			Type:         "update",
			UniqueSuffix: suffix,
		},
	}

	filteredOps, err := f.Filter("1234", ops)
	require.NoError(t, err)
	require.Equal(t, ops, filteredOps)
}
