/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

func TestNoopOperationFilter_Filter(t *testing.T) {
	p := &NoopOperationFilterProvider{}

	const suffix = "1234"
	const ns = "did:sidetree"

	f, err := p.Get(ns)
	require.NoError(t, err)

	ops := []*batch.Operation{
		{
			Type:         "create",
			ID:           ns + docutil.NamespaceDelimiter + suffix,
			UniqueSuffix: suffix,
		},
		{
			Type:         "update",
			ID:           ns + docutil.NamespaceDelimiter + suffix,
			UniqueSuffix: suffix,
		},
	}

	filteredOps, err := f.Filter("1234", ops)
	require.NoError(t, err)
	require.Equal(t, ops, filteredOps)
}
