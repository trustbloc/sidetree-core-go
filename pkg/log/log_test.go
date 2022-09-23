/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/internal/log"
)

func TestDefaultLevel(t *testing.T) {
	SetDefaultLevel(log.ERROR)

	require.Equal(t, log.ERROR, GetLevel("moduley"))
}

func TestSetLevel(t *testing.T) {
	SetLevel("modulex", log.PANIC)

	require.Equal(t, log.PANIC, GetLevel("modulex"))
}

func TestSetSpec(t *testing.T) {
	require.NoError(t, SetSpec("modulea=debug:moduleb=panic:error"))
	require.Contains(t, GetSpec(), "modulea=DEBUG")
	require.Contains(t, GetSpec(), "moduleb=PANIC")
	require.Contains(t, GetSpec(), ":ERROR")

	require.Equal(t, log.DEBUG, GetLevel("modulea"))
	require.Equal(t, log.PANIC, GetLevel("moduleb"))
	require.Equal(t, log.ERROR, GetLevel(""))
}
