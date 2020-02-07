/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package filehandler

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

var batch = [][]byte{[]byte("op1"), []byte("op2")}

func TestProcessBatch(t *testing.T) {
	handler := Handler{}

	batch, err := handler.CreateBatchFile(batch)
	require.Nil(t, err)
	require.NotNil(t, batch)
}

func TestCreateAnchorFile(t *testing.T) {
	handler := Handler{}

	uniqueSuffixes := []string{"uniqueSuffix1", "uniqueSuffix2"}

	anchorBytes, err := handler.CreateAnchorFile(uniqueSuffixes, "batchAddr")
	require.Nil(t, err)
	require.NotNil(t, anchorBytes)

	af := AnchorFile{}
	err = json.Unmarshal(anchorBytes, &af)
	require.NoError(t, err)
	require.Equal(t, uniqueSuffixes, af.UniqueSuffixes)
}
