/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package filehandler

import (
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

	anchorBytes, err := handler.CreateAnchorFile([]string{"uniqueSuffix1", "uniqueSuffix2"}, "batchAddr")
	require.Nil(t, err)
	require.NotNil(t, anchorBytes)
}
