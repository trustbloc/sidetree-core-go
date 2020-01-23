/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package filehandler

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const sha2_256 = 18

var batch = [][]byte{[]byte("op1"), []byte("op2")}

func TestProcessBatch(t *testing.T) {
	handler := Handler{}

	batch, err := handler.CreateBatchFile(batch)
	require.Nil(t, err)
	require.NotNil(t, batch)
}

func TestCreateAnchorFile(t *testing.T) {
	handler := Handler{}

	anchorBytes, err := handler.CreateAnchorFile(batch, "batchAddr", sha2_256)
	require.Nil(t, err)
	require.NotNil(t, anchorBytes)
}

func TestCreateAnchorFileError(t *testing.T) {
	handler := Handler{}

	anchorBytes, err := handler.CreateAnchorFile(batch, "batchAddr", 55)
	require.NotNil(t, err)
	require.Nil(t, anchorBytes)
}

func TestGetMerkleTreeError(t *testing.T) {
	mtr, err := getMerkleTreeRoot(batch, 55)
	require.NotNil(t, err)
	require.Nil(t, mtr)
}
