/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package filehandler

import (
	"gitlab.com/NebulousLabs/merkletree"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

// Handler creates batch/anchor files from operations
type Handler struct{}

// AnchorFile defines the schema of a Anchor File and its related operations.
type AnchorFile struct {
	// BatchFileHash is encoded hash of the batch file
	BatchFileHash string `json:"batchFileHash"`

	// MerkleRoot is encoded root hash of the Merkle tree constructed from
	// the operations included in the batch file
	MerkleRoot string `json:"merkleRoot"`
}

// BatchFile defines the schema of a Batch File and its related operations.
type BatchFile struct {
	// operations included in this batch file, each operation is an encoded string
	Operations []string `json:"operations"`
}

// New returns new operations handler
func New() *Handler {
	return &Handler{}
}

// CreateBatchFile will combine all operations into batch file
// returns batch file bytes
func (h *Handler) CreateBatchFile(operations [][]byte) ([]byte, error) {
	// creates new batch file with supplied operations list
	// operations is the list of operations, each of which is an encoded string
	// as specified by the Sidetree protocol.
	var ops []string
	for _, op := range operations {
		opStr := docutil.EncodeToString(op)
		ops = append(ops, opStr)
	}

	bf := BatchFile{Operations: ops}

	return docutil.MarshalCanonical(bf)
}

// CreateAnchorFile will create anchor file for Sidetree transaction
// returns anchor file bytes
func (h *Handler) CreateAnchorFile(operations [][]byte, batchAddress string, multihashCode uint) ([]byte, error) {
	// Create Merkle tree and get it's root for anchor file
	mtrHash, err := getMerkleTreeRoot(operations, multihashCode)
	if err != nil {
		return nil, err
	}

	af := AnchorFile{
		BatchFileHash: batchAddress,
		MerkleRoot:    docutil.EncodeToString(mtrHash),
	}

	return docutil.MarshalCanonical(af)
}

func getMerkleTreeRoot(operations [][]byte, multihashCode uint) ([]byte, error) {
	hash, err := docutil.GetHash(multihashCode)
	if err != nil {
		return nil, err
	}

	tree := merkletree.New(hash)
	if err = tree.SetIndex(1); err != nil {
		return nil, err
	}

	for _, op := range operations {
		tree.Push(op)
	}

	return tree.Root(), nil
}
