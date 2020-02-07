/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package filehandler

import (
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

// Handler creates batch/anchor files from operations
type Handler struct{}

// AnchorFile defines the schema of a Anchor File
type AnchorFile struct {
	// BatchFileHash is encoded hash of the batch file
	BatchFileHash string `json:"batchFileHash"`

	// UniqueSuffixes is an array of suffixes (the unique portion of the ID string that differentiates
	// one document from another) for all documents that are declared to have operations within the associated batch file.
	UniqueSuffixes []string `json:"uniqueSuffixes"`
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
func (h *Handler) CreateAnchorFile(uniqueSuffixes []string, batchAddress string) ([]byte, error) {
	af := AnchorFile{
		BatchFileHash:  batchAddress,
		UniqueSuffixes: uniqueSuffixes,
	}

	return docutil.MarshalCanonical(af)
}
