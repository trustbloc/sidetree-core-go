/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"encoding/json"

	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
)

// CoreIndexFile defines the schema of an core index file.
type CoreIndexFile struct {

	// ProvisionalIndexFileURI is provisional index file URI
	ProvisionalIndexFileURI string `json:"provisionalIndexFileUri,omitempty"`

	// CoreProofFileURI is core proof file URI
	CoreProofFileURI string `json:"coreProofFileUri,omitempty"`

	// CoreOperations contain proving data for create, recover and deactivate operations.
	Operations *CoreOperations `json:"operations,omitempty"`
}

// CreateReference contains create operation reference.
type CreateReference struct {
	// SuffixData object
	SuffixData *model.SuffixDataModel `json:"suffixData"`
}

// CoreOperations contains operation references.
type CoreOperations struct {
	Create     []CreateReference    `json:"create,omitempty"`
	Recover    []OperationReference `json:"recover,omitempty"`
	Deactivate []OperationReference `json:"deactivate,omitempty"`
}

// CreateCoreIndexFile will create core index file from provided operations.
// returns core index file model.
func CreateCoreIndexFile(coreProofURI, provisionalIndexURI string, ops *SortedOperations) *CoreIndexFile {
	var coreOps *CoreOperations

	if len(ops.Create)+len(ops.Recover)+len(ops.Deactivate) > 0 {
		coreOps = &CoreOperations{}

		coreOps.Create = assembleCreateReferences(ops.Create)
		coreOps.Recover = getOperationReferences(ops.Recover)
		coreOps.Deactivate = getOperationReferences(ops.Deactivate)
	}

	return &CoreIndexFile{
		CoreProofFileURI:        coreProofURI,
		ProvisionalIndexFileURI: provisionalIndexURI,
		Operations:              coreOps,
	}
}

func assembleCreateReferences(createOps []*model.Operation) []CreateReference {
	var result []CreateReference
	for _, op := range createOps {
		create := CreateReference{SuffixData: op.SuffixData}
		result = append(result, create)
	}

	return result
}

// ParseCoreIndexFile will parse anchor model from content.
func ParseCoreIndexFile(content []byte) (*CoreIndexFile, error) {
	file := &CoreIndexFile{}
	err := json.Unmarshal(content, file)
	if err != nil {
		return nil, err
	}

	return file, nil
}
