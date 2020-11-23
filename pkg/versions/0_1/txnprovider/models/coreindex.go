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
	Operations CoreOperations `json:"operations"`
}

// CreateOperation contains create operation data.
type CreateOperation struct {
	// SuffixData object
	SuffixData *model.SuffixDataModel `json:"suffixData"`
}

// CoreOperations contains operation proving data.
type CoreOperations struct {
	Create     []CreateOperation    `json:"create,omitempty"`
	Recover    []OperationReference `json:"recover,omitempty"`
	Deactivate []OperationReference `json:"deactivate,omitempty"`
}

// CreateCoreIndexFile will create core index file from provided operations.
// returns core index file model.
func CreateCoreIndexFile(coreProofURI, mapURI string, ops *SortedOperations) *CoreIndexFile {
	return &CoreIndexFile{
		CoreProofFileURI:        coreProofURI,
		ProvisionalIndexFileURI: mapURI,
		Operations: CoreOperations{
			Create:     assembleCreateOperations(ops.Create),
			Recover:    getOperationReferences(ops.Recover),
			Deactivate: getOperationReferences(ops.Deactivate),
		},
	}
}

func assembleCreateOperations(createOps []*model.Operation) []CreateOperation {
	var result []CreateOperation
	for _, op := range createOps {
		create := CreateOperation{SuffixData: op.SuffixData}
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
