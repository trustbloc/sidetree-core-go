/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"encoding/json"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
)

// AnchorFile defines the schema of an anchor file.
type AnchorFile struct {

	// MapFileURI is map file URI
	MapFileURI string `json:"mapFileUri,omitempty"`

	// CoreProofFileURI is core proof file URI
	CoreProofFileURI string `json:"coreProofFileUri,omitempty"`

	// ProvisionalProofFileURI is provisional proof file URI
	ProvisionalProofFileURI string `json:"provisionalProofFileUri,omitempty"`

	// Operations contain proving data for create, recover and deactivate operations.
	Operations Operations `json:"operations"`
}

// CreateOperation contains create operation data.
type CreateOperation struct {
	// SuffixData object
	SuffixData *model.SuffixDataModel `json:"suffixData"`
}

// Operations contains operation proving data.
type Operations struct {
	Create     []CreateOperation `json:"create,omitempty"`
	Update     []SignedOperation `json:"update,omitempty"`
	Recover    []SignedOperation `json:"recover,omitempty"`
	Deactivate []SignedOperation `json:"deactivate,omitempty"`
}

// CreateAnchorFile will create anchor file from provided operations.
// returns anchor file model.
func CreateAnchorFile(coreProofURI, provisionalProofURI, mapURI string, ops []*model.Operation) *AnchorFile {
	return &AnchorFile{
		CoreProofFileURI:        coreProofURI,
		ProvisionalProofFileURI: provisionalProofURI,
		MapFileURI:              mapURI,
		Operations: Operations{
			Create:     getCreateOperations(ops),
			Recover:    getSignedOperations(operation.TypeRecover, ops),
			Deactivate: getSignedOperations(operation.TypeDeactivate, ops),
		},
	}
}

func getCreateOperations(ops []*model.Operation) []CreateOperation {
	var result []CreateOperation
	for _, op := range ops {
		if op.Type == operation.TypeCreate {
			create := CreateOperation{SuffixData: op.SuffixData}

			result = append(result, create)
		}
	}

	return result
}

// ParseAnchorFile will parse anchor model from content.
func ParseAnchorFile(content []byte) (*AnchorFile, error) {
	af, err := getAnchorFile(content)
	if err != nil {
		return nil, err
	}

	return af, nil
}

// getAnchorFile creates new anchor file struct from bytes.
var getAnchorFile = func(bytes []byte) (*AnchorFile, error) {
	return unmarshalAnchorFile(bytes)
}

// unmarshalAnchorFile creates new anchor file struct from bytes.
func unmarshalAnchorFile(bytes []byte) (*AnchorFile, error) {
	file := &AnchorFile{}
	err := json.Unmarshal(bytes, file)
	if err != nil {
		return nil, err
	}

	return file, nil
}
