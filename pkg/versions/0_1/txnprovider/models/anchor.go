/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"encoding/json"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
)

// AnchorFile defines the schema of an anchor file
type AnchorFile struct {
	// MapFileHash is encoded hash of the map file
	MapFileHash string `json:"mapFileHash,omitempty"`

	// Operations contain proving data for create, recover and deactivate operations
	Operations Operations `json:"operations"`
}

//CreateOperation contains create operation data
type CreateOperation struct {
	// Encoded suffix data object
	SuffixData string `json:"suffix_data"`
}

//SignedOperation contains operation proving data
type SignedOperation struct {
	//The suffix of the DID
	DidSuffix string `json:"did_suffix"`

	// Compact JWS
	SignedData string `json:"signed_data"`
}

// Operations contains operation proving data
type Operations struct {
	Create     []CreateOperation `json:"create,omitempty"`
	Update     []SignedOperation `json:"update,omitempty"`
	Recover    []SignedOperation `json:"recover,omitempty"`
	Deactivate []SignedOperation `json:"deactivate,omitempty"`
}

// CreateAnchorFile will create anchor file from provided operations
// returns anchor file model
func CreateAnchorFile(mapAddress string, ops []*batch.Operation) *AnchorFile {
	return &AnchorFile{
		MapFileHash: mapAddress,
		Operations: Operations{
			Create:     getCreateOperations(ops),
			Recover:    getSignedOperations(batch.OperationTypeRecover, ops),
			Deactivate: getSignedOperations(batch.OperationTypeDeactivate, ops),
		},
	}
}

func getCreateOperations(ops []*batch.Operation) []CreateOperation {
	var result []CreateOperation
	for _, op := range ops {
		if op.Type == batch.OperationTypeCreate {
			create := CreateOperation{SuffixData: op.SuffixData}

			result = append(result, create)
		}
	}

	return result
}

// ParseAnchorFile will parse anchor model from content
func ParseAnchorFile(content []byte) (*AnchorFile, error) {
	af, err := getAnchorFile(content)
	if err != nil {
		return nil, err
	}

	return af, nil
}

// getAnchorFile creates new anchor file struct from bytes
var getAnchorFile = func(bytes []byte) (*AnchorFile, error) {
	return unmarshalAnchorFile(bytes)
}

// unmarshalAnchorFile creates new anchor file struct from bytes
func unmarshalAnchorFile(bytes []byte) (*AnchorFile, error) {
	file := &AnchorFile{}
	err := json.Unmarshal(bytes, file)
	if err != nil {
		return nil, err
	}

	return file, nil
}
