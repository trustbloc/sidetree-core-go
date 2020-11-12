/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
)

func TestCreateAnchorFile(t *testing.T) {
	const createOpsNum = 2
	const updateOpsNum = 2
	const deactivateOpsNum = 2
	const recoverOpsNum = 2

	ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

	cif := CreateCoreIndexFile("coreURI", "mapURI", ops)
	require.NotNil(t, cif)
	require.Equal(t, createOpsNum, len(cif.Operations.Create))
	require.Equal(t, deactivateOpsNum, len(cif.Operations.Deactivate))
	require.Equal(t, recoverOpsNum, len(cif.Operations.Recover))
}

func TestParseAnchorFile(t *testing.T) {
	const createOpsNum = 5
	const updateOpsNum = 4
	const deactivateOpsNum = 3
	const recoverOpsNum = 1

	ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

	model := CreateCoreIndexFile("coreURI", "mapURI", ops)

	bytes, err := json.Marshal(model)
	require.NoError(t, err)

	parsed, err := ParseCoreIndexFile(bytes)
	require.NoError(t, err)

	require.Equal(t, createOpsNum, len(parsed.Operations.Create))
	require.Equal(t, deactivateOpsNum, len(parsed.Operations.Deactivate))
	require.Equal(t, recoverOpsNum, len(parsed.Operations.Recover))
}

func getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum int) *SortedOperations {
	result := &SortedOperations{}
	result.Create = append(result.Create, generateOperations(createOpsNum, operation.TypeCreate)...)
	result.Recover = append(result.Recover, generateOperations(recoverOpsNum, operation.TypeRecover)...)
	result.Deactivate = append(result.Deactivate, generateOperations(deactivateOpsNum, operation.TypeDeactivate)...)
	result.Update = append(result.Update, generateOperations(updateOpsNum, operation.TypeUpdate)...)

	return result
}

func generateOperations(numOfOperations int, opType operation.Type) (ops []*model.Operation) {
	for j := 1; j <= numOfOperations; j++ {
		ops = append(ops, generateOperation(j, opType))
	}

	return
}

func generateOperation(num int, opType operation.Type) *model.Operation {
	return &model.Operation{
		Type:         opType,
		UniqueSuffix: fmt.Sprintf("%s-%d", opType, num),
		Namespace:    "did:sidetree",
		SuffixData:   &model.SuffixDataModel{},
		Delta:        &model.DeltaModel{},
		SignedData:   "signed-data",
	}
}
