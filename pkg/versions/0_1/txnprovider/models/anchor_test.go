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

	af := CreateAnchorFile("coreURI", "provisionalURI", "mapURI", ops)
	require.NotNil(t, af)
	require.Equal(t, createOpsNum, len(af.Operations.Create))
	require.Equal(t, 0, len(af.Operations.Update))
	require.Equal(t, deactivateOpsNum, len(af.Operations.Deactivate))
	require.Equal(t, recoverOpsNum, len(af.Operations.Recover))
}

func TestParseAnchorFile(t *testing.T) {
	const createOpsNum = 5
	const updateOpsNum = 4
	const deactivateOpsNum = 3
	const recoverOpsNum = 1

	ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

	model := CreateAnchorFile("coreURI", "provisionalURI", "mapURI", ops)

	bytes, err := json.Marshal(model)
	require.NoError(t, err)

	parsed, err := ParseAnchorFile(bytes)
	require.NoError(t, err)

	require.Equal(t, createOpsNum, len(parsed.Operations.Create))
	require.Equal(t, 0, len(parsed.Operations.Update))
	require.Equal(t, deactivateOpsNum, len(parsed.Operations.Deactivate))
	require.Equal(t, recoverOpsNum, len(parsed.Operations.Recover))
}

func getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum int) []*model.Operation {
	var ops []*model.Operation
	ops = append(ops, generateOperations(createOpsNum, operation.TypeCreate)...)
	ops = append(ops, generateOperations(recoverOpsNum, operation.TypeRecover)...)
	ops = append(ops, generateOperations(deactivateOpsNum, operation.TypeDeactivate)...)
	ops = append(ops, generateOperations(updateOpsNum, operation.TypeUpdate)...)

	return ops
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
