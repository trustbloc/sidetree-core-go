/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

func TestParseUpdateOperation(t *testing.T) {
	p := protocol.Protocol{
		HashAlgorithmInMultiHashCode: sha2_256,
	}
	t.Run("success", func(t *testing.T) {
		payload, err := getUpdateRequestBytes()
		require.NoError(t, err)

		op, err := ParseUpdateOperation(payload, p)
		require.NoError(t, err)
		require.Equal(t, batch.OperationTypeUpdate, op.Type)
	})
	t.Run("invalid json", func(t *testing.T) {
		schema, err := ParseUpdateOperation([]byte(""), p)
		require.Error(t, err)
		require.Nil(t, schema)
		require.Contains(t, err.Error(), "unexpected end of JSON input")
	})
	t.Run("invalid next update commitment hash", func(t *testing.T) {
		patchData, err := getUpdatePatchData()
		require.NoError(t, err)
		patchData.NextUpdateCommitmentHash = ""

		req, err := getUpdateRequest(patchData)
		require.NoError(t, err)
		payload, err := json.Marshal(req)
		require.NoError(t, err)

		schema, err := ParseUpdateOperation(payload, p)
		require.Error(t, err)
		require.Nil(t, schema)
		require.Contains(t, err.Error(),
			"next update commitment hash is not computed with the latest supported hash algorithm")
	})
}

func TestValidateUpdatePatchData(t *testing.T) {
	t.Run("invalid next update commitment hash", func(t *testing.T) {
		patchData, err := getUpdatePatchData()
		require.NoError(t, err)

		patchData.NextUpdateCommitmentHash = ""
		err = validatePatchData(patchData, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"next update commitment hash is not computed with the latest supported hash algorithm")
	})
}

func TestParseUpdatePatchData(t *testing.T) {
	t.Run("invalid next update commitment", func(t *testing.T) {
		patchData, err := getUpdatePatchData()
		require.NoError(t, err)

		patchData.NextUpdateCommitmentHash = ""
		patchDataBytes, err := json.Marshal(patchData)
		require.NoError(t, err)

		parsed, err := parseUpdatePatchData(docutil.EncodeToString(patchDataBytes), sha2_256)
		require.Error(t, err)
		require.Nil(t, parsed)
		require.Contains(t, err.Error(),
			"next update commitment hash is not computed with the latest supported hash algorithm")
	})
	t.Run("invalid bytes", func(t *testing.T) {
		parsed, err := parseUpdatePatchData("invalid", sha2_256)
		require.Error(t, err)
		require.Nil(t, parsed)
		require.Contains(t, err.Error(), "invalid character")
	})
}

func getUpdateRequest(patchData *model.PatchDataModel) (*model.UpdateRequest, error) {
	patchDataBytes, err := json.Marshal(patchData)
	if err != nil {
		return nil, err
	}

	return &model.UpdateRequest{
		Operation: model.OperationTypeUpdate,
		PatchData: docutil.EncodeToString(patchDataBytes),
	}, nil
}

func getDefaultUpdateRequest() (*model.UpdateRequest, error) {
	patchData, err := getUpdatePatchData()
	if err != nil {
		return nil, err
	}
	return getUpdateRequest(patchData)
}

func getUpdateRequestBytes() ([]byte, error) {
	req, err := getDefaultUpdateRequest()
	if err != nil {
		return nil, err
	}

	return json.Marshal(req)
}

func getUpdatePatchData() (*model.PatchDataModel, error) {
	jsonPatch, err := patch.NewJSONPatch(getTestPatch())
	if err != nil {
		return nil, err
	}

	return &model.PatchDataModel{
		NextUpdateCommitmentHash: computeMultihash("updateReveal"),
		Patches:                  []patch.Patch{jsonPatch},
	}, nil
}

func getTestPatch() string {
	return `[{"op": "replace", "path": "/name", "value": "Jane"}]`
}
