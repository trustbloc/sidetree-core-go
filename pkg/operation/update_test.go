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
		delta, err := getUpdateDelta()
		require.NoError(t, err)
		delta.UpdateCommitment = ""

		req, err := getUpdateRequest(delta)
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

func TestValidateUpdatedelta(t *testing.T) {
	t.Run("invalid next update commitment hash", func(t *testing.T) {
		delta, err := getUpdateDelta()
		require.NoError(t, err)

		delta.UpdateCommitment = ""
		err = validateDelta(delta, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"next update commitment hash is not computed with the latest supported hash algorithm")
	})
}

func TestParseUpdatedelta(t *testing.T) {
	t.Run("invalid next update commitment", func(t *testing.T) {
		delta, err := getUpdateDelta()
		require.NoError(t, err)

		delta.UpdateCommitment = ""
		deltaBytes, err := json.Marshal(delta)
		require.NoError(t, err)

		parsed, err := parseUpdateDelta(docutil.EncodeToString(deltaBytes), sha2_256)
		require.Error(t, err)
		require.Nil(t, parsed)
		require.Contains(t, err.Error(),
			"next update commitment hash is not computed with the latest supported hash algorithm")
	})
	t.Run("invalid bytes", func(t *testing.T) {
		parsed, err := parseUpdateDelta("invalid", sha2_256)
		require.Error(t, err)
		require.Nil(t, parsed)
		require.Contains(t, err.Error(), "invalid character")
	})
}

func TestValidateUpdateRequest(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		update, err := getDefaultUpdateRequest()
		require.NoError(t, err)

		err = validateUpdateRequest(update)
		require.NoError(t, err)
	})
	t.Run("missing signed data", func(t *testing.T) {
		update, err := getDefaultUpdateRequest()
		require.NoError(t, err)
		update.SignedData = nil

		err = validateUpdateRequest(update)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing signed data")
	})
	t.Run("missing did suffix", func(t *testing.T) {
		update, err := getDefaultUpdateRequest()
		require.NoError(t, err)
		update.DidSuffix = ""

		err = validateUpdateRequest(update)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing did suffix")
	})
	t.Run("missing delta", func(t *testing.T) {
		update, err := getDefaultUpdateRequest()
		require.NoError(t, err)
		update.Delta = ""

		err = validateUpdateRequest(update)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing delta")
	})
}

func getUpdateRequest(delta *model.DeltaModel) (*model.UpdateRequest, error) {
	deltaBytes, err := json.Marshal(delta)
	if err != nil {
		return nil, err
	}

	return &model.UpdateRequest{
		DidSuffix: "suffix",
		SignedData: &model.JWS{
			Protected: &model.Header{
				Alg: "alg",
				Kid: "kid",
			},
			Payload:   "payload",
			Signature: "signature",
		},
		Operation: model.OperationTypeUpdate,
		Delta:     docutil.EncodeToString(deltaBytes),
	}, nil
}

func getDefaultUpdateRequest() (*model.UpdateRequest, error) {
	delta, err := getUpdateDelta()
	if err != nil {
		return nil, err
	}
	return getUpdateRequest(delta)
}

func getUpdateRequestBytes() ([]byte, error) {
	req, err := getDefaultUpdateRequest()
	if err != nil {
		return nil, err
	}

	return json.Marshal(req)
}

func getUpdateDelta() (*model.DeltaModel, error) {
	jsonPatch, err := patch.NewJSONPatch(getTestPatch())
	if err != nil {
		return nil, err
	}

	return &model.DeltaModel{
		UpdateCommitment: computeMultihash("updateReveal"),
		Patches:          []patch.Patch{jsonPatch},
	}, nil
}

func getTestPatch() string {
	return `[{"op": "replace", "path": "/name", "value": "Jane"}]`
}
