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
}

func TestValidateUpdateOperationData(t *testing.T) {
	t.Run("invalid next update OTP", func(t *testing.T) {
		operationData := getUpdateOperationData()
		operationData.NextUpdateOTPHash = ""
		err := validateUpdateOperationData(operationData, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"next update OTP hash is not computed with the latest supported hash algorithm")
	})
}

func getUpdateRequest() (*model.UpdateRequest, error) {
	operationDataBytes, err := json.Marshal(getUpdateOperationData())
	if err != nil {
		return nil, err
	}

	return &model.UpdateRequest{
		Operation:     model.OperationTypeUpdate,
		OperationData: docutil.EncodeToString(operationDataBytes),
	}, nil
}

func getUpdateRequestBytes() ([]byte, error) {
	req, err := getUpdateRequest()
	if err != nil {
		return nil, err
	}

	return json.Marshal(req)
}

func getUpdateOperationData() *model.UpdateOperationData {
	return &model.UpdateOperationData{
		NextUpdateOTPHash: computeMultihash("updateOTP"),
	}
}
