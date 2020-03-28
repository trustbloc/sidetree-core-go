/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"

	jsonpatch "github.com/evanphx/json-patch"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// ParseUpdateOperation will parse update operation
func ParseUpdateOperation(request []byte, protocol protocol.Protocol) (*batch.Operation, error) {
	schema, err := parseUpdateRequest(request)
	if err != nil {
		return nil, err
	}

	operationData, err := parseUpdateOperationData(schema.OperationData, protocol.HashAlgorithmInMultiHashCode)
	if err != nil {
		return nil, err
	}

	patches := operationData.Patches[0].GetStringValue(patch.PatchesKey)

	// TODO: model for operation patch will change with issue-155
	patch, err := jsonpatch.DecodePatch([]byte(patches))
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		Type:                         batch.OperationTypeUpdate,
		OperationBuffer:              request,
		UniqueSuffix:                 schema.DidUniqueSuffix,
		UpdateOTP:                    schema.UpdateOTP,
		NextUpdateOTPHash:            operationData.NextUpdateOTPHash,
		Patch:                        patch,
		HashAlgorithmInMultiHashCode: protocol.HashAlgorithmInMultiHashCode,
	}, nil
}

func parseUpdateRequest(payload []byte) (*model.UpdateRequest, error) {
	schema := &model.UpdateRequest{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, err
	}
	return schema, nil
}

func parseUpdateOperationData(encoded string, code uint) (*model.OperationDataModel, error) {
	bytes, err := docutil.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	schema := &model.OperationDataModel{}
	err = json.Unmarshal(bytes, schema)
	if err != nil {
		return nil, err
	}

	if err := validateOperationData(schema, code); err != nil {
		return nil, err
	}

	return schema, nil
}
