/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
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

	return &batch.Operation{
		Type:                         batch.OperationTypeUpdate,
		OperationBuffer:              request,
		UniqueSuffix:                 schema.DidUniqueSuffix,
		UpdateOTP:                    schema.UpdateOTP,
		NextUpdateOTPHash:            operationData.NextUpdateOTPHash,
		Patch:                        operationData.DocumentPatch,
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

func parseUpdateOperationData(encoded string, code uint) (*model.UpdateOperationData, error) {
	bytes, err := docutil.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	schema := &model.UpdateOperationData{}
	err = json.Unmarshal(bytes, schema)
	if err != nil {
		return nil, err
	}

	if err := validateUpdateOperationData(schema, code); err != nil {
		return nil, err
	}

	return schema, nil
}

func validateUpdateOperationData(opData *model.UpdateOperationData, code uint) error {
	// TODO: Add validation of patches

	if !docutil.IsComputedUsingHashAlgorithm(opData.NextUpdateOTPHash, uint64(code)) {
		return errors.New("next update OTP hash is not computed with the latest supported hash algorithm")
	}

	return nil
}
