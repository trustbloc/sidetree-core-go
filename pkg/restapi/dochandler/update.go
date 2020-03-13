/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"encoding/json"
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

func (h *UpdateHandler) parseUpdateOperation(request []byte) (*batch.Operation, error) {
	schema, err := h.parseUpdateRequest(request)
	if err != nil {
		return nil, err
	}

	operationData, err := h.parseUpdateOperationData(schema.OperationData)
	if err != nil {
		return nil, err
	}

	id := h.processor.Namespace() + docutil.NamespaceDelimiter + schema.DidUniqueSuffix

	return &batch.Operation{
		Type:                         batch.OperationTypeUpdate,
		OperationBuffer:              request,
		ID:                           id,
		UniqueSuffix:                 schema.DidUniqueSuffix,
		UpdateOTP:                    schema.UpdateOTP,
		NextUpdateOTPHash:            operationData.NextUpdateOTPHash,
		Patch:                        schema.Patch,
		HashAlgorithmInMultiHashCode: h.processor.Protocol().Current().HashAlgorithmInMultiHashCode,
	}, nil
}

func (h *UpdateHandler) parseUpdateRequest(payload []byte) (*model.UpdateRequest, error) {
	schema := &model.UpdateRequest{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, err
	}
	return schema, nil
}

func (h *UpdateHandler) parseUpdateOperationData(encoded string) (*model.UpdateOperationData, error) {
	bytes, err := docutil.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	schema := &model.UpdateOperationData{}
	err = json.Unmarshal(bytes, schema)
	if err != nil {
		return nil, err
	}

	if err := h.validateUpdateOperationData(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

func (h *UpdateHandler) validateUpdateOperationData(opData *model.UpdateOperationData) error {
	// TODO: Add validation of patches

	code := h.processor.Protocol().Current().HashAlgorithmInMultiHashCode

	if !docutil.IsComputedUsingHashAlgorithm(opData.NextUpdateOTPHash, uint64(code)) {
		return errors.New("next update OTP hash is not computed with the latest supported hash algorithm")
	}

	return nil
}
