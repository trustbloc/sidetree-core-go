/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

func (h *UpdateHandler) handlePayload(operation *batch.Operation) (*batch.Operation, error) {
	decodedPayload, operationType, err := getDecodedPayload(operation.EncodedPayload)
	if err != nil {
		return nil, err
	}
	operation.Type = operationType

	switch operation.Type {
	case batch.OperationTypeCreate:

		schema, err := h.parseCreatePayload(decodedPayload)
		if err != nil {
			return nil, err
		}

		uniqueSuffix, err := docutil.GetOperationHash(operation)
		if err != nil {
			return nil, err
		}
		operation.UniqueSuffix = uniqueSuffix

		operation.Document = schema.OperationData.Document
		operation.NextUpdateOTPHash = schema.OperationData.NextUpdateOTPHash
		operation.NextRecoveryOTPHash = schema.SuffixData.NextRecoveryOTPHash

	case batch.OperationTypeUpdate:
		schema, err := getUpdatePayloadSchema(decodedPayload)
		if err != nil {
			return nil, errors.New("request payload doesn't follow the expected update payload schema")
		}

		operation.UniqueSuffix = schema.DidUniqueSuffix
		operation.Patch = schema.Patch
		operation.NextUpdateOTPHash = schema.NextUpdateOTPHash
		operation.UpdateOTP = schema.UpdateOTP

	case batch.OperationTypeDelete:
		schema, err := getDeletePayloadSchema(decodedPayload)
		if err != nil {
			return nil, errors.New("request payload doesn't follow the expected delete payload schema")
		}

		operation.UniqueSuffix = schema.DidUniqueSuffix
		operation.RecoveryOTP = schema.RecoveryOTP

	default:
		return nil, fmt.Errorf("operation type [%s] not implemented", operation.Type)
	}

	operation.ID = h.processor.Namespace() + docutil.NamespaceDelimiter + operation.UniqueSuffix

	return operation, nil
}

func getUpdatePayloadSchema(payload []byte) (*model.UpdatePayloadSchema, error) {
	schema := &model.UpdatePayloadSchema{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, err
	}
	return schema, nil
}

func (h *UpdateHandler) parseCreatePayload(payload []byte) (*model.CreatePayloadSchema, error) {
	schema := &model.CreatePayloadSchema{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, err
	}

	if err := h.validateCreatePayload(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

func (h *UpdateHandler) validateCreatePayload(schema *model.CreatePayloadSchema) error {
	if schema.OperationData.Document == "" {
		return errors.New("missing opaque document")
	}

	if schema.SuffixData.RecoveryKey.PublicKeyHex == "" {
		return errors.New("missing recovery key")
	}

	code := h.processor.Protocol().Current().HashAlgorithmInMultiHashCode

	if !docutil.IsComputedUsingHashAlgorithm(schema.SuffixData.NextRecoveryOTPHash, uint64(code)) {
		return errors.New("next recovery OTP hash is not computed with the latest supported hash algorithm")
	}

	if !docutil.IsComputedUsingHashAlgorithm(schema.SuffixData.OperationDataHash, uint64(code)) {
		return errors.New("operation data hash is not computed with the latest supported hash algorithm")
	}

	if !docutil.IsComputedUsingHashAlgorithm(schema.OperationData.NextUpdateOTPHash, uint64(code)) {
		return errors.New("next update OTP hash is not computed with the latest supported hash algorithm")
	}

	return nil
}

func getDeletePayloadSchema(payload []byte) (*model.DeletePayloadSchema, error) {
	schema := &model.DeletePayloadSchema{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, err
	}
	return schema, nil
}

func getDecodedPayload(encodedPayload string) (decodedPayload []byte, operationType batch.OperationType, err error) {
	decodedPayload, err = docutil.DecodeString(encodedPayload)
	if err != nil {
		return nil, "", err
	}

	typeSchema := &payloadSchema{}
	err = json.Unmarshal(decodedPayload, typeSchema)
	if err != nil {
		return nil, "", err
	}

	return decodedPayload, getOperationType(typeSchema.Operation), nil
}

func getOperationType(t model.OperationType) batch.OperationType {
	switch t {
	case model.OperationTypeCreate:
		return batch.OperationTypeCreate
	case model.OperationTypeUpdate:
		return batch.OperationTypeUpdate
	case model.OperationTypeDelete:
		return batch.OperationTypeDelete
	default:
		return ""
	}
}

// payloadSchema is used to get operation type
type payloadSchema struct {

	// operation
	Operation model.OperationType `json:"type"`
}
