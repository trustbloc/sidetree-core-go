/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"encoding/json"
	"fmt"

	jsonpatch "github.com/evanphx/json-patch"
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

		uniqueSuffix, err := docutil.GetOperationHash(operation)
		if err != nil {
			return nil, err
		}

		operation.UniqueSuffix = uniqueSuffix
		operation.ID = h.processor.Namespace() + docutil.NamespaceDelimiter + operation.UniqueSuffix

		schema, err := getCreatePayloadSchema(decodedPayload)
		if err != nil {
			return nil, errors.New("request payload doesn't follow the expected create payload schema")
		}

		operation.EncodedDocument = schema.DidDocument
		operation.NextUpdateOTPHash = schema.NextUpdateOTPHash
		operation.NextRecoveryOTPHash = schema.NextRecoveryOTPHash

	case batch.OperationTypeUpdate:
		schema, err := getUpdatePayloadSchema(decodedPayload)
		if err != nil {
			return nil, errors.New("request payload doesn't follow the expected update payload schema")
		}

		operation.UniqueSuffix = schema.DidUniqueSuffix
		operation.ID = h.processor.Namespace() + docutil.NamespaceDelimiter + schema.DidUniqueSuffix
		operation.Patch = schema.Patch
		operation.NextUpdateOTPHash = schema.NextUpdateOTPHash

	case batch.OperationTypeDelete:
		schema, err := getDeletePayloadSchema(decodedPayload)
		if err != nil {
			return nil, errors.New("request payload doesn't follow the expected delete payload schema")
		}

		operation.UniqueSuffix = schema.DidUniqueSuffix
		operation.ID = h.processor.Namespace() + docutil.NamespaceDelimiter + schema.DidUniqueSuffix
		operation.RecoveryOTP = schema.RecoveryOTP

	default:
		return nil, fmt.Errorf("operation type [%s] not implemented", operation.Type)
	}

	return operation, nil
}

func getUpdatePayloadSchema(payload []byte) (*updatePayloadSchema, error) {
	schema := &updatePayloadSchema{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, err
	}
	return schema, nil
}

func getCreatePayloadSchema(payload []byte) (*createPayloadSchema, error) {
	schema := &createPayloadSchema{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, err
	}
	return schema, nil
}

func getDeletePayloadSchema(payload []byte) (*deletePayloadSchema, error) {
	schema := &deletePayloadSchema{}
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

//updatePayloadSchema is the struct for update payload
type updatePayloadSchema struct {

	// operation
	// Required: true
	Operation model.OperationType `json:"type"`

	//The unique suffix of the DID
	DidUniqueSuffix string `json:"didUniqueSuffix"`

	//An RFC 6902 JSON patch to the current DID Document
	Patch jsonpatch.Patch

	// One-time password for update operation
	UpdateOTP string `json:"updateOtp"`

	// Hash of the one-time password for the next update operation
	NextUpdateOTPHash string `json:"nextUpdateOtpHash"`
}

//deletePayloadSchema is the struct for delete payload
type deletePayloadSchema struct {

	// operation
	// Required: true
	Operation model.OperationType `json:"type"`

	//The unique suffix of the DID
	// Required: true
	DidUniqueSuffix string `json:"didUniqueSuffix"`

	// One-time password for update operation
	// Required: true
	RecoveryOTP string `json:"recoveryOtp"`
}

// createPayloadSchema is the struct for create payload
type createPayloadSchema struct {

	// operation
	Operation model.OperationType `json:"type"`

	// Encoded original DID document
	DidDocument string `json:"didDocument"`

	// Hash of the one-time password for the next update operation
	NextUpdateOTPHash string `json:"nextUpdateOtpHash"`

	// Hash of the one-time password for this recovery/checkpoint/revoke operation.
	NextRecoveryOTPHash string `json:"nextRecoveryOtpHash"`
}

// payloadSchema is used to get operation type
type payloadSchema struct {

	// operation
	Operation model.OperationType `json:"type"`
}
