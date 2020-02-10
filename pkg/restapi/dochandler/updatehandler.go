/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"encoding/json"
	"fmt"
	"net/http"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/pkg/errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// Processor processes document operations
type Processor interface {
	Namespace() string
	Protocol() protocol.Client
	ProcessOperation(operation batch.Operation) (document.Document, error)
}

// UpdateHandler handles the creation and update of documents
type UpdateHandler struct {
	processor Processor
}

// NewUpdateHandler returns a new document update handler
func NewUpdateHandler(processor Processor) *UpdateHandler {
	return &UpdateHandler{
		processor: processor,
	}
}

// Update creates or updates a document
func (h *UpdateHandler) Update(rw http.ResponseWriter, req *http.Request) {
	request := &model.Request{}
	err := json.NewDecoder(req.Body).Decode(&request)
	if err != nil {
		common.WriteError(rw, http.StatusBadRequest, err)
		return
	}
	response, err := h.doUpdate(request)
	if err != nil {
		common.WriteError(rw, err.(*common.HTTPError).Status(), err)
		return
	}
	common.WriteResponse(rw, http.StatusOK, response)
}

func (h *UpdateHandler) doUpdate(request *model.Request) (document.Document, error) {
	operation, err := h.getOperation(request)
	if err != nil {
		logger.Errorf("Error: %s", err)
		return nil, common.NewHTTPError(http.StatusBadRequest, err)
	}

	//handling operation based on validated operation type and encoded payload from request bytes
	doc, err := h.processor.ProcessOperation(operation)
	if err != nil {
		logger.Errorf("Error: %s", err)
		return nil, common.NewHTTPError(http.StatusInternalServerError, err)
	}

	return doc, nil
}

func (h *UpdateHandler) getOperation(request *model.Request) (batch.Operation, error) {
	operation := batch.Operation{
		EncodedPayload:               request.Payload,
		Signature:                    request.Signature,
		SigningKeyID:                 request.Protected.Kid,
		HashAlgorithmInMultiHashCode: h.processor.Protocol().Current().HashAlgorithmInMultiHashCode,
	}

	decodedPayload, operationType, err := getDecodedPayload(operation.EncodedPayload)
	if err != nil {
		return batch.Operation{}, err
	}

	operation.Type = operationType

	switch operation.Type {
	case batch.OperationTypeCreate:

		uniqueSuffix, err := docutil.GetOperationHash(operation)
		if err != nil {
			return batch.Operation{}, err
		}

		operation.UniqueSuffix = uniqueSuffix
		operation.ID = h.processor.Namespace() + docutil.NamespaceDelimiter + operation.UniqueSuffix

		schema, err := getCreatePayloadSchema(decodedPayload)
		if err != nil {
			return batch.Operation{}, errors.New("request payload doesn't follow the expected create payload schema")
		}

		operation.EncodedDocument = schema.DidDocument
		operation.NextUpdateOTPHash = schema.NextUpdateOTPHash
		operation.NextRecoveryOTPHash = schema.NextRecoveryOTPHash

		return operation, nil

	case batch.OperationTypeUpdate:
		schema, err := getUpdatePayloadSchema(decodedPayload)
		if err != nil {
			return batch.Operation{}, errors.New("request payload doesn't follow the expected update payload schema")
		}

		operation.UniqueSuffix = schema.DidUniqueSuffix
		operation.ID = h.processor.Namespace() + docutil.NamespaceDelimiter + schema.DidUniqueSuffix

		operation.Patch = schema.Patch

		operation.NextUpdateOTPHash = schema.NextUpdateOTPHash

		return operation, nil

	default:
		return batch.Operation{}, fmt.Errorf("operation type [%s] not implemented", operation.Type)
	}
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
