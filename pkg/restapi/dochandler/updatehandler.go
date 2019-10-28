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

func (h *UpdateHandler) doUpdate(request *model.Request) (*model.Response, error) {
	operation, err := h.getOperation(request)
	if err != nil {
		logger.Errorf("Error: %s", err)
		return nil, common.NewHTTPError(http.StatusBadRequest, err)
	}

	//handling operation based on validated operation type and encoded payload from request bytes
	didDoc, err := h.processor.ProcessOperation(operation)
	if err != nil {
		logger.Errorf("Error: %s", err)
		return nil, common.NewHTTPError(http.StatusInternalServerError, err)
	}

	return &model.Response{Body: didDoc}, nil
}

func (h *UpdateHandler) getOperation(request *model.Request) (batch.Operation, error) {
	operation := batch.Operation{
		EncodedPayload:               request.Payload,
		Signature:                    request.Signature,
		SigningKeyID:                 request.Header.Kid,
		Type:                         getOperationType(request.Header.Operation),
		HashAlgorithmInMultiHashCode: h.processor.Protocol().Current().HashAlgorithmInMultiHashCode,
	}

	switch operation.Type {
	case batch.OperationTypeCreate:
		uniqueSuffix, err := docutil.GetOperationHash(operation)
		if err != nil {
			return batch.Operation{}, err
		}
		operation.UniqueSuffix = uniqueSuffix
		operation.ID = h.processor.Namespace() + uniqueSuffix
		operation.OperationNumber = 0
		return operation, nil

	case batch.OperationTypeUpdate:
		decodedPayload, err := getDecodedPayload(request.Payload)
		if err != nil {
			return batch.Operation{}, errors.New("request payload doesn't follow the expected update payload schema")
		}
		operation.OperationNumber = decodedPayload.OperationNumber
		operation.UniqueSuffix = decodedPayload.DidUniqueSuffix
		operation.PreviousOperationHash = decodedPayload.PreviousOperationHash
		operation.Patch = decodedPayload.Patch
		operation.ID = h.processor.Namespace() + decodedPayload.DidUniqueSuffix
		return operation, nil

	default:
		return batch.Operation{}, fmt.Errorf("operation type [%s] not implemented", operation.Type)
	}
}

func getDecodedPayload(encodedPayload string) (*payloadSchema, error) {
	decodedPayload, err := docutil.DecodeString(encodedPayload)
	if err != nil {
		return nil, err
	}
	uploadPayloadSchema := &payloadSchema{}
	err = json.Unmarshal(decodedPayload, uploadPayloadSchema)
	if err != nil {
		return nil, err
	}
	return uploadPayloadSchema, nil
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

//payloadSchema is the struct for update payload
type payloadSchema struct {
	//The unique suffix of the DID
	DidUniqueSuffix string
	//The number incremented from the last change version number. 1 if first change.
	OperationNumber uint
	//The hash of the previous operation made to the DID Document.
	PreviousOperationHash string
	//An RFC 6902 JSON patch to the current DID Document
	Patch jsonpatch.Patch
}
