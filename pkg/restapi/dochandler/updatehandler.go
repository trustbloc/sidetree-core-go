/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// Processor processes document operations
type Processor interface {
	Namespace() string
	Protocol() protocol.Client
	ProcessOperation(operation *batch.Operation) (document.Document, error)
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
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		common.WriteError(rw, http.StatusBadRequest, err)
		return
	}

	request, err := getRequest(string(body))
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

func getRequest(body string) (*model.Request, error) {
	request := &model.Request{}
	err := json.NewDecoder(strings.NewReader(body)).Decode(request)
	if err != nil {
		return nil, err
	}

	// update, delete and recover require protected header all good
	if request.Protected != nil {
		return request, nil
	}

	// only create operation may not be protected - check if it is create operation
	create := &model.CreatePayloadSchema{}
	err = json.NewDecoder(strings.NewReader(body)).Decode(create)
	if err != nil {
		return nil, err
	}

	if create.Operation != model.OperationTypeCreate {
		// not create request; protected header is mandatory
		return nil, errors.New("missing protected header")
	}

	payload, err := json.Marshal(create)
	if err != nil {
		return nil, err
	}

	request = &model.Request{
		Payload: docutil.EncodeToString(payload),
	}

	return request, nil
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

func (h *UpdateHandler) getOperation(request *model.Request) (*batch.Operation, error) {
	// populate common values
	operation := &batch.Operation{
		EncodedPayload:               request.Payload,
		Signature:                    request.Signature,
		HashAlgorithmInMultiHashCode: h.processor.Protocol().Current().HashAlgorithmInMultiHashCode,
	}

	if request.Protected != nil {
		operation.SigningKeyID = request.Protected.Kid
		operation.SigningAlgorithm = request.Protected.Alg
	}

	return h.handlePayload(operation)
}
