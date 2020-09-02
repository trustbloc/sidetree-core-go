/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"io/ioutil"
	"net/http"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
)

// Processor processes document operations
type Processor interface {
	Namespace() string
	Protocol() protocol.Client
	ProcessOperation(operation *batch.Operation) (*document.ResolutionResult, error)
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
	request, err := ioutil.ReadAll(req.Body)
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

func (h *UpdateHandler) doUpdate(request []byte) (*document.ResolutionResult, error) {
	operation, err := h.getOperation(request)
	if err != nil {
		logger.Warnf("operation validation error: %s", err.Error())
		return nil, common.NewHTTPError(http.StatusBadRequest, err)
	}

	// operation has been validated, now process it
	result, err := h.processor.ProcessOperation(operation)
	if err != nil {
		logger.Errorf("internal server error:  %s", err.Error())
		return nil, common.NewHTTPError(http.StatusInternalServerError, err)
	}

	return result, nil
}

func (h *UpdateHandler) getOperation(operationBuffer []byte) (*batch.Operation, error) {
	currentProtocol, err := h.processor.Protocol().Current()
	if err != nil {
		return nil, err
	}

	return operation.ParseOperation(h.processor.Namespace(), operationBuffer, currentProtocol)
}
