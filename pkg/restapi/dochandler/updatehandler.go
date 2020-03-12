/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

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

func (h *UpdateHandler) doUpdate(request []byte) (document.Document, error) {
	operation, err := h.getOperation(request)
	if err != nil {
		logger.Errorf("Error: %s", err)
		return nil, common.NewHTTPError(http.StatusBadRequest, err)
	}

	// operation has been validated, now process it
	doc, err := h.processor.ProcessOperation(operation)
	if err != nil {
		logger.Errorf("Error: %s", err)
		return nil, common.NewHTTPError(http.StatusInternalServerError, err)
	}

	return doc, nil
}

func (h *UpdateHandler) getOperation(payload []byte) (*batch.Operation, error) {
	schema := &requestSchema{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, err
	}

	switch schema.Operation {
	case model.OperationTypeCreate:
		return h.parseCreateOperation(payload)
	case model.OperationTypeUpdate:
		return h.parseUpdateOperation(payload)
	case model.OperationTypeRevoke:
		return h.parseRevokeOperation(payload)
	default:
		return nil, fmt.Errorf("operation type [%s] not implemented", schema.Operation)
	}
}

// requestSchema is used to get operation type
type requestSchema struct {

	// operation
	Operation model.OperationType `json:"type"`
}
