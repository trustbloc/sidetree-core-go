/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
)

// Processor processes document operations.
type Processor interface {
	Namespace() string
	ProcessOperation(operation []byte, protocolVersion uint64) (*document.ResolutionResult, error)
}

type metricsProvider interface {
	HTTPCreateUpdateTime(duration time.Duration)
}

// UpdateHandler handles the creation and update of documents.
type UpdateHandler struct {
	processor Processor
	protocol  protocol.Client
	metrics   metricsProvider
}

// NewUpdateHandler returns a new document update handler.
func NewUpdateHandler(processor Processor, pc protocol.Client, metrics metricsProvider) *UpdateHandler {
	return &UpdateHandler{
		processor: processor,
		protocol:  pc,
		metrics:   metrics,
	}
}

// Update creates or updates a document.
func (h *UpdateHandler) Update(rw http.ResponseWriter, req *http.Request) {
	startTime := time.Now()

	defer func() {
		h.metrics.HTTPCreateUpdateTime(time.Since(startTime))
	}()

	request, err := ioutil.ReadAll(req.Body)
	if err != nil {
		common.WriteError(rw, http.StatusBadRequest, err)

		return
	}

	logger.Debug("Processing update request", log.WithRequestBody(request))

	response, err := h.doUpdate(request)
	if err != nil {
		common.WriteError(rw, err.(*common.HTTPError).Status(), err)

		return
	}
	common.WriteResponse(rw, http.StatusOK, response)
}

func (h *UpdateHandler) doUpdate(operation []byte) (*document.ResolutionResult, error) {
	currentProtocol, err := h.protocol.Current()
	if err != nil {
		return nil, err
	}

	result, err := h.processor.ProcessOperation(operation, currentProtocol.Protocol().GenesisTime)
	if err != nil {
		if strings.Contains(err.Error(), "bad request") {
			logger.Warn("Operation validation error", log.WithError(err))

			return nil, common.NewHTTPError(http.StatusBadRequest, err)
		}

		logger.Error("Internal server error", log.WithError(err))

		return nil, common.NewHTTPError(http.StatusInternalServerError, err)
	}

	return result, nil
}
