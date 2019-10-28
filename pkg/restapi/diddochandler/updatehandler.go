/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diddochandler

import (
	"net/http"

	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/dochandler"
)

const (
	// Path is the context path for the DID document REST service
	Path = "/document"
)

// UpdateHandler handles the creation and update of DID documents
type UpdateHandler struct {
	*dochandler.UpdateHandler
}

// NewUpdateHandler returns a new DID document update handler
func NewUpdateHandler(processor dochandler.Processor) *UpdateHandler {
	return &UpdateHandler{
		UpdateHandler: dochandler.NewUpdateHandler(processor),
	}
}

// Path returns the context path
func (h *UpdateHandler) Path() string {
	return Path
}

// Method returns the HTTP method
func (h *UpdateHandler) Method() string {
	return http.MethodPost
}

// Handler returns the handler
func (h *UpdateHandler) Handler() common.HTTPRequestHandler {
	return h.Update
}

// Update updates/creates a DID document.
func (h *UpdateHandler) Update(rw http.ResponseWriter, req *http.Request) {
	h.UpdateHandler.Update(rw, req)
}
