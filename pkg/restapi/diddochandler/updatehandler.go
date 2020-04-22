/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diddochandler

import (
	"fmt"
	"net/http"

	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/dochandler"
)

// UpdateHandler handles the creation and update of DID documents
type UpdateHandler struct {
	*dochandler.UpdateHandler
	path string
}

// NewUpdateHandler returns a new DID document update handler
func NewUpdateHandler(basePath string, processor dochandler.Processor) *UpdateHandler {
	return &UpdateHandler{
		UpdateHandler: dochandler.NewUpdateHandler(processor),
		path:          fmt.Sprintf("%s/operations", basePath),
	}
}

// Path returns the context path
func (h *UpdateHandler) Path() string {
	return h.path
}

// Method returns the HTTP method
func (h *UpdateHandler) Method() string {
	return http.MethodPost
}

// Handler returns the handler
func (h *UpdateHandler) Handler() common.HTTPRequestHandler {
	return h.Update
}
