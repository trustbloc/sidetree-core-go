/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diddochandler

import (
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
)

// handler resolves DID documents
type handler struct {
	path       string
	method     string
	reqHandler common.HTTPRequestHandler
}

func newHandler(path, method string, reqHandler common.HTTPRequestHandler) *handler {
	return &handler{
		path:       path,
		method:     method,
		reqHandler: reqHandler,
	}
}

// Path returns the context path
func (h *handler) Path() string {
	return h.path
}

// Method returns the HTTP method
func (h *handler) Method() string {
	return h.method
}

// Handler returns the handler
func (h *handler) Handler() common.HTTPRequestHandler {
	return h.reqHandler
}
