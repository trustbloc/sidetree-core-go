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

// ResolveHandler resolves DID documents
type ResolveHandler struct {
	*dochandler.ResolveHandler
	basePath string
}

// NewResolveHandler returns a new DID document resolve handler
func NewResolveHandler(basePath string, resolver dochandler.Resolver) *ResolveHandler {
	return &ResolveHandler{
		ResolveHandler: dochandler.NewResolveHandler(resolver),
		basePath:       basePath,
	}
}

// Path returns the context path
func (h *ResolveHandler) Path() string {
	return h.basePath + "/{id}"
}

// Method returns the HTTP method
func (h *ResolveHandler) Method() string {
	return http.MethodGet
}

// Handler returns the handler
func (h *ResolveHandler) Handler() common.HTTPRequestHandler {
	return h.Resolve
}
