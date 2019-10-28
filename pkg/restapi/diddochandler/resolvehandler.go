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
}

// NewResolveHandler returns a new DID document resolve handler
func NewResolveHandler(resolver dochandler.Resolver) *ResolveHandler {
	return &ResolveHandler{
		ResolveHandler: dochandler.NewResolveHandler(resolver),
	}
}

// Path returns the context path
func (o *ResolveHandler) Path() string {
	return Path + "/{id}"
}

// Method returns the HTTP method
func (o *ResolveHandler) Method() string {
	return http.MethodGet
}

// Handler returns the handler
func (o *ResolveHandler) Handler() common.HTTPRequestHandler {
	return o.Resolve
}

// Resolve resolves a DID document by ID or DID document
func (o *ResolveHandler) Resolve(rw http.ResponseWriter, req *http.Request) {
	o.ResolveHandler.Resolve(rw, req)
}
