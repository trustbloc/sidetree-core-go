/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package diddochandler DID document API.
//
//
// Terms Of Service:
//
//     Schemes: http, https
//     Host: 127.0.0.1:8080
//     Version: 0.1.0
//     License: SPDX-License-Identifier: Apache-2.0
//
//     Consumes:
//     - application/did+ld+json
//
//     Produces:
//     - application/did+ld+json
//
// swagger:meta
package diddochandler

import (
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// swagger:route POST /document create-did-document request
// Creates/updates a DID document.
// Responses:
//    default: error
//        200: response

// Resolve swagger:route GET /document/{id} resolve-did-document resolveDocParams
// Resolves a DID document by ID or by ID and initial value if provided.
// Responses:
//    default: error
//        200: response

// Contains the request.
//swagger:parameters request
//nolint:deadcode,unused
type requestWrapper struct {
	// The body of the request.
	//
	// required: true
	// in: body
	Body model.Request
}

// Contains the document.
//swagger:response response
//nolint:deadcode,unused
type responseWrapper struct {
	// The body of the response.
	//
	// required: true
	// in: body
	Body string
}

// Contains the error.
//swagger:response error
//nolint:deadcode,unused
type errorWrapper struct {
	// A description of the error.
	//
	// required: true
	// in: body
	Body string
}

// resolveDocumentParams model
// This is used for getting specific DID document
//
//swagger:parameters resolveDocParams
//nolint:deadcode,unused
type resolveDocumentParams struct {
	// The DID or the DID with initial-values parameter that contains encoded original did document.
	//
	// in: path
	// required: true
	ID string `json:"id"`
}
