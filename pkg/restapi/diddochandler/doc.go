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
//     - application/json
//
//     Produces:
//     - application/json
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
// Resolves a DID document by ID or validates the DID document if provided.
// Responses:
//    default: error
//        200: response

// Contains the DID document.
//swagger:response response
//nolint:deadcode,unused
type responseWrapper struct {
	// The body of the response.
	//
	// required: true
	// in: body
	Body model.Response
}

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

// resolveDocumentParams model
// This is used for getting specific DID document
//
//swagger:parameters resolveDocParams
//nolint:deadcode,unused
type resolveDocumentParams struct {
	// The ID of the DID document or the DID document to be validated.
	//
	// in: path
	// required: true
	ID string `json:"id"`
}
