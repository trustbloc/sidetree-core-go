/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diddochandler

import (
	"fmt"
	"net/http"

	"github.com/trustbloc/sidetree-core-go/pkg/restapi/dochandler"
)

// ResolveHandler resolves DID documents.
type ResolveHandler struct {
	*handler
}

// NewResolveHandler returns a new DID document resolve handler.
func NewResolveHandler(basePath string, resolver dochandler.Resolver) *ResolveHandler {
	return &ResolveHandler{
		handler: newHandler(
			fmt.Sprintf("%s/{id}", basePath),
			http.MethodGet,
			dochandler.NewResolveHandler(resolver).Resolve,
		),
	}
}
