/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diddochandler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/trustbloc/sidetree-core-go/pkg/restapi/dochandler"
)

// ResolveHandler resolves DID documents.
type ResolveHandler struct {
	*handler
}

type metricsResolveProvider interface {
	HTTPResolveTime(duration time.Duration)
}

// NewResolveHandler returns a new DID document resolve handler.
func NewResolveHandler(basePath string, resolver dochandler.Resolver,
	metrics metricsResolveProvider) *ResolveHandler {
	return &ResolveHandler{
		handler: newHandler(
			fmt.Sprintf("%s/{id}", basePath),
			http.MethodGet,
			dochandler.NewResolveHandler(resolver, metrics).Resolve,
		),
	}
}
