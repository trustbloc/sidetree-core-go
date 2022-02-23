/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
)

var logger = log.New("sidetree-core-restapi-dochandler")

const versionIDParam = "versionId"

// Resolver resolves documents.
type Resolver interface {
	ResolveDocument(idOrDocument string, opts ...document.ResolutionOption) (*document.ResolutionResult, error)
}

type metricsResolveProvider interface {
	HTTPResolveTime(duration time.Duration)
}

// ResolveHandler resolves generic documents.
type ResolveHandler struct {
	resolver Resolver
	metrics  metricsResolveProvider
}

// NewResolveHandler returns a new document resolve handler.
func NewResolveHandler(resolver Resolver, metrics metricsResolveProvider) *ResolveHandler {
	return &ResolveHandler{
		resolver: resolver,
		metrics:  metrics,
	}
}

// Resolve resolves a document.
func (o *ResolveHandler) Resolve(rw http.ResponseWriter, req *http.Request) {
	startTime := time.Now()

	defer func() {
		o.metrics.HTTPResolveTime(time.Since(startTime))
	}()

	id := getID(req)
	opts := getResolutionOptions(req)

	logger.Debugf("Resolving DID document for ID [%s]", id)
	response, err := o.doResolve(id, opts...)
	if err != nil {
		common.WriteError(rw, err.(*common.HTTPError).Status(), err)

		return
	}

	logger.Debugf("... resolved DID document for ID [%s]: %s", id, response.Document)
	common.WriteResponse(rw, http.StatusOK, response)
}

func (o *ResolveHandler) doResolve(id string, opts ...document.ResolutionOption) (*document.ResolutionResult, error) {
	resolutionResult, err := o.resolver.ResolveDocument(id, opts...)
	if err != nil {
		if strings.Contains(err.Error(), "bad request") {
			return nil, common.NewHTTPError(http.StatusBadRequest, err)
		}
		if strings.Contains(err.Error(), "not found") {
			return nil, common.NewHTTPError(http.StatusNotFound, errors.New("document not found"))
		}

		logger.Errorf("internal server error:  %s", err.Error())

		return nil, common.NewHTTPError(http.StatusInternalServerError, err)
	}

	return resolutionResult, nil
}

var getID = func(req *http.Request) string {
	return mux.Vars(req)["id"]
}

func getResolutionOptions(req *http.Request) []document.ResolutionOption {
	var resolutionOpts []document.ResolutionOption

	versionID := req.URL.Query().Get(versionIDParam)
	if versionID != "" {
		resolutionOpts = append(resolutionOpts, document.WithVersionID(versionID))
	}

	return resolutionOpts
}
