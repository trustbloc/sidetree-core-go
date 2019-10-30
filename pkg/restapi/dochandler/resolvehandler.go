/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
)

var logger = logrus.New()

// Resolver resolves documents
type Resolver interface {
	Namespace() string
	ResolveDocument(idOrDocument string) (document.Document, error)
}

// ResolveHandler resolves generic documents
type ResolveHandler struct {
	resolver Resolver
}

// NewResolveHandler returns a new document resolve handler
func NewResolveHandler(resolver Resolver) *ResolveHandler {
	return &ResolveHandler{
		resolver: resolver,
	}
}

// Resolve resolves a document
func (o *ResolveHandler) Resolve(rw http.ResponseWriter, req *http.Request) {
	id := getID(req)
	logger.Debugf("Resolving DID document for ID [%s]", id)
	response, err := o.doResolve(id)
	if err != nil {
		common.WriteError(rw, err.(*common.HTTPError).Status(), err)
		return
	}
	logger.Debugf("... resolved DID document for ID [%s]: %s", id, response)
	common.WriteResponse(rw, http.StatusOK, response)
}

func (o *ResolveHandler) doResolve(id string) (document.Document, error) {
	if !strings.HasPrefix(id, o.resolver.Namespace()) {
		logger.Errorf("DID ID [%s] does not start with supported namespace [%s]", id, o.resolver.Namespace())
		return nil, common.NewHTTPError(http.StatusBadRequest, errors.New("must start with supported namespace"))
	}

	doc, err := o.resolver.ResolveDocument(id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, common.NewHTTPError(http.StatusNotFound, errors.New("document not found"))
		}
		return nil, common.NewHTTPError(http.StatusInternalServerError, err)
	}

	return doc, nil
}

var getID = func(req *http.Request) string {
	return mux.Vars(req)["id"]
}
