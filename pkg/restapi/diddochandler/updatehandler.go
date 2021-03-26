/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diddochandler

import (
	"net/http"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/dochandler"
)

// UpdateHandler handles the creation and update of DID documents.
type UpdateHandler struct {
	*handler
}

// NewUpdateHandler returns a newHandler DID document update handler.
func NewUpdateHandler(basePath string, processor dochandler.Processor, pc protocol.Client) *UpdateHandler {
	return &UpdateHandler{
		handler: newHandler(
			basePath,
			http.MethodPost,
			dochandler.NewUpdateHandler(processor, pc).Update,
		),
	}
}
