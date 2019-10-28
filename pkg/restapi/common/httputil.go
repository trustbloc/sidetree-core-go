/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"encoding/json"
	"net/http"

	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// WriteResponse writes a response to the response writer
func WriteResponse(rw http.ResponseWriter, status int, v interface{}) {
	rw.WriteHeader(status)
	err := json.NewEncoder(rw).Encode(v)
	if err != nil {
		logger.Errorf("Unable to encode response: %s", err)
	}
}

// WriteError writes an error to the response writer
func WriteError(rw http.ResponseWriter, status int, err error) {
	WriteResponse(rw, status,
		&model.Error{
			Message: err.Error(),
		},
	)
}
