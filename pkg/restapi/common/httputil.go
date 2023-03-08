/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"encoding/json"
	"net/http"

	"github.com/trustbloc/logutil-go/pkg/log"
)

// WriteResponse writes a response to the response writer.
func WriteResponse(rw http.ResponseWriter, status int, v interface{}) {
	rw.Header().Set("Content-Type", "application/did+ld+json")
	rw.WriteHeader(status)
	err := json.NewEncoder(rw).Encode(v)
	if err != nil {
		log.WriteResponseBodyError(logger, err)
	}
}

// WriteError writes an error to the response writer.
func WriteError(rw http.ResponseWriter, status int, err error) {
	if status >= http.StatusInternalServerError {
		logger.Warn("Returning error status", log.WithHTTPStatus(status), log.WithError(err))
	} else {
		logger.Debug("Returning error status", log.WithHTTPStatus(status), log.WithError(err))
	}

	rw.Header().Set("Content-Type", "text/plain")
	rw.WriteHeader(status)
	_, e := rw.Write([]byte(err.Error()))
	if e != nil {
		log.WriteResponseBodyError(logger, e)
	}
}
