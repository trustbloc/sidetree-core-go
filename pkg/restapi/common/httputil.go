/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"encoding/json"
	"net/http"
)

// WriteResponse writes a response to the response writer
func WriteResponse(rw http.ResponseWriter, status int, v interface{}) {
	rw.Header().Set("Content-Type", "application/did+ld+json")
	rw.WriteHeader(status)
	err := json.NewEncoder(rw).Encode(v)
	if err != nil {
		logger.Errorf("Unable to write response: %s", err)
	}
}

// WriteError writes an error to the response writer
func WriteError(rw http.ResponseWriter, status int, err error) {
	rw.Header().Set("Content-Type", "text/plain")
	rw.WriteHeader(status)
	_, e := rw.Write([]byte(err.Error()))
	if e != nil {
		logger.Errorf("Unable to write response: %s", e)
	}
}
