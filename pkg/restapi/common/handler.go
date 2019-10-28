/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

// HTTPRequestHandler is an HTTP handler
type HTTPRequestHandler func(http.ResponseWriter, *http.Request)

// HTTPHandler is a HTTP handler descriptor containing the context path, method, and request handler
type HTTPHandler interface {
	Path() string
	Method() string
	Handler() HTTPRequestHandler
}
