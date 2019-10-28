/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

// HTTPError holds an error and an HTTP status code
type HTTPError struct {
	err    error
	status int
}

// NewHTTPError returns a new HTTPError
func NewHTTPError(status int, err error) *HTTPError {
	return &HTTPError{
		err:    err,
		status: status,
	}
}

// Error returns the error string
func (e *HTTPError) Error() string {
	return e.err.Error()
}

// Status returns the status code
func (e *HTTPError) Status() int {
	return e.status
}
