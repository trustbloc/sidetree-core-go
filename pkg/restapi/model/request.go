/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

// Request is the document request
// swagger:model docRequest
type Request struct {
	// header
	// Required: true
	Header *Header `json:"header"`

	// payload
	// Required: true
	Payload string `json:"payload"`

	// signature
	// Required: true
	Signature string `json:"signature"`
}
