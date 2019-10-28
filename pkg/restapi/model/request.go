/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

// Request is the document request
type Request struct {
	Header    *Header `json:"header"`
	Payload   string  `json:"payload"`
	Signature string  `json:"signature"`
}
