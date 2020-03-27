/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

// JWS contains JWS signature
type JWS struct {
	// JWS header
	// Required: true
	Protected *Header `json:"protected"`

	// JWS encoded JSON object
	// Required: true
	Payload string `json:"payload"`

	// JWS signature
	// Required: true
	Signature string `json:"signature"`
}

// Header is the operation header
// swagger:model Header
type Header struct {
	// alg
	// Required: true
	Alg string `json:"alg"`

	// kid
	// Required: true
	Kid string `json:"kid"`
}
