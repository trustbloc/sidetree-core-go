/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

// Header is the operation header
// swagger:model Header
type Header struct {
	// alg
	// Required: true
	Alg string `json:"alg"`

	// kid
	// Required: true
	Kid string `json:"kid"`

	// operation
	// Required: true
	Operation OperationType `json:"operation"`
}
