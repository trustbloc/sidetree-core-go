/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

// Header is the operation header
type Header struct {
	Alg       string        `json:"alg"`
	Kid       string        `json:"kid"`
	Operation OperationType `json:"operation"`
}
