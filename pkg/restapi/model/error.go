/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

// Error contains the error message
// swagger:response error
type Error struct {
	// message
	// Required: true
	Message string `json:"message"`
}
