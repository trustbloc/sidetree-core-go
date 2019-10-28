/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

// Response is the document response
// swagger:model docResponse
type Response struct {
	// in:body
	Body interface{} `json:"body,omitempty"`
}
