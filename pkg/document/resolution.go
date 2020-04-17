/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

import "github.com/trustbloc/sidetree-core-go/pkg/jws"

// ResolutionResult describes resolution result
type ResolutionResult struct {
	Context        string         `json:"@context"`
	Document       Document       `json:"didDocument"`
	MethodMetadata MethodMetadata `json:"methodMetadata"`
}

// MethodMetadata contains document metadata
type MethodMetadata struct {
	OperationPublicKeys []PublicKey `json:"operationPublicKeys,omitempty"`
	RecoveryKey         *jws.JWK    `json:"recoveryKey,omitempty"`
	Published           bool        `json:"published"`
}
