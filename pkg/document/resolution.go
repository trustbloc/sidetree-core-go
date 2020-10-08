/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

// ResolutionResult describes resolution result.
type ResolutionResult struct {
	Context        string         `json:"@context"`
	Document       Document       `json:"didDocument"`
	MethodMetadata MethodMetadata `json:"methodMetadata"`
}

// MethodMetadata contains document metadata.
type MethodMetadata struct {
	UpdateCommitment   string `json:"updateCommitment"`
	RecoveryCommitment string `json:"recoveryCommitment"`
	Published          bool   `json:"published"`
}
