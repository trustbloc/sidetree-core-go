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
type MethodMetadata map[string]interface{}

const (
	// UpdateCommitmentProperty is update commitment key.
	UpdateCommitmentProperty = "updateCommitment"

	// RecoveryCommitmentProperty is recovery commitment key.
	RecoveryCommitmentProperty = "recoveryCommitment"

	// PublishedProperty is published key.
	PublishedProperty = "published"

	// CanonicalIDProperty is canonical ID key.
	CanonicalIDProperty = "canonicalID"
)
