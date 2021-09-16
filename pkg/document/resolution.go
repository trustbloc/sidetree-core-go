/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

// ResolutionResult describes resolution result.
type ResolutionResult struct {
	Context          string   `json:"@context"`
	Document         Document `json:"didDocument"`
	DocumentMetadata Metadata `json:"didDocumentMetadata,omitempty"`
}

// Metadata can contains various metadata such as document metadata and method metadata..
type Metadata map[string]interface{}

const (
	// UpdateCommitmentProperty is update commitment key.
	UpdateCommitmentProperty = "updateCommitment"

	// RecoveryCommitmentProperty is recovery commitment key.
	RecoveryCommitmentProperty = "recoveryCommitment"

	// PublishedProperty is published key.
	PublishedProperty = "published"

	// DeactivatedProperty is deactivated flag key.
	DeactivatedProperty = "deactivated"

	// AnchorOriginProperty is anchor origin key.
	AnchorOriginProperty = "anchorOrigin"

	// CanonicalIDProperty is canonical ID key.
	CanonicalIDProperty = "canonicalId"

	// EquivalentIDProperty is equivalent ID array.
	EquivalentIDProperty = "equivalentId"

	// MethodProperty is used for method metadata within did document metadata.
	MethodProperty = "method"

	// UnpublishedOperationsProperty holds unpublished did operations.
	UnpublishedOperationsProperty = "unpublishedOperations"

	// PublishedOperationsProperty holds published did operations.
	PublishedOperationsProperty = "publishedOperations"
)
