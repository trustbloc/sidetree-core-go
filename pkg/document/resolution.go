/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

import "github.com/trustbloc/sidetree-core-go/pkg/api/operation"

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

	// CreatedProperty is the time that document was created - anchoring time of first successful create operation.
	CreatedProperty = "created"

	// UpdatedProperty is the time of last document update - anchoring time of update/recover operations.
	UpdatedProperty = "updated"

	// VersionIDProperty is version ID key.
	VersionIDProperty = "versionId"

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

// ResolutionOption is an option for specifying the resolution options for various resolvers.
type ResolutionOption func(opts *ResolutionOptions)

// ResolutionOptions represent resolution options.
type ResolutionOptions struct {
	AdditionalOperations []*operation.AnchoredOperation
	VersionID            string
	VersionTime          string
}

// WithAdditionalOperations sets the additional operations to be used in a Resolve call.
func WithAdditionalOperations(additionalOperations []*operation.AnchoredOperation) ResolutionOption {
	return func(opts *ResolutionOptions) {
		if len(additionalOperations) > 0 {
			opts.AdditionalOperations = additionalOperations
		}
	}
}

// WithVersionID sets the version ID to be used in a Resolve call.
func WithVersionID(versionID string) ResolutionOption {
	return func(opts *ResolutionOptions) {
		opts.VersionID = versionID
	}
}

// WithVersionTime sets the version time to be used in a Resolve call.
func WithVersionTime(versionTime string) ResolutionOption {
	return func(opts *ResolutionOptions) {
		opts.VersionTime = versionTime
	}
}

// GetResolutionOptions returns resolution options.
func GetResolutionOptions(opts ...ResolutionOption) (ResolutionOptions, error) {
	options := ResolutionOptions{}

	for _, option := range opts {
		if option != nil {
			option(&options)
		}
	}

	return options, nil
}
