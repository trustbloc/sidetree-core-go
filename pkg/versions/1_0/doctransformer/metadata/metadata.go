/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metadata

import (
	"errors"
	"sort"
	"time"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
)

// Metadata is responsible for creating document metadata.
type Metadata struct {
	includePublishedOperations   bool
	includeUnpublishedOperations bool
}

// Option is a metadata instance option.
type Option func(opts *Metadata)

// New creates a new metadata transformer.
func New(opts ...Option) *Metadata {
	md := &Metadata{}

	// apply options
	for _, opt := range opts {
		opt(md)
	}

	return md
}

// WithIncludePublishedOperations sets optional include published operations flag.
func WithIncludePublishedOperations(enabled bool) Option {
	return func(opts *Metadata) {
		opts.includePublishedOperations = enabled
	}
}

// WithIncludeUnpublishedOperations sets optional include unpublished operations flag.
func WithIncludeUnpublishedOperations(enabled bool) Option {
	return func(opts *Metadata) {
		opts.includeUnpublishedOperations = enabled
	}
}

// CreateDocumentMetadata will create document metadata.
func (t *Metadata) CreateDocumentMetadata(rm *protocol.ResolutionModel, info protocol.TransformationInfo) (document.Metadata, error) { // nolint: funlen,gocyclo
	if rm == nil || rm.Doc == nil {
		return nil, errors.New("resolution model is required for creating document metadata")
	}

	if info == nil {
		return nil, errors.New("transformation info is required for creating document metadata")
	}

	published, ok := info[document.PublishedProperty]
	if !ok {
		return nil, errors.New("published is required for creating document metadata")
	}

	methodMetadata := make(document.Metadata)
	methodMetadata[document.PublishedProperty] = published

	if rm.RecoveryCommitment != "" {
		methodMetadata[document.RecoveryCommitmentProperty] = rm.RecoveryCommitment
	}

	if rm.UpdateCommitment != "" {
		methodMetadata[document.UpdateCommitmentProperty] = rm.UpdateCommitment
	}

	if rm.AnchorOrigin != nil {
		methodMetadata[document.AnchorOriginProperty] = rm.AnchorOrigin
	}

	if t.includeUnpublishedOperations && len(rm.UnpublishedOperations) > 0 {
		methodMetadata[document.UnpublishedOperationsProperty] = getUnpublishedOperations(rm.UnpublishedOperations)
	}

	if t.includePublishedOperations && len(rm.PublishedOperations) > 0 {
		methodMetadata[document.PublishedOperationsProperty] = getPublishedOperations(rm.PublishedOperations)
	}

	docMetadata := make(document.Metadata)
	docMetadata[document.MethodProperty] = methodMetadata

	if rm.Deactivated {
		docMetadata[document.DeactivatedProperty] = rm.Deactivated
	}

	canonicalID, ok := info[document.CanonicalIDProperty]
	if ok {
		docMetadata[document.CanonicalIDProperty] = canonicalID
	}

	equivalentID, ok := info[document.EquivalentIDProperty]
	if ok {
		docMetadata[document.EquivalentIDProperty] = equivalentID
	}

	if published.(bool) {
		docMetadata[document.CreatedProperty] = time.Unix(int64(rm.CreatedTime), 0).UTC().Format(time.RFC3339)
	}

	if rm.VersionID != "" {
		docMetadata[document.VersionIDProperty] = rm.VersionID
		if rm.UpdatedTime > 0 {
			docMetadata[document.UpdatedProperty] = time.Unix(int64(rm.UpdatedTime), 0).UTC().Format(time.RFC3339)
		}
	}

	return docMetadata, nil
}

func sortOperations(ops []*operation.AnchoredOperation) {
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].TransactionTime < ops[j].TransactionTime {
			return true
		}

		return ops[i].TransactionNumber < ops[j].TransactionNumber
	})
}

// remove duplicate published operations and then sort them by transaction (anchoring) time.
func getPublishedOperations(ops []*operation.AnchoredOperation) []*PublishedOperation {
	sortOperations(ops)

	uniqueOps := make(map[string]bool)

	var publishedOps []*PublishedOperation

	for _, op := range ops {
		_, ok := uniqueOps[op.CanonicalReference]
		if !ok {
			publishedOps = append(publishedOps,
				&PublishedOperation{
					Type:                 op.Type,
					OperationRequest:     op.OperationRequest,
					TransactionTime:      op.TransactionTime,
					TransactionNumber:    op.TransactionNumber,
					ProtocolVersion:      op.ProtocolVersion,
					CanonicalReference:   op.CanonicalReference,
					EquivalentReferences: op.EquivalentReferences,
					AnchorOrigin:         op.AnchorOrigin,
				})

			uniqueOps[op.CanonicalReference] = true
		}
	}

	return publishedOps
}

// sort unpublished operations by request time.
func getUnpublishedOperations(ops []*operation.AnchoredOperation) []*UnpublishedOperation {
	sortOperations(ops)

	unpublishedOps := make([]*UnpublishedOperation, len(ops))

	for i, op := range ops {
		unpublishedOps[i] = &UnpublishedOperation{
			Type:             op.Type,
			OperationRequest: op.OperationRequest,
			TransactionTime:  op.TransactionTime,
			ProtocolVersion:  op.ProtocolVersion,
			AnchorOrigin:     op.AnchorOrigin,
		}
	}

	return unpublishedOps
}

// PublishedOperation defines an published operation for metadata. It is a subset of anchored operation.
type PublishedOperation struct {

	// Type defines operation type.
	Type operation.Type `json:"type"`

	// OperationRequest is the original operation request.
	OperationRequest []byte `json:"operation"`

	// TransactionTime is the logical anchoring time.
	TransactionTime uint64 `json:"transactionTime"`

	// TransactionNumber is the transaction number of the transaction this operation was batched within.
	TransactionNumber uint64 `json:"transactionNumber"`

	// ProtocolVersion is the genesis time of the protocol that was used for this operation.
	ProtocolVersion uint64 `json:"protocolVersion"`

	// CanonicalReference contains canonical reference that applies to this operation.
	CanonicalReference string `json:"canonicalReference,omitempty"`

	// EquivalenceReferences contains equivalence reference that applies to this operation.
	EquivalentReferences []string `json:"equivalentReferences,omitempty"`

	// AnchorOrigin is anchor origin
	AnchorOrigin interface{} `json:"anchorOrigin,omitempty"`
}

// UnpublishedOperation defines an un-published operation for metadata. It is a subset of anchored operation.
type UnpublishedOperation struct {

	// Type defines operation type.
	Type operation.Type `json:"type"`

	// OperationRequest is the original operation request.
	OperationRequest []byte `json:"operation"`

	// TransactionTime is the logical anchoring time.
	TransactionTime uint64 `json:"transactionTime"`

	// ProtocolVersion is the genesis time of the protocol that was used for this operation.
	ProtocolVersion uint64 `json:"protocolVersion"`

	// AnchorOrigin is anchor origin.
	AnchorOrigin interface{} `json:"anchorOrigin,omitempty"`
}
