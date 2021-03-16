/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package doctransformer

import (
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
)

// CreateDocumentMetadata will create document metadata.
func CreateDocumentMetadata(rm *protocol.ResolutionModel, info protocol.TransformationInfo) (document.Metadata, error) { // nolint: gocyclo
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

	return docMetadata, nil
}
