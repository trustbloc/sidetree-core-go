/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package doctransformer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
)

func TestPopulateDocumentMetadata(t *testing.T) {
	doc, err := document.FromBytes(validDoc)
	require.NoError(t, err)

	internal := &protocol.ResolutionModel{Doc: doc, RecoveryCommitment: "recovery", UpdateCommitment: "update", AnchorOrigin: "origin.com"}

	t.Run("success - all info present", func(t *testing.T) {
		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = "did:abc:123"
		info[document.PublishedProperty] = true
		info[document.CanonicalIDProperty] = "canonical"
		info[document.EquivalentIDProperty] = []string{"equivalent"}

		documentMetadata, err := CreateDocumentMetadata(internal, info)
		require.NoError(t, err)

		require.Empty(t, documentMetadata[document.DeactivatedProperty])
		require.Equal(t, "canonical", documentMetadata[document.CanonicalIDProperty])
		require.NotEmpty(t, documentMetadata[document.EquivalentIDProperty])

		methodMetadataEntry, ok := documentMetadata[document.MethodProperty]
		require.True(t, ok)
		methodMetadata, ok := methodMetadataEntry.(document.Metadata)
		require.True(t, ok)

		require.Equal(t, true, methodMetadata[document.PublishedProperty])
		require.Equal(t, "recovery", methodMetadata[document.RecoveryCommitmentProperty])
		require.Equal(t, "update", methodMetadata[document.UpdateCommitmentProperty])
	})

	t.Run("success - deactivated, commitments empty", func(t *testing.T) {
		internal2 := &protocol.ResolutionModel{Doc: doc, Deactivated: true}

		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = "did:abc:123"
		info[document.PublishedProperty] = true
		info[document.CanonicalIDProperty] = "canonical"

		documentMetadata, err := CreateDocumentMetadata(internal2, info)
		require.NoError(t, err)

		require.Equal(t, true, documentMetadata[document.DeactivatedProperty])
		require.Equal(t, "canonical", documentMetadata[document.CanonicalIDProperty])
		require.Empty(t, documentMetadata[document.EquivalentIDProperty])

		methodMetadataEntry, ok := documentMetadata[document.MethodProperty]
		require.True(t, ok)
		methodMetadata, ok := methodMetadataEntry.(document.Metadata)
		require.True(t, ok)

		require.Equal(t, true, methodMetadata[document.PublishedProperty])
		require.Empty(t, methodMetadata[document.RecoveryCommitmentProperty])
		require.Empty(t, methodMetadata[document.UpdateCommitmentProperty])
	})

	t.Run("error - internal document is missing", func(t *testing.T) {
		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = "doc:abc:xyz"
		info[document.PublishedProperty] = true

		result, err := CreateDocumentMetadata(nil, info)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "resolution model is required for creating document metadata")
	})

	t.Run("error - transformation info is missing", func(t *testing.T) {
		result, err := CreateDocumentMetadata(internal, nil)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "transformation info is required for creating document metadata")
	})

	t.Run("error - transformation info is missing published", func(t *testing.T) {
		info := make(protocol.TransformationInfo)

		result, err := CreateDocumentMetadata(internal, info)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "published is required for creating document metadata")
	})
}

var validDoc = []byte(`{ "name": "John Smith" }`)
