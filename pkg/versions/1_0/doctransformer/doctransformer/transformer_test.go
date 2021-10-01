/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package doctransformer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/doctransformer/metadata"
)

const testID = "doc:abc:123"

func TestNewTransformer(t *testing.T) {
	transformer := New()
	require.NotNil(t, transformer)
	require.Equal(t, false, transformer.includePublishedOperations)
	require.Equal(t, false, transformer.includeUnpublishedOperations)

	transformer = New(WithIncludeUnpublishedOperations(true), WithIncludePublishedOperations(true))
	require.NotNil(t, transformer)
	require.Equal(t, true, transformer.includePublishedOperations)
	require.Equal(t, true, transformer.includeUnpublishedOperations)
}

func TestTransformDocument(t *testing.T) {
	doc, err := document.FromBytes(validDoc)
	require.NoError(t, err)

	transformer := New()

	internal := &protocol.ResolutionModel{Doc: doc, RecoveryCommitment: "recovery", UpdateCommitment: "update"}

	t.Run("success", func(t *testing.T) {
		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = "did:abc:123"
		info[document.PublishedProperty] = true

		result, err := transformer.TransformDocument(internal, info)
		require.NoError(t, err)
		require.Equal(t, "did:abc:123", result.Document[document.IDProperty])

		methodMetadataEntry, ok := result.DocumentMetadata[document.MethodProperty]
		require.True(t, ok)
		methodMetadata, ok := methodMetadataEntry.(document.Metadata)
		require.True(t, ok)

		require.Equal(t, true, methodMetadata[document.PublishedProperty])
		require.Equal(t, "recovery", methodMetadata[document.RecoveryCommitmentProperty])
		require.Equal(t, "update", methodMetadata[document.UpdateCommitmentProperty])
	})

	t.Run("success - with canonical, equivalent ID", func(t *testing.T) {
		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = "did:abc:123"
		info[document.PublishedProperty] = true
		info[document.CanonicalIDProperty] = "canonical"
		info[document.EquivalentIDProperty] = []string{"equivalent"}

		result, err := transformer.TransformDocument(internal, info)
		require.NoError(t, err)
		require.Equal(t, "did:abc:123", result.Document[document.IDProperty])

		methodMetadataEntry, ok := result.DocumentMetadata[document.MethodProperty]
		require.True(t, ok)
		methodMetadata, ok := methodMetadataEntry.(document.Metadata)
		require.True(t, ok)

		require.Equal(t, true, methodMetadata[document.PublishedProperty])
		require.Equal(t, "recovery", methodMetadata[document.RecoveryCommitmentProperty])
		require.Equal(t, "update", methodMetadata[document.UpdateCommitmentProperty])

		require.Equal(t, "canonical", result.DocumentMetadata[document.CanonicalIDProperty])
		require.NotEmpty(t, result.DocumentMetadata[document.EquivalentIDProperty])
	})

	t.Run("success - include operations (published/unpublished)", func(t *testing.T) {
		trans := New(
			WithIncludePublishedOperations(true),
			WithIncludeUnpublishedOperations(true))

		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = testID
		info[document.PublishedProperty] = true

		publishedOps := []*operation.AnchoredOperation{
			{Type: "create", UniqueSuffix: "suffix", CanonicalReference: "ref1"},
			{Type: "update", UniqueSuffix: "suffix", CanonicalReference: "ref2"},
		}

		unpublishedOps := []*operation.AnchoredOperation{
			{Type: "update", UniqueSuffix: "suffix"},
		}

		rm := &protocol.ResolutionModel{
			Doc:                   doc,
			RecoveryCommitment:    "recovery",
			UpdateCommitment:      "update",
			PublishedOperations:   publishedOps,
			UnpublishedOperations: unpublishedOps,
		}

		result, err := trans.TransformDocument(rm, info)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, testID, result.Document[document.IDProperty])

		methodMetadataEntry, ok := result.DocumentMetadata[document.MethodProperty]
		require.True(t, ok)
		methodMetadata, ok := methodMetadataEntry.(document.Metadata)
		require.True(t, ok)

		require.Equal(t, true, methodMetadata[document.PublishedProperty])
		require.Equal(t, "recovery", methodMetadata[document.RecoveryCommitmentProperty])
		require.Equal(t, "update", methodMetadata[document.UpdateCommitmentProperty])

		require.Equal(t, 2, len(methodMetadata[document.PublishedOperationsProperty].([]*metadata.PublishedOperation)))
		require.Equal(t, 1, len(methodMetadata[document.UnpublishedOperationsProperty].([]*metadata.UnpublishedOperation)))
	})

	t.Run("error - internal document is missing", func(t *testing.T) {
		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = "doc:abc:xyz"
		info[document.PublishedProperty] = true

		result, err := transformer.TransformDocument(nil, info)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "resolution model is required for creating document metadata")
	})

	t.Run("error - transformation info is missing", func(t *testing.T) {
		result, err := transformer.TransformDocument(internal, nil)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "transformation info is required for creating document metadata")
	})

	t.Run("error - transformation info is missing id", func(t *testing.T) {
		info := make(protocol.TransformationInfo)
		info[document.PublishedProperty] = true

		result, err := transformer.TransformDocument(internal, info)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "id is required for document transformation")
	})
}

var validDoc = []byte(`{ "name": "John Smith" }`)
