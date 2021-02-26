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

func TestNewTransformer(t *testing.T) {
	require.NotNil(t, New())
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
