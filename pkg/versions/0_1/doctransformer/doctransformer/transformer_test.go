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
		require.Equal(t, true, result.MethodMetadata[document.PublishedProperty])
		require.Equal(t, "recovery", result.MethodMetadata[document.RecoveryCommitmentProperty])
		require.Equal(t, "update", result.MethodMetadata[document.UpdateCommitmentProperty])
		require.Empty(t, result.MethodMetadata[document.CanonicalIDProperty])
	})

	t.Run("success - with canonical ID", func(t *testing.T) {
		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = "did:abc:123"
		info[document.PublishedProperty] = true
		info[document.CanonicalIDProperty] = "canonical"

		result, err := transformer.TransformDocument(internal, info)
		require.NoError(t, err)
		require.Equal(t, "did:abc:123", result.Document[document.IDProperty])
		require.Equal(t, true, result.MethodMetadata[document.PublishedProperty])
		require.Equal(t, "recovery", result.MethodMetadata[document.RecoveryCommitmentProperty])
		require.Equal(t, "update", result.MethodMetadata[document.UpdateCommitmentProperty])
		require.Equal(t, "canonical", result.MethodMetadata[document.CanonicalIDProperty])
	})

	t.Run("error - internal document is missing", func(t *testing.T) {
		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = "doc:abc:xyz"
		info[document.PublishedProperty] = true

		result, err := transformer.TransformDocument(nil, info)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "resolution model is required for document transformation")
	})

	t.Run("error - transformation info is missing", func(t *testing.T) {
		result, err := transformer.TransformDocument(internal, nil)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "transformation info is required for document transformation")
	})

	t.Run("error - transformation info is missing id", func(t *testing.T) {
		info := make(protocol.TransformationInfo)
		info[document.PublishedProperty] = true

		result, err := transformer.TransformDocument(internal, info)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "id is required for document transformation")
	})

	t.Run("error - transformation info is missing published", func(t *testing.T) {
		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = "doc:abc:xyz"

		result, err := transformer.TransformDocument(internal, info)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "published is required for document transformation")
	})
}

var validDoc = []byte(`{ "name": "John Smith" }`)
