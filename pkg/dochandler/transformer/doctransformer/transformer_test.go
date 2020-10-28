/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package doctransformer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
)

func TestNewTransformer(t *testing.T) {
	require.NotNil(t, New())
}

func TestTransformDocument(t *testing.T) {
	doc, err := document.FromBytes(validDoc)
	require.NoError(t, err)

	transformer := getDefaultTransformer()

	// there is no transformation for generic doc for now
	result, err := transformer.TransformDocument(doc)
	require.NoError(t, err)
	require.Equal(t, doc, result.Document)

	// test document with operation keys
	doc, err = document.FromBytes([]byte(validDocWithOpsKeys))
	require.NoError(t, err)
	result, err = transformer.TransformDocument(doc)
	require.NoError(t, err)
	require.Equal(t, doc, result.Document)
}

func getDefaultTransformer() *Transformer {
	return New()
}

var validDoc = []byte(`{ "name": "John Smith" }`)

const validDocWithOpsKeys = `
{
  "id" : "doc:method:abc",
  "other": [
    {
      "name": "name"
    }
  ]
}`
