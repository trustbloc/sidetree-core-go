/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

func TestApplyPatches(t *testing.T) {
	t.Run("action not supported", func(t *testing.T) {
		replace := patch.NewReplacePatch("{}")
		replace["action"] = "invalid"

		doc, err := ApplyPatches(nil, []patch.Patch{replace})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "not supported")
	})
}

func TestApplyPatches_Replace(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		replace := patch.NewReplacePatch(testDoc)

		doc, err := ApplyPatches(nil, []patch.Patch{replace})
		require.NoError(t, err)
		require.NotNil(t, doc)
	})
}

func TestApplyPatches_JSON(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		replace := patch.NewReplacePatch(testDoc)
		doc, err := ApplyPatches(nil, []patch.Patch{replace})

		ietf := patch.NewJSONPatch(patches)
		doc, err = ApplyPatches(doc, []patch.Patch{ietf})
		require.NoError(t, err)
		require.NotNil(t, doc)
	})
	t.Run("invalid json", func(t *testing.T) {
		replace := patch.NewReplacePatch(testDoc)
		doc, err := ApplyPatches(nil, []patch.Patch{replace})

		ietf := patch.NewJSONPatch("invalid")
		doc, err = ApplyPatches(doc, []patch.Patch{ietf})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "invalid character")
	})
	t.Run("invalid operation", func(t *testing.T) {
		replace := patch.NewReplacePatch(testDoc)
		doc, err := ApplyPatches(nil, []patch.Patch{replace})

		ietf := patch.NewJSONPatch(invalidPatches)
		doc, err = ApplyPatches(doc, []patch.Patch{ietf})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "Unexpected kind: invalid")
	})
}

const invalidPatches = `[
	{
      "op": "invalid",
      "path": "/service",
      "value": "new value"
	}
]`

const patches = `[
	{
      "op": "replace",
      "path": "/service",
      "value": "new value"
	}
]`

const testDoc = `{
  "service": [{
    "id":"#vcs",
    "type": "VerifiableCredentialService",
    "serviceEndpoint": "https://example.com/vc/"
  }]
}`
