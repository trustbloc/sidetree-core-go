/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package patchvalidator

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

func TestValidate(t *testing.T) {
	t.Run("success - add public keys", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(addPublicKeysPatch))
		require.NoError(t, err)

		err = Validate(p)
		require.NoError(t, err)
	})
	t.Run("success - remove public keys", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(removePublicKeysPatch))
		require.NoError(t, err)

		err = Validate(p)
		require.NoError(t, err)
	})
	t.Run("success - add service endpoints", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(addServiceEndpoints))
		require.NoError(t, err)

		err = Validate(p)
		require.NoError(t, err)
	})
	t.Run("success - remove service endpoints", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(removeServiceEndpoints))
		require.NoError(t, err)

		err = Validate(p)
		require.NoError(t, err)
	})
	t.Run("success - ietf patch", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(ietfPatch))
		require.NoError(t, err)

		err = Validate(p)
		require.NoError(t, err)
	})
	t.Run("success - replace patch", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(replacePatch))
		require.NoError(t, err)

		err = Validate(p)
		require.NoError(t, err)
	})
	t.Run("error - patch not supported", func(t *testing.T) {
		p := make(patch.Patch)
		p[patch.ActionKey] = "invalid"

		err := Validate(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "action 'invalid' is not supported")
	})
}
