package patchvalidator

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

func TestAddAlsoKnowAsValidator(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(addAlsoKnownAs))
		require.NoError(t, err)

		err = NewAlsoKnownAsValidator().Validate(p)
		require.NoError(t, err)
	})
	t.Run("error - missing action", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(addAlsoKnownAs))
		require.NoError(t, err)

		delete(p, patch.ActionKey)
		err = NewAlsoKnownAsValidator().Validate(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "patch is missing action key")
	})
	t.Run("error - missing uris", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(addAlsoKnownAs))
		require.NoError(t, err)

		delete(p, patch.UrisKey)
		err = NewAlsoKnownAsValidator().Validate(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "add-also-known-as patch is missing key: uris")
	})
	t.Run("error - uris value is not expected type", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(addAlsoKnownAs))
		require.NoError(t, err)

		p[patch.UrisKey] = []int{123}
		err = NewAlsoKnownAsValidator().Validate(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "add-also-known-as: expected array of interfaces")
	})
	t.Run("error - uri is not valid", func(t *testing.T) {
		p, err := patch.NewAddAlsoKnownAs(`[":abc"]`)
		require.NoError(t, err)

		err = NewAlsoKnownAsValidator().Validate(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "add-also-known-as: validate URIs: failed to parse URI:")
	})
	t.Run("error - duplicate URI", func(t *testing.T) {
		p, err := patch.NewAddAlsoKnownAs(`["https://abc.com", "https://abc.com"]`)
		require.NoError(t, err)

		err = NewAlsoKnownAsValidator().Validate(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "add-also-known-as: validate URIs: duplicate uri: https://abc.com")
	})
}

const addAlsoKnownAs = `{
  "action": "add-also-known-as",
  "uris": ["did:abc:123", "https://other.com"]
}`

const removeAlsoKnownAs = `{
  "action": "remove-also-known-as",
  "uris": ["did:abc:123"]
}`
