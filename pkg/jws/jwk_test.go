package jws

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	t.Run("success ", func(t *testing.T) {
		jwk := JWK{
			Kty: "kty",
			Crv: "crv",
			X:   "x",
		}

		err := jwk.Validate()
		require.NoError(t, err)
	})

	t.Run("missing kty", func(t *testing.T) {
		jwk := JWK{
			Kty: "",
			Crv: "crv",
			X:   "x",
		}

		err := jwk.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "kty is missing")
	})

	t.Run("missing crv", func(t *testing.T) {
		jwk := JWK{
			Kty: "kty",
			X:   "x",
		}

		err := jwk.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "crv is missing")
	})

	t.Run("missing x", func(t *testing.T) {
		jwk := JWK{
			Kty: "kty",
			Crv: "crv",
		}

		err := jwk.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "x is missing")
	})
}
