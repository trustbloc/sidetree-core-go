package signutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	internal "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
)

func TestSignModel(t *testing.T) {
	t.Run("marshal error", func(t *testing.T) {
		ch := make(chan int)
		request, err := SignModel(ch, nil)
		require.Error(t, err)
		require.Empty(t, request)
		require.Contains(t, err.Error(), "unsupported type: chan int")
	})
	t.Run("success", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer := ecsigner.New(privateKey, "ES256", "key-1")

		test := struct {
			message string
		}{
			message: "test",
		}

		request, err := SignModel(test, signer)
		require.NoError(t, err)
		require.NotEmpty(t, request)
	})
}

func TestSignPayload(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwk, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		signer := ecsigner.New(privateKey, "ES256", "key-1")

		message := []byte("test")
		jwsSignature, err := SignPayload(message, signer)
		require.NoError(t, err)
		require.NotEmpty(t, jwsSignature)

		_, err = internal.VerifyJWS(jwsSignature, jwk)
		require.NoError(t, err)
	})
	t.Run("signing algorithm required", func(t *testing.T) {
		signer := ecsigner.New(privateKey, "", "kid")

		jws, err := SignPayload([]byte("test"), signer)
		require.Error(t, err)
		require.Empty(t, jws)
		require.Contains(t, err.Error(), "signing algorithm is required")
	})
	t.Run("kid is required", func(t *testing.T) {
		jws, err := SignPayload([]byte(""), NewMockSigner(errors.New("test error"), true))
		require.Error(t, err)
		require.Empty(t, jws)
		require.Contains(t, err.Error(), "test error")
	})
}

// MockSigner implements signer interface.
type MockSigner struct {
	Recovery bool
	Err      error
}

// NewMockSigner creates new mock signer (default to recovery signer).
func NewMockSigner(err error, recovery bool) *MockSigner {
	return &MockSigner{Err: err, Recovery: recovery}
}

// Headers provides required JWS protected headers. It provides information about signing key and algorithm.
func (ms *MockSigner) Headers() jws.Headers {
	headers := make(jws.Headers)
	headers[jws.HeaderAlgorithm] = "alg"
	if !ms.Recovery {
		headers[jws.HeaderKeyID] = "kid"
	}

	return headers
}

// Sign signs msg and returns mock signature value.
func (ms *MockSigner) Sign(msg []byte) ([]byte, error) {
	if ms.Err != nil {
		return nil, ms.Err
	}

	return []byte("signature"), nil
}
