/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jws

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/edsigner"
)

func TestHeaders_GetKeyID(t *testing.T) {
	kid, ok := jws.Headers{"kid": "key id"}.KeyID()
	require.True(t, ok)
	require.Equal(t, "key id", kid)

	kid, ok = jws.Headers{"kid": 777}.KeyID()
	require.False(t, ok)
	require.Empty(t, kid)

	kid, ok = jws.Headers{}.KeyID()
	require.False(t, ok)
	require.Empty(t, kid)
}

func TestHeaders_GetAlgorithm(t *testing.T) {
	kid, ok := jws.Headers{"alg": "EdDSA"}.Algorithm()
	require.True(t, ok)
	require.Equal(t, "EdDSA", kid)

	kid, ok = jws.Headers{"alg": 777}.Algorithm()
	require.False(t, ok)
	require.Empty(t, kid)

	kid, ok = jws.Headers{}.Algorithm()
	require.False(t, ok)
	require.Empty(t, kid)
}

func TestJSONWebSignature_SerializeCompact(t *testing.T) {
	headers := jws.Headers{"alg": "EdSDA", "typ": "JWT"}
	payload := []byte("payload")

	newJWS, err := NewJWS(headers, nil, payload,
		&testSigner{
			headers:   jws.Headers{"alg": "dummy"},
			signature: []byte("signature"),
		})
	require.NoError(t, err)

	jwsCompact, err := newJWS.SerializeCompact(false)
	require.NoError(t, err)
	require.NotEmpty(t, jwsCompact)

	// b64=false
	newJWS, err = NewJWS(headers, nil, payload,
		&testSigner{
			headers:   jws.Headers{"alg": "dummy", "b64": false},
			signature: []byte("signature"),
		})
	require.NoError(t, err)

	jwsCompact, err = newJWS.SerializeCompact(false)
	require.NoError(t, err)
	require.NotEmpty(t, jwsCompact)

	// signer error
	newJWS, err = NewJWS(headers, nil, payload,
		&testSigner{
			headers: jws.Headers{"alg": "dummy"},
			err:     errors.New("signer error"),
		})
	require.Error(t, err)
	require.Contains(t, err.Error(), "sign JWS verification data")
	require.Nil(t, newJWS)

	// no alg defined
	newJWS, err = NewJWS(jws.Headers{}, nil, payload,
		&testSigner{
			headers: jws.Headers{},
		})
	require.Error(t, err)
	require.Contains(t, err.Error(), "alg JWS header is not defined")
	require.Nil(t, newJWS)

	// jose headers marshalling error
	newJWS, err = NewJWS(jws.Headers{}, nil, payload,
		&testSigner{
			headers: getUnmarshallableMap(),
		})
	require.Error(t, err)
	require.Contains(t, err.Error(), "serialize JWS headers")
	require.Nil(t, newJWS)

	// invalid b64
	newJWS, err = NewJWS(jws.Headers{}, nil, payload,
		&testSigner{
			headers:   jws.Headers{"alg": "dummy", "b64": "invalid"},
			signature: []byte("signature"),
		})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid b64 header")
	require.Nil(t, newJWS)
}

func TestJSONWebSignature_Signature(t *testing.T) {
	jws := &JSONWebSignature{
		signature: []byte("signature"),
	}
	require.NotEmpty(t, jws.Signature())

	jws.signature = nil
	require.Empty(t, jws.Signature())
}

func TestParseJWS(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwk, err := getPublicKeyJWK(&privateKey.PublicKey)
	require.NoError(t, err)

	corruptedBased64 := "XXXXXaGVsbG8="

	signer := ecsigner.New(privateKey, "ES256", "key-1")
	jws, err := NewJWS(signer.Headers(), nil, []byte("payload"),
		signer)
	require.NoError(t, err)

	jwsCompact, err := jws.SerializeCompact(false)
	require.NoError(t, err)
	require.NotEmpty(t, jwsCompact)

	validJWSParts := strings.Split(jwsCompact, ".")

	parsedJWS, err := VerifyJWS(jwsCompact, jwk)
	require.NoError(t, err)
	require.NotNil(t, parsedJWS)
	require.Equal(t, jws, parsedJWS)

	jwsDetached := fmt.Sprintf("%s.%s.%s", validJWSParts[0], "", validJWSParts[2])

	detachedPayload, err := base64.RawURLEncoding.DecodeString(validJWSParts[1])
	require.NoError(t, err)

	parsedJWS, err = VerifyJWS(jwsDetached, jwk, WithJWSDetachedPayload(detachedPayload))
	require.NoError(t, err)
	require.NotNil(t, parsedJWS)
	require.Equal(t, jws, parsedJWS)

	// Parse not compact JWS format
	parsedJWS, err = VerifyJWS(`{"some": "JSON"}`, jwk)
	require.Error(t, err)
	require.EqualError(t, err, "JWS JSON serialization is not supported")
	require.Nil(t, parsedJWS)

	// Parse invalid compact JWS format
	parsedJWS, err = VerifyJWS("two_parts.only", jwk)
	require.Error(t, err)
	require.EqualError(t, err, "invalid JWS compact format")
	require.Nil(t, parsedJWS)

	// invalid headers
	jwsWithInvalidHeaders := fmt.Sprintf("%s.%s.%s", "invalid", validJWSParts[1], validJWSParts[2])
	parsedJWS, err = VerifyJWS(jwsWithInvalidHeaders, jwk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unmarshal JSON headers")
	require.Nil(t, parsedJWS)

	jwsWithInvalidHeaders = fmt.Sprintf("%s.%s.%s", corruptedBased64, validJWSParts[1], validJWSParts[2])
	parsedJWS, err = VerifyJWS(jwsWithInvalidHeaders, jwk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode base64 header")
	require.Nil(t, parsedJWS)

	emptyHeaders := base64.RawURLEncoding.EncodeToString([]byte("{}"))

	jwsWithInvalidHeaders = fmt.Sprintf("%s.%s.%s", emptyHeaders, validJWSParts[1], validJWSParts[2])
	parsedJWS, err = VerifyJWS(jwsWithInvalidHeaders, jwk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "alg JWS header is not defined")
	require.Nil(t, parsedJWS)

	// invalid payload
	jwsWithInvalidPayload := fmt.Sprintf("%s.%s.%s", validJWSParts[0], corruptedBased64, validJWSParts[2])
	parsedJWS, err = VerifyJWS(jwsWithInvalidPayload, jwk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode base64 payload")
	require.Nil(t, parsedJWS)

	// invalid signature
	jwsWithInvalidSignature := fmt.Sprintf("%s.%s.%s", validJWSParts[0], validJWSParts[1], corruptedBased64)
	parsedJWS, err = VerifyJWS(jwsWithInvalidSignature, jwk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode base64 signature")
	require.Nil(t, parsedJWS)

	// missing signature
	jwsMissingSignature := fmt.Sprintf("%s.%s.%s", validJWSParts[0], validJWSParts[1], "")
	parsedJWS, err = VerifyJWS(jwsMissingSignature, jwk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "compact jws signature is empty")
	require.Nil(t, parsedJWS)

	// missing payload
	jwsMissingPayload := fmt.Sprintf("%s.%s.%s", validJWSParts[0], "", validJWSParts[2])
	parsedJWS, err = VerifyJWS(jwsMissingPayload, jwk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "compact jws payload is empty")
	require.Nil(t, parsedJWS)

	// signature verification error error
	jwk.Kty = "type"
	parsedJWS, err = VerifyJWS(jwsCompact, jwk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "key type is not supported for verifying signature")
	require.Nil(t, parsedJWS)
}

func TestParseJWS_ED25519(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwk, err := getPublicKeyJWK(publicKey)
	require.NoError(t, err)

	signer := edsigner.New(privateKey, "EdDSA", "key-1")
	jws, err := NewJWS(signer.Headers(), nil, []byte("payload"), signer)
	require.NoError(t, err)

	jwsCompact, err := jws.SerializeCompact(false)
	require.NoError(t, err)
	require.NotEmpty(t, jwsCompact)

	parsedJWS, err := VerifyJWS(jwsCompact, jwk)
	require.NoError(t, err)
	require.NotNil(t, parsedJWS)
	require.Equal(t, jws, parsedJWS)
}

func TestIsCompactJWS(t *testing.T) {
	require.True(t, IsCompactJWS("a.b.c"))
	require.False(t, IsCompactJWS("a.b"))
	require.False(t, IsCompactJWS(`{"some": "JSON"}`))
	require.False(t, IsCompactJWS(""))
}

type testSigner struct {
	headers   jws.Headers
	signature []byte
	err       error
}

func (s testSigner) Sign(_ []byte) ([]byte, error) {
	return s.signature, s.err
}

func (s testSigner) Headers() jws.Headers {
	return s.headers
}

func getUnmarshallableMap() map[string]interface{} {
	return map[string]interface{}{"alg": "JWS", "error": map[chan int]interface{}{make(chan int): 6}}
}
