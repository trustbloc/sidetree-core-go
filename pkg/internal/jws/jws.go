/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jws

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/square/go-jose/v3/json"

	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

const (
	jwsPartsCount    = 3
	jwsHeaderPart    = 0
	jwsPayloadPart   = 1
	jwsSignaturePart = 2
)

// JSONWebSignature defines JSON Web Signature (https://tools.ietf.org/html/rfc7515)
type JSONWebSignature struct {
	ProtectedHeaders   jws.Headers
	UnprotectedHeaders jws.Headers
	Payload            []byte

	signature   []byte
	joseHeaders jws.Headers
}

// Signer defines JWS Signer interface. It makes signing of data and provides custom JWS headers relevant to the signer.
type Signer interface {
	// Sign signs.
	Sign(data []byte) ([]byte, error)

	// Headers provides JWS headers. "alg" header must be provided (see https://tools.ietf.org/html/rfc7515#section-4.1)
	Headers() jws.Headers
}

// NewJWS creates JSON Web Signature.
func NewJWS(protectedHeaders, unprotectedHeaders jws.Headers, payload []byte, signer Signer) (*JSONWebSignature, error) {
	headers := mergeHeaders(protectedHeaders, signer.Headers())
	jws := &JSONWebSignature{
		ProtectedHeaders:   headers,
		UnprotectedHeaders: unprotectedHeaders,
		Payload:            payload,
		joseHeaders:        headers,
	}

	signature, err := sign(jws.joseHeaders, payload, signer)
	if err != nil {
		return nil, fmt.Errorf("sign JWS: %w", err)
	}

	jws.signature = signature

	return jws, nil
}

// SerializeCompact makes JWS Compact Serialization (https://tools.ietf.org/html/rfc7515#section-7.1)
func (s JSONWebSignature) SerializeCompact(detached bool) (string, error) {
	byteHeaders, err := json.Marshal(s.joseHeaders)
	if err != nil {
		return "", fmt.Errorf("marshal JWS JOSE Headers: %w", err)
	}

	b64Headers := base64.RawURLEncoding.EncodeToString(byteHeaders)

	b64Payload := ""
	if !detached {
		b64Payload = base64.RawURLEncoding.EncodeToString(s.Payload)
	}

	b64Signature := base64.RawURLEncoding.EncodeToString(s.signature)

	return fmt.Sprintf("%s.%s.%s",
		b64Headers,
		b64Payload,
		b64Signature), nil
}

// Signature returns a copy of JWS signature.
func (s JSONWebSignature) Signature() []byte {
	if s.signature == nil {
		return nil
	}

	sCopy := make([]byte, len(s.signature))
	copy(sCopy, s.signature)

	return sCopy
}

func mergeHeaders(h1, h2 jws.Headers) jws.Headers {
	h := make(jws.Headers, len(h1)+len(h2))

	for k, v := range h2 {
		h[k] = v
	}

	for k, v := range h1 {
		h[k] = v
	}

	return h
}

func sign(joseHeaders jws.Headers, payload []byte, signer Signer) ([]byte, error) {
	err := checkJWSHeaders(joseHeaders)
	if err != nil {
		return nil, fmt.Errorf("check JOSE headers: %w", err)
	}

	sigInput, err := signingInput(joseHeaders, payload)
	if err != nil {
		return nil, fmt.Errorf("prepare JWS verification data: %w", err)
	}

	signature, err := signer.Sign(sigInput)
	if err != nil {
		return nil, fmt.Errorf("sign JWS verification data: %w", err)
	}

	return signature, nil
}

// jwsParseOpts holds options for the JWS Parsing.
type jwsParseOpts struct {
	detachedPayload []byte
}

// ParseOpt is the JWS Parser option.
type ParseOpt func(opts *jwsParseOpts)

// WithJWSDetachedPayload option is for definition of JWS detached payload.
func WithJWSDetachedPayload(payload []byte) ParseOpt {
	return func(opts *jwsParseOpts) {
		opts.detachedPayload = payload
	}
}

// ParseJWS parses serialized JWS. Currently only JWS Compact Serialization parsing is supported.
func ParseJWS(jws string, opts ...ParseOpt) (*JSONWebSignature, error) {
	pOpts := &jwsParseOpts{}

	for _, opt := range opts {
		opt(pOpts)
	}

	if strings.HasPrefix(jws, "{") {
		// TODO support JWS JSON serialization format
		//  https://github.com/hyperledger/aries-framework-go/issues/1331
		return nil, errors.New("JWS JSON serialization is not supported")
	}

	return parseCompacted(jws, pOpts)
}

// VerifyJWS parses and validates serialized JWS. Currently only JWS Compact Serialization parsing is supported.
func VerifyJWS(jws string, jwk *jws.JWK, opts ...ParseOpt) (*JSONWebSignature, error) {
	parsedJWS, err := ParseJWS(jws, opts...)
	if err != nil {
		return nil, err
	}

	sInput, err := signingInput(parsedJWS.ProtectedHeaders, parsedJWS.Payload)
	if err != nil {
		return nil, fmt.Errorf("build signing input: %w", err)
	}

	err = VerifySignature(jwk, parsedJWS.signature, sInput)
	if err != nil {
		return nil, err
	}

	return parsedJWS, nil
}

// IsCompactJWS checks weather input is a compact JWS (based on https://tools.ietf.org/html/rfc7516#section-9)
func IsCompactJWS(s string) bool {
	parts := strings.Split(s, ".")

	return len(parts) == jwsPartsCount
}

func parseCompacted(jwsCompact string, opts *jwsParseOpts) (*JSONWebSignature, error) {
	parts := strings.Split(jwsCompact, ".")
	if len(parts) != jwsPartsCount {
		return nil, errors.New("invalid JWS compact format")
	}

	joseHeaders, err := parseCompactedHeaders(parts)
	if err != nil {
		return nil, err
	}

	payload, err := parseCompactedPayload(parts[jwsPayloadPart], opts)
	if err != nil {
		return nil, err
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[jwsSignaturePart])
	if err != nil {
		return nil, fmt.Errorf("decode base64 signature: %w", err)
	}

	if len(signature) == 0 {
		return nil, errors.New("compact jws signature is empty")
	}

	return &JSONWebSignature{
		ProtectedHeaders: joseHeaders,
		Payload:          payload,
		signature:        signature,
		joseHeaders:      joseHeaders,
	}, nil
}

func parseCompactedPayload(jwsPayload string, opts *jwsParseOpts) ([]byte, error) {
	if len(opts.detachedPayload) > 0 {
		return opts.detachedPayload, nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(jwsPayload)
	if err != nil {
		return nil, fmt.Errorf("decode base64 payload: %w", err)
	}

	if len(payload) == 0 {
		return nil, errors.New("compact jws payload is empty")
	}

	return payload, nil
}

func parseCompactedHeaders(parts []string) (jws.Headers, error) {
	headersBytes, err := base64.RawURLEncoding.DecodeString(parts[jwsHeaderPart])
	if err != nil {
		return nil, fmt.Errorf("decode base64 header: %w", err)
	}

	var joseHeaders jws.Headers

	err = json.Unmarshal(headersBytes, &joseHeaders)
	if err != nil {
		return nil, fmt.Errorf("unmarshal JSON headers: %w", err)
	}

	err = checkJWSHeaders(joseHeaders)
	if err != nil {
		return nil, err
	}

	return joseHeaders, nil
}

func signingInput(headers jws.Headers, payload []byte) ([]byte, error) {
	headersBytes, err := json.Marshal(headers)
	if err != nil {
		return nil, fmt.Errorf("serialize JWS headers: %w", err)
	}

	hBase64 := true

	if b64, ok := headers[jws.HeaderB64Payload]; ok {
		if hBase64, ok = b64.(bool); !ok {
			return nil, errors.New("invalid b64 header")
		}
	}

	headersStr := base64.RawURLEncoding.EncodeToString(headersBytes)

	var payloadStr string

	if hBase64 {
		payloadStr = base64.RawURLEncoding.EncodeToString(payload)
	} else {
		payloadStr = string(payload)
	}

	return []byte(fmt.Sprintf("%s.%s", headersStr, payloadStr)), nil
}

func checkJWSHeaders(headers jws.Headers) error {
	if _, ok := headers[jws.HeaderAlgorithm]; !ok {
		return fmt.Errorf("%s JWS header is not defined", jws.HeaderAlgorithm)
	}

	return nil
}
