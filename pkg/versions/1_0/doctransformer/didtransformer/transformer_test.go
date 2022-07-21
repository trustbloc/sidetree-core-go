/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didtransformer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/doctransformer/metadata"
)

const testID = "doc:abc:123"

func TestNewTransformer(t *testing.T) {
	transformer := New()
	require.NotNil(t, transformer)
	require.Empty(t, transformer.methodCtx)
	require.Equal(t, false, transformer.includeBase)
	require.Equal(t, false, transformer.includePublishedOperations)
	require.Equal(t, false, transformer.includeUnpublishedOperations)

	const ctx1 = "ctx-1"
	transformer = New(WithMethodContext([]string{ctx1}))
	require.Equal(t, 1, len(transformer.methodCtx))
	require.Equal(t, ctx1, transformer.methodCtx[0])

	const ctx2 = "ctx-2"
	transformer = New(WithMethodContext([]string{ctx1, ctx2}))
	require.Equal(t, 2, len(transformer.methodCtx))
	require.Equal(t, ctx2, transformer.methodCtx[1])

	transformer = New(WithBase(true))
	require.Equal(t, true, transformer.includeBase)

	var keyCtx map[string]string = map[string]string{
		"key-1": "value-1",
		"key-2": "value-2",
	}

	transformer = New(WithKeyContext(keyCtx))
	require.Equal(t, 2, len(transformer.keyCtx))

	transformer = New(WithIncludePublishedOperations(true), WithIncludeUnpublishedOperations(true))
	require.Equal(t, true, transformer.includePublishedOperations)
	require.Equal(t, true, transformer.includeUnpublishedOperations)
}

func TestTransformDocument(t *testing.T) {
	r := reader(t, "testdata/doc.json")
	docBytes, err := ioutil.ReadAll(r)
	require.NoError(t, err)
	doc, err := document.FromBytes(docBytes)
	require.NoError(t, err)

	transformer := New()

	internal := &protocol.ResolutionModel{Doc: doc, RecoveryCommitment: "recovery", UpdateCommitment: "update"}

	t.Run("success", func(t *testing.T) {
		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = testID
		info[document.PublishedProperty] = true

		result, err := transformer.TransformDocument(internal, info)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, testID, result.Document[document.IDProperty])

		methodMetadataEntry, ok := result.DocumentMetadata[document.MethodProperty]
		require.True(t, ok)
		methodMetadata, ok := methodMetadataEntry.(document.Metadata)
		require.True(t, ok)

		require.Equal(t, true, methodMetadata[document.PublishedProperty])
		require.Equal(t, "recovery", methodMetadata[document.RecoveryCommitmentProperty])
		require.Equal(t, "update", methodMetadata[document.UpdateCommitmentProperty])

		jsonTransformed, err := json.Marshal(result.Document)
		require.NoError(t, err)

		didDoc, err := document.DidDocumentFromBytes(jsonTransformed)
		require.NoError(t, err)

		// test document has 5 keys defined, two distinct key types: EcdsaSecp256k1VerificationKey2019, JsonWebKey2020
		require.Equal(t, 3, len(didDoc.Context()))
		require.Equal(t, didContext, didDoc.Context()[0])
		require.NotEmpty(t, didDoc[document.AlsoKnownAs])
		require.Equal(t, ecdsaSecp256k1VerificationKey2019Ctx, didDoc.Context()[1])
		require.Equal(t, jsonWebKey2020Ctx, didDoc.Context()[2])

		// validate services
		service := didDoc.Services()[0]
		require.Equal(t, service.ID(), testID+"#hub")
		require.Equal(t, "https://example.com/hub/", service.ServiceEndpoint().(string))
		require.Equal(t, "recipientKeysValue", service["recipientKeys"])
		require.Equal(t, "routingKeysValue", service["routingKeys"])
		require.Equal(t, "IdentityHub", service.Type())

		service = didDoc.Services()[1]
		require.Equal(t, service.ID(), testID+"#hub-object")
		require.NotEmpty(t, service.ServiceEndpoint())
		require.Empty(t, service["recipientKeys"])
		require.Equal(t, "IdentityHub", service.Type())

		serviceEndpointEntry := service.ServiceEndpoint()
		serviceEndpoint := serviceEndpointEntry.(map[string]interface{})
		require.Equal(t, "https://schema.identity.foundation/hub", serviceEndpoint["@context"])
		require.Equal(t, "UserHubEndpoint", serviceEndpoint["type"])
		require.Equal(t, []interface{}{"did:example:456", "did:example:789"}, serviceEndpoint["instances"])

		// validate public keys
		pk := didDoc.VerificationMethods()[0]
		require.Contains(t, pk.ID(), testID)
		require.NotEmpty(t, pk.Type())
		require.NotEmpty(t, pk.PublicKeyJwk())
		require.Empty(t, pk.PublicKeyBase58())

		expectedPublicKeys := []string{"master", "general", "authentication", "assertion", "agreement", "delegation", "invocation"}
		require.Equal(t, len(expectedPublicKeys), len(didDoc.VerificationMethods()))

		expectedAuthenticationKeys := []string{"master", "authentication"}
		require.Equal(t, len(expectedAuthenticationKeys), len(didDoc.Authentications()))

		expectedAssertionMethodKeys := []string{"master", "assertion"}
		require.Equal(t, len(expectedAssertionMethodKeys), len(didDoc.AssertionMethods()))

		expectedAgreementKeys := []string{"master", "agreement"}
		require.Equal(t, len(expectedAgreementKeys), len(didDoc.AgreementKeys()))

		expectedDelegationKeys := []string{"master", "delegation"}
		require.Equal(t, len(expectedDelegationKeys), len(didDoc.DelegationKeys()))

		expectedInvocationKeys := []string{"master", "invocation"}
		require.Equal(t, len(expectedInvocationKeys), len(didDoc.InvocationKeys()))
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

	t.Run("success - all supported contexts for key type", func(t *testing.T) {
		d, err := document.FromBytes([]byte(allKeyTypes))
		require.NoError(t, err)

		trans := New()

		internalDoc := &protocol.ResolutionModel{Doc: d}

		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = testID
		info[document.PublishedProperty] = true

		result, err := trans.TransformDocument(internalDoc, info)
		require.NoError(t, err)
		require.NotEmpty(t, result)

		didDoc := result.Document

		require.Equal(t, 7, len(didDoc.Context()))
		require.Equal(t, didContext, didDoc.Context()[0])
		require.Equal(t, bls12381G2Key2020Ctx, didDoc.Context()[1])
		require.Equal(t, jsonWebKey2020Ctx, didDoc.Context()[2])
		require.Equal(t, ecdsaSecp256k1VerificationKey2019Ctx, didDoc.Context()[3])
		require.Equal(t, ed25519VerificationKey2018Ctx, didDoc.Context()[4])
		require.Equal(t, x25519KeyAgreementKey2019Ctx, didDoc.Context()[5])
		require.Equal(t, ed25519VerificationKey2020Ctx, didDoc.Context()[6])
	})

	t.Run("success - override contexts for key type", func(t *testing.T) {
		testKeyContexts := map[string]string{
			bls12381G2Key2020:                 "context-1",
			jsonWebKey2020:                    "context-2",
			ecdsaSecp256k1VerificationKey2019: "context-3",
			ed25519VerificationKey2018:        "context-4",
			x25519KeyAgreementKey2019:         "context-5",
			ed25519VerificationKey2020:        "context-6",
		}

		d, err := document.FromBytes([]byte(allKeyTypes))
		require.NoError(t, err)

		trans := New(WithKeyContext(testKeyContexts))

		internalDoc := &protocol.ResolutionModel{Doc: d}

		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = testID
		info[document.PublishedProperty] = true

		result, err := trans.TransformDocument(internalDoc, info)
		require.NoError(t, err)
		require.NotEmpty(t, result)

		didDoc := result.Document

		require.Equal(t, 7, len(didDoc.Context()))
		require.Equal(t, didContext, didDoc.Context()[0])
		require.Equal(t, "context-1", didDoc.Context()[1])
		require.Equal(t, "context-2", didDoc.Context()[2])
		require.Equal(t, "context-3", didDoc.Context()[3])
		require.Equal(t, "context-4", didDoc.Context()[4])
		require.Equal(t, "context-5", didDoc.Context()[5])
		require.Equal(t, "context-6", didDoc.Context()[6])
	})

	t.Run("success - include operations (published/unpublished)", func(t *testing.T) {
		trans := New(
			WithIncludePublishedOperations(true),
			WithIncludeUnpublishedOperations(true))

		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = testID
		info[document.PublishedProperty] = true

		publishedOps := []*operation.AnchoredOperation{
			{Type: "create", UniqueSuffix: "suffix", CanonicalReference: "ref1"},
			{Type: "update", UniqueSuffix: "suffix", CanonicalReference: "ref2"},
		}

		unpublishedOps := []*operation.AnchoredOperation{
			{Type: "update", UniqueSuffix: "suffix"},
		}

		rm := &protocol.ResolutionModel{
			Doc:                   doc,
			RecoveryCommitment:    "recovery",
			UpdateCommitment:      "update",
			PublishedOperations:   publishedOps,
			UnpublishedOperations: unpublishedOps,
		}

		result, err := trans.TransformDocument(rm, info)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, testID, result.Document[document.IDProperty])

		methodMetadataEntry, ok := result.DocumentMetadata[document.MethodProperty]
		require.True(t, ok)
		methodMetadata, ok := methodMetadataEntry.(document.Metadata)
		require.True(t, ok)

		require.Equal(t, true, methodMetadata[document.PublishedProperty])
		require.Equal(t, "recovery", methodMetadata[document.RecoveryCommitmentProperty])
		require.Equal(t, "update", methodMetadata[document.UpdateCommitmentProperty])

		require.Equal(t, 2, len(methodMetadata[document.PublishedOperationsProperty].([]*metadata.PublishedOperation)))
		require.Equal(t, 1, len(methodMetadata[document.UnpublishedOperationsProperty].([]*metadata.UnpublishedOperation)))
	})

	t.Run("error - internal document is missing", func(t *testing.T) {
		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = testID
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

	t.Run("error - missing context for key type", func(t *testing.T) {
		doc, err := document.FromBytes([]byte(noContextForKeyType))
		require.NoError(t, err)

		transformer := New()

		internal := &protocol.ResolutionModel{Doc: doc}

		info := make(protocol.TransformationInfo)
		info[document.IDProperty] = testID
		info[document.PublishedProperty] = true

		result, err := transformer.TransformDocument(internal, info)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "key context not found for key type: InvalidType")
	})
}

func TestWithMethodContext(t *testing.T) {
	doc := make(document.Document)

	transformer := New(WithMethodContext([]string{"ctx-1", "ctx-2"}))

	internal := &protocol.ResolutionModel{Doc: doc}

	info := make(protocol.TransformationInfo)
	info[document.IDProperty] = testID
	info[document.PublishedProperty] = true

	result, err := transformer.TransformDocument(internal, info)
	require.NoError(t, err)

	jsonTransformed, err := json.Marshal(result.Document)
	require.NoError(t, err)

	didDoc, err := document.DidDocumentFromBytes(jsonTransformed)
	require.NoError(t, err)
	require.Equal(t, 3, len(didDoc.Context()))
	require.Equal(t, "ctx-1", didDoc.Context()[1])
	require.Equal(t, "ctx-2", didDoc.Context()[2])
}

func TestWithBase(t *testing.T) {
	r := reader(t, "testdata/doc.json")
	docBytes, err := ioutil.ReadAll(r)
	require.NoError(t, err)
	doc, err := document.FromBytes(docBytes)
	require.NoError(t, err)

	transformer := New(WithBase(true))

	internal := &protocol.ResolutionModel{Doc: doc}

	info := make(protocol.TransformationInfo)
	info[document.IDProperty] = testID
	info[document.PublishedProperty] = true

	result, err := transformer.TransformDocument(internal, info)
	require.NoError(t, err)

	jsonTransformed, err := json.Marshal(result.Document)
	require.NoError(t, err)

	didDoc, err := document.DidDocumentFromBytes(jsonTransformed)
	require.NoError(t, err)

	// test document has 5 keys defined, two distinct key types: EcdsaSecp256k1VerificationKey2019, JsonWebKey2020
	// two distinct key context + did context + @base context
	require.Equal(t, 4, len(didDoc.Context()))

	// second context is @base
	baseMap := didDoc.Context()[1].(map[string]interface{})
	baseMap["@base"] = testID

	// validate service id doesn't contain document id
	service := didDoc.Services()[0]
	require.NotContains(t, service.ID(), testID)

	// validate public key id doesn't contain document id
	pk := didDoc.VerificationMethods()[0]
	require.NotContains(t, pk.ID(), testID)
}

func TestEd25519VerificationKey2018(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwk, err := pubkey.GetPublicKeyJWK(publicKey)
	require.NoError(t, err)

	publicKeyBytes, err := json.Marshal(jwk)
	require.NoError(t, err)

	data := fmt.Sprintf(ed25519DocTemplate, string(publicKeyBytes))

	doc, err := document.FromBytes([]byte(data))
	require.NoError(t, err)

	transformer := New()

	internal := &protocol.ResolutionModel{Doc: doc}

	info := make(protocol.TransformationInfo)
	info[document.IDProperty] = testID
	info[document.PublishedProperty] = true

	result, err := transformer.TransformDocument(internal, info)
	require.NoError(t, err)

	jsonTransformed, err := json.Marshal(result.Document)
	require.NoError(t, err)

	didDoc, err := document.DidDocumentFromBytes(jsonTransformed)
	require.NoError(t, err)
	require.Equal(t, didDoc.VerificationMethods()[0].Controller(), didDoc.ID())
	require.Equal(t, didContext, didDoc.Context()[0])

	// validate service
	service := didDoc.Services()[0]
	require.Contains(t, service.ID(), testID)
	require.NotEmpty(t, service.ServiceEndpoint())
	require.Equal(t, "OpenIdConnectVersion1.0Service", service.Type())

	// validate public key
	pk := didDoc.VerificationMethods()[0]
	require.Contains(t, pk.ID(), testID)
	require.Equal(t, "Ed25519VerificationKey2018", pk.Type())
	require.Empty(t, pk.PublicKeyJwk())

	// test base58 encoding
	require.Equal(t, base58.Encode(publicKey), pk.PublicKeyBase58())

	// validate length of expected keys
	expectedPublicKeys := []string{"assertion"}
	require.Equal(t, len(expectedPublicKeys), len(didDoc.VerificationMethods()))

	expectedAssertionMethodKeys := []string{"assertion"}
	require.Equal(t, len(expectedAssertionMethodKeys), len(didDoc.AssertionMethods()))

	require.Equal(t, 0, len(didDoc.Authentications()))
	require.Equal(t, 0, len(didDoc.AgreementKeys()))
}

func TestEd25519VerificationKey2020(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwk, err := pubkey.GetPublicKeyJWK(publicKey)
	require.NoError(t, err)

	publicKeyBytes, err := json.Marshal(jwk)
	require.NoError(t, err)

	data := fmt.Sprintf(ed25519VerificationKey2020DocTemplate, string(publicKeyBytes))

	doc, err := document.FromBytes([]byte(data))
	require.NoError(t, err)

	transformer := New()

	internal := &protocol.ResolutionModel{Doc: doc}

	info := make(protocol.TransformationInfo)
	info[document.IDProperty] = testID
	info[document.PublishedProperty] = true

	result, err := transformer.TransformDocument(internal, info)
	require.NoError(t, err)

	jsonTransformed, err := json.Marshal(result.Document)
	require.NoError(t, err)

	didDoc, err := document.DidDocumentFromBytes(jsonTransformed)
	require.NoError(t, err)
	require.Equal(t, didDoc.VerificationMethods()[0].Controller(), didDoc.ID())
	require.Equal(t, didContext, didDoc.Context()[0])

	// validate service
	service := didDoc.Services()[0]
	require.Contains(t, service.ID(), testID)
	require.NotEmpty(t, service.ServiceEndpoint())
	require.Equal(t, "OpenIdConnectVersion1.0Service", service.Type())

	// validate public key
	pk := didDoc.VerificationMethods()[0]
	require.Contains(t, pk.ID(), testID)
	require.Equal(t, "Ed25519VerificationKey2020", pk.Type())
	require.Empty(t, pk.PublicKeyJwk())

	// test base58 encoding
	multibaseEncode, err := multibase.Encode(multibase.Base58BTC, publicKey)
	require.NoError(t, err)

	require.Equal(t, multibaseEncode, pk.PublicKeyMultibase())

	// validate length of expected keys
	expectedPublicKeys := []string{"assertion"}
	require.Equal(t, len(expectedPublicKeys), len(didDoc.VerificationMethods()))

	expectedAssertionMethodKeys := []string{"assertion"}
	require.Equal(t, len(expectedAssertionMethodKeys), len(didDoc.AssertionMethods()))

	require.Equal(t, 0, len(didDoc.Authentications()))
	require.Equal(t, 0, len(didDoc.AgreementKeys()))
}

func TestEd25519VerificationKey2018_Error(t *testing.T) {
	doc, err := document.FromBytes([]byte(ed25519Invalid))
	require.NoError(t, err)

	transformer := New()

	internal := &protocol.ResolutionModel{Doc: doc}

	info := make(protocol.TransformationInfo)
	info[document.IDProperty] = testID
	info[document.PublishedProperty] = true

	result, err := transformer.TransformDocument(internal, info)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "unknown curve")
}

func TestEd25519VerificationKey2020_Error(t *testing.T) {
	doc, err := document.FromBytes([]byte(ed25519VerificationKey2020DocInvalid))
	require.NoError(t, err)

	transformer := New()

	internal := &protocol.ResolutionModel{Doc: doc}

	info := make(protocol.TransformationInfo)
	info[document.IDProperty] = testID
	info[document.PublishedProperty] = true

	result, err := transformer.TransformDocument(internal, info)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "unknown curve")
}

func TestPublicKeyBase58(t *testing.T) {
	pkB58 := "36d8RkFy2SdabnGzcZ3LcCSDA8NP5T4bsoADwuXtoN3B"

	doc, err := document.FromBytes([]byte(fmt.Sprintf(publicKeyBase58Template, pkB58)))
	require.NoError(t, err)

	transformer := New()

	internal := &protocol.ResolutionModel{Doc: doc}

	info := make(protocol.TransformationInfo)
	info[document.IDProperty] = testID
	info[document.PublishedProperty] = true

	result, err := transformer.TransformDocument(internal, info)
	require.NoError(t, err)

	jsonTransformed, err := json.Marshal(result.Document)
	require.NoError(t, err)

	didDoc, err := document.DidDocumentFromBytes(jsonTransformed)
	require.NoError(t, err)
	require.Equal(t, didDoc.VerificationMethods()[0].Controller(), didDoc.ID())
	require.Equal(t, didContext, didDoc.Context()[0])

	pk := didDoc.VerificationMethods()[0]
	require.Contains(t, pk.ID(), testID)
	require.Equal(t, "Ed25519VerificationKey2018", pk.Type())
	require.Empty(t, pk.PublicKeyJwk())

	require.Equal(t, pkB58, pk.PublicKeyBase58())
}

func TestPublicKeyMultibase(t *testing.T) {
	pkMultibase := "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"

	doc, err := document.FromBytes([]byte(fmt.Sprintf(publicKeyMultibaseTemplate, pkMultibase)))
	require.NoError(t, err)

	transformer := New()

	internal := &protocol.ResolutionModel{Doc: doc}

	info := make(protocol.TransformationInfo)
	info[document.IDProperty] = testID
	info[document.PublishedProperty] = true

	result, err := transformer.TransformDocument(internal, info)
	require.NoError(t, err)

	jsonTransformed, err := json.Marshal(result.Document)
	require.NoError(t, err)

	didDoc, err := document.DidDocumentFromBytes(jsonTransformed)
	require.NoError(t, err)
	require.Equal(t, didDoc.VerificationMethods()[0].Controller(), didDoc.ID())
	require.Equal(t, didContext, didDoc.Context()[0])

	pk := didDoc.VerificationMethods()[0]
	require.Contains(t, pk.ID(), testID)
	require.Equal(t, "Ed25519VerificationKey2020", pk.Type())
	require.Empty(t, pk.PublicKeyJwk())

	require.Equal(t, pkMultibase, pk.PublicKeyMultibase())
}

func reader(t *testing.T, filename string) io.Reader {
	f, err := os.Open(filename)
	require.NoError(t, err)

	return f
}

const ed25519DocTemplate = `{
  "publicKey": [
	{
  		"id": "assertion",
  		"type": "Ed25519VerificationKey2018",
		"purposes": ["assertionMethod"],
  		"publicKeyJwk": %s
	}
  ],
  "service": [
	{
	   "id": "oidc",
	   "type": "OpenIdConnectVersion1.0Service",
	   "serviceEndpoint": "https://openid.example.com/"
	}
  ]
}`

const ed25519VerificationKey2020DocTemplate = `{
  "publicKey": [
	{
  		"id": "assertion",
  		"type": "Ed25519VerificationKey2020",
		"purposes": ["assertionMethod"],
  		"publicKeyJwk": %s
	}
  ],
  "service": [
	{
	   "id": "oidc",
	   "type": "OpenIdConnectVersion1.0Service",
	   "serviceEndpoint": "https://openid.example.com/"
	}
  ]
}`

const publicKeyBase58Template = `{
  "publicKey": [
	{
  		"id": "assertion",
  		"type": "Ed25519VerificationKey2018",
		"purposes": ["assertionMethod"],
  		"publicKeyBase58": "%s"
	}
  ],
  "service": [
	{
	   "id": "oidc",
	   "type": "OpenIdConnectVersion1.0Service",
	   "serviceEndpoint": "https://openid.example.com/"
	}
  ]
}`

const publicKeyMultibaseTemplate = `{
  "publicKey": [
	{
  		"id": "assertion",
  		"type": "Ed25519VerificationKey2020",
		"purposes": ["assertionMethod"],
  		"publicKeyMultibase": "%s"
	}
  ],
  "service": [
	{
	   "id": "oidc",
	   "type": "OpenIdConnectVersion1.0Service",
	   "serviceEndpoint": "https://openid.example.com/"
	}
  ]
}`

const ed25519Invalid = `{
  "publicKey": [
	{
  		"id": "assertion",
  		"type": "Ed25519VerificationKey2018",
		"purposes": ["assertionMethod"],
      	"publicKeyJwk": {
        	"kty": "OKP",
        	"crv": "curve",
        	"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        	"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      	}
	}
  ]
}`

const ed25519VerificationKey2020DocInvalid = `{
  "publicKey": [
	{
  		"id": "assertion",
  		"type": "Ed25519VerificationKey2020",
		"purposes": ["assertionMethod"],
      	"publicKeyJwk": {
        	"kty": "OKP",
        	"crv": "curve",
        	"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        	"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      	}
	}
  ]
}`

const noContextForKeyType = `{
  "publicKey": [
	{
  		"id": "assertion",
  		"type": "InvalidType",
		"purposes": ["assertionMethod"],
      	"publicKeyJwk": {
        	"kty": "OKP",
        	"crv": "curve",
        	"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        	"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      	}
	}
  ]
}`

const allKeyTypes = `{
  "publicKey": [
	{
	  	"id": "key-1",
      	"type": "Bls12381G2Key2020",
		"purposes": ["keyAgreement"],
      	"publicKeyJwk": {
        	"kty": "OKP",
        	"crv": "P-256",
        	"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        	"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      	}
	},
    {
      	"id": "key-2",
      	"type": "JsonWebKey2020",
      	"purposes": ["authentication"],
      	"publicKeyJwk": {
        	"kty": "EC",
        	"crv": "P-256",
        	"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        	"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      	}
    },    
	{
      	"id": "key-3",
      	"type": "EcdsaSecp256k1VerificationKey2019",
      	"purposes": ["assertionMethod"],
      	"publicKeyJwk": {
        	"kty": "EC",
        	"crv": "P-256K",
        	"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        	"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      	}
    },
    {
      	"id": "key-4",
		"type": "Ed25519VerificationKey2018",
		"purposes": ["assertionMethod"],
  		"publicKeyJwk": {
			"kty":"OKP",
			"crv":"Ed25519",
			"x":"K24aib_Py_D2ST8F_IiIA2SJo1EiseS0hbaa36tVSAU"
		}
    },
    {
      	"id": "key-5",
      	"type": "X25519KeyAgreementKey2019",
      	"purposes": ["keyAgreement"],
      	"publicKeyJwk": {
        	"kty": "EC",
        	"crv": "P-256",
        	"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        	"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      	}
    },
    {
      	"id": "key-6",
		"type": "Ed25519VerificationKey2020",
		"purposes": ["assertionMethod"],
  		"publicKeyJwk": {
			"kty":"OKP",
			"crv":"Ed25519",
			"x":"K24aib_Py_D2ST8F_IiIA2SJo1EiseS0hbaa36tVSAU"
		}
    }
  ]
}`
