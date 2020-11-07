/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didtransformer

import (
	"github.com/btcsuite/btcutil/base58"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	internaljws "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

const (
	didContext = "https://www.w3.org/ns/did/v1"

	didResolutionContext = "https://www.w3.org/ns/did-resolution/v1"

	// ed25519VerificationKey2018 requires special handling (convert to base58).
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
)

// Option is a registry instance option.
type Option func(opts *Transformer)

// WithMethodContext sets optional method context(s).
func WithMethodContext(ctx []string) Option {
	return func(opts *Transformer) {
		opts.methodCtx = ctx
	}
}

// WithBase sets optional @base context.
func WithBase(enabled bool) Option {
	return func(opts *Transformer) {
		opts.includeBase = enabled
	}
}

// Transformer is responsible for transforming internal to external document.
type Transformer struct {
	methodCtx   []string // used for setting additional contexts during resolution
	includeBase bool
}

// New creates a new DID Transformer.
func New(opts ...Option) *Transformer {
	transformer := &Transformer{}

	// apply options
	for _, opt := range opts {
		opt(transformer)
	}

	return transformer
}

// TransformDocument takes internal representation of document and transforms it to required representation.
func (t *Transformer) TransformDocument(doc document.Document) (*document.ResolutionResult, error) {
	internal := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())

	// start with empty document
	external := document.DidDocumentFromJSONLDObject(make(document.DIDDocument))

	// add main context
	ctx := []interface{}{didContext}

	// add optional method contexts
	for _, c := range t.methodCtx {
		ctx = append(ctx, c)
	}

	if t.includeBase {
		ctx = append(ctx, getBase(internal.ID()))
	}

	external[document.ContextProperty] = ctx
	external[document.IDProperty] = internal.ID()

	result := &document.ResolutionResult{
		Context:        didResolutionContext,
		Document:       external.JSONLdObject(),
		MethodMetadata: document.MethodMetadata{},
	}

	// add keys
	err := t.processKeys(internal, result)
	if err != nil {
		return nil, err
	}

	// add services
	t.processServices(internal, result)

	return result, nil
}

func getBase(id string) interface{} {
	return &struct {
		Base string `json:"@base"`
	}{
		Base: id,
	}
}

// processServices will process services and add them to external document.
func (t *Transformer) processServices(internal document.DIDDocument, resolutionResult *document.ResolutionResult) {
	var services []document.Service

	// add did to service id
	for _, sv := range internal.Services() {
		externalService := make(document.Service)
		externalService[document.IDProperty] = t.getObjectID(internal.ID(), sv.ID())
		externalService[document.TypeProperty] = sv.Type()
		externalService[document.ServiceEndpointProperty] = sv.ServiceEndpoint()

		for key, value := range sv {
			_, ok := externalService[key]
			if !ok {
				externalService[key] = value
			}
		}

		services = append(services, externalService)
	}

	if len(services) > 0 {
		resolutionResult.Document[document.ServiceProperty] = services
	}
}

// processKeys will process keys according to Sidetree rules bellow and add them to external document.
// every key will be included in the verificationMethod section of the resolved DID Document.
//
// -- authentication: the key MUST be included by reference (full id) in the authentication section of the resolved DID Document
// -- assertion: the key MUST be included by reference in the assertionMethod section.
// -- agreement: the key MUST be included by reference in the keyAgreement section.
// -- delegation: the key MUST be included by reference in the capabilityDelegation section.
// -- invocation: the key MUST be included by reference in the capabilityInvocation section.
func (t *Transformer) processKeys(internal document.DIDDocument, resolutionResult *document.ResolutionResult) error { //nolint:gocyclo,funlen,gocognit
	purposes := map[string][]interface{}{
		document.AuthenticationProperty:  make([]interface{}, 0),
		document.AssertionMethodProperty: make([]interface{}, 0),
		document.KeyAgreementProperty:    make([]interface{}, 0),
		document.DelegationKeyProperty:   make([]interface{}, 0),
		document.InvocationKeyProperty:   make([]interface{}, 0),
	}

	var publicKeys []document.PublicKey

	for _, pk := range internal.PublicKeys() {
		// construct full DID URL for inclusion in purpose sections
		id := internal.ID() + "#" + pk.ID()

		externalPK := make(document.PublicKey)
		externalPK[document.IDProperty] = t.getObjectID(internal.ID(), pk.ID())
		externalPK[document.TypeProperty] = pk.Type()
		externalPK[document.ControllerProperty] = internal[document.IDProperty]

		if pk.Type() == ed25519VerificationKey2018 {
			ed25519PubKey, err := getED2519PublicKey(pk.PublicKeyJwk())
			if err != nil {
				return err
			}
			externalPK[document.PublicKeyBase58Property] = base58.Encode(ed25519PubKey)
		} else {
			externalPK[document.PublicKeyJwkProperty] = pk.PublicKeyJwk()
		}

		publicKeys = append(publicKeys, externalPK)

		for _, p := range pk.Purpose() {
			switch p {
			case document.KeyPurposeAuthentication:
				purposes[document.AuthenticationProperty] = append(purposes[document.AuthenticationProperty], id)
			case document.KeyPurposeAssertionMethod:
				purposes[document.AssertionMethodProperty] = append(purposes[document.AssertionMethodProperty], id)
			case document.KeyPurposeKeyAgreement:
				purposes[document.KeyAgreementProperty] = append(purposes[document.KeyAgreementProperty], id)
			case document.KeyPurposeCapabilityDelegation:
				purposes[document.DelegationKeyProperty] = append(purposes[document.DelegationKeyProperty], id)
			case document.KeyPurposeCapabilityInvocation:
				purposes[document.InvocationKeyProperty] = append(purposes[document.InvocationKeyProperty], id)
			}
		}
	}

	if len(publicKeys) > 0 {
		resolutionResult.Document[document.VerificationMethodProperty] = publicKeys
	}

	for key, value := range purposes {
		if len(value) > 0 {
			resolutionResult.Document[key] = value
		}
	}

	return nil
}

func (t *Transformer) getObjectID(docID string, objectID string) interface{} {
	relativeID := "#" + objectID
	if t.includeBase {
		return relativeID
	}

	return docID + relativeID
}

func getED2519PublicKey(pkJWK document.JWK) ([]byte, error) {
	jwk := &jws.JWK{
		Crv: pkJWK.Crv(),
		Kty: pkJWK.Kty(),
		X:   pkJWK.X(),
		Y:   pkJWK.Y(),
	}

	return internaljws.GetED25519PublicKey(jwk)
}
