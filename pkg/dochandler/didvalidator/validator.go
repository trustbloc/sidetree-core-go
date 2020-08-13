/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didvalidator

import (
	"errors"

	"github.com/btcsuite/btcutil/base58"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	internaljws "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

const (
	didSuffix = "did_suffix"

	didContext = "https://www.w3.org/ns/did/v1"
	//sidetreeContext = "https://identity.foundation/sidetree/context-v1.jsonld"
	trustblocContext = "https://trustbloc.github.io/context/did/trustbloc-v1.jsonld"

	didResolutionContext = "https://www.w3.org/ns/did-resolution/v1"
)

// Validator is responsible for validating did operations and sidetree rules
type Validator struct {
	store OperationStoreClient
}

// OperationStoreClient defines interface for retrieving all operations related to document
type OperationStoreClient interface {

	// Get retrieves all operations related to document
	Get(uniqueSuffix string) ([]*batch.AnchoredOperation, error)
}

// New creates a new did validator
func New(store OperationStoreClient) *Validator {
	return &Validator{
		store: store,
	}
}

// IsValidPayload verifies that the given payload is a valid Sidetree specific payload
// that can be accepted by the Sidetree update operations
func (v *Validator) IsValidPayload(payload []byte) error {
	doc, err := document.FromBytes(payload)
	if err != nil {
		return err
	}

	didSuffix := doc.GetStringValue(didSuffix)
	if didSuffix == "" {
		return errors.New("missing did unique suffix")
	}

	// did document has to exist in the store for all operations except for create
	docs, err := v.store.Get(didSuffix)
	if err != nil {
		return err
	}

	if len(docs) == 0 {
		return errors.New("missing did document operations")
	}

	return nil
}

// IsValidOriginalDocument verifies that the given payload is a valid Sidetree specific did document that can be accepted by the Sidetree create operation.
func (v *Validator) IsValidOriginalDocument(payload []byte) error {
	didDoc, err := document.DidDocumentFromBytes(payload)
	if err != nil {
		return err
	}

	// Sidetree rule: The document must NOT have the id property
	if didDoc.ID() != "" {
		return errors.New("document must NOT have the id property")
	}

	// Sidetree rule: validate public keys
	if err := document.ValidatePublicKeys(didDoc.PublicKeys()); err != nil {
		return err
	}

	// Sidetree rule: validate services
	if err := document.ValidateServices(didDoc.Services()); err != nil {
		return err
	}

	// Sidetree rule: must not have context
	ctx := didDoc.Context()
	if len(ctx) != 0 {
		return errors.New("document must NOT have context")
	}

	return nil
}

// TransformDocument takes internal representation of document and transforms it to required representation
func (v *Validator) TransformDocument(doc document.Document) (*document.ResolutionResult, error) {
	internal := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())

	// start with empty document
	external := document.DidDocumentFromJSONLDObject(make(document.DIDDocument))

	// add context and id
	// TODO: Add sidetree context once it gets fixed
	external[document.ContextProperty] = []interface{}{didContext, trustblocContext}
	external[document.IDProperty] = internal.ID()

	result := &document.ResolutionResult{
		Context:        didResolutionContext,
		Document:       external.JSONLdObject(),
		MethodMetadata: document.MethodMetadata{},
	}

	// add keys
	err := processKeys(internal, result)
	if err != nil {
		return nil, err
	}

	// add services
	processServices(internal, result)

	return result, nil
}

// processServices will process services and add them to external document
func processServices(internal document.DIDDocument, resolutionResult *document.ResolutionResult) {
	var services []document.Service

	// add did to service id
	for _, sv := range internal.Services() {
		externalService := make(document.Service)
		externalService[document.IDProperty] = internal.ID() + "#" + sv.ID()
		externalService[document.TypeProperty] = sv.Type()
		externalService[document.ServiceEndpointProperty] = sv.Endpoint()

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

// processKeys will process keys according to Sidetree rules bellow and add them to external document
// -- general: the key is to be included in the publicKeys section of the resolved DID Document.
// -- auth: the key is to be included in the authentication section of the resolved DID Document as follows:
// If the general purpose value IS NOT present in the purpose array,
// the key descriptor object will be included directly in the authentication section of the resolved DID Document.
// If the general purpose value IS present in the purpose array,
// the key descriptor object will be directly included in the publicKeys section of the resolved DID Document,
// and included by reference in the authentication section.
// -- assertion: the key MUST be included in the assertionMethod section of the resolved DID Document
// (same rules as for auth)
// -- agreement: the key MUST be included in the keyAgreement section of the resolved DID Document
// (same rules as for auth)
// -- delegation: the key MUST be included in the capabilityDelegation section of the resolved DID Document
// (same rules as for auth)
// -- invocation: the key MUST be included in the capabilityInvocation section of the resolved DID Document
// (same rules as for auth)
// -- ops: the key is allowed to generate DID operations for the DID and will be included in method metadata
func processKeys(internal document.DIDDocument, resolutionResult *document.ResolutionResult) error { //nolint: gocyclo,funlen, gocognit
	var authentication []interface{}
	var assertionMethod []interface{}
	var agreementKey []interface{}
	var delegationKey []interface{}
	var invocationKey []interface{}

	var publicKeys []document.PublicKey

	// add controller to public key
	for _, pk := range internal.PublicKeys() {
		// construct relative DID URL for inclusion in authentication and assertion method
		relativeID := "#" + pk.ID()

		externalPK := make(document.PublicKey)
		externalPK[document.IDProperty] = internal.ID() + relativeID
		externalPK[document.TypeProperty] = pk.Type()
		externalPK[document.ControllerProperty] = internal[document.IDProperty]

		if pk.Type() == document.Ed25519VerificationKey2018 {
			ed25519PubKey, err := getED2519PublicKey(pk.JWK())
			if err != nil {
				return err
			}
			externalPK[document.PublicKeyBase58Property] = base58.Encode(ed25519PubKey)
		} else {
			externalPK[document.PublicKeyJwkProperty] = pk.JWK()
		}

		purposes := pk.Purpose()
		if document.IsGeneralKey(purposes) {
			publicKeys = append(publicKeys, externalPK)

			// add into authentication by reference if the key has both auth and general purpose
			if document.IsAuthenticationKey(purposes) {
				authentication = append(authentication, relativeID)
			}
			// add into assertionMethod by reference if the key has both assertion and general purpose
			if document.IsAssertionKey(purposes) {
				assertionMethod = append(assertionMethod, relativeID)
			}
			// add into keyAgreement by reference if the key has both agreement and general purpose
			if document.IsAgreementKey(purposes) {
				agreementKey = append(agreementKey, relativeID)
			}
			// add into capabilityDelegation by reference if the key has both delegation and general purpose
			if document.IsDelegationKey(purposes) {
				delegationKey = append(delegationKey, relativeID)
			}
			// add into capabilityInvocation by reference if the key has both invocation and general purpose
			if document.IsInvocationKey(purposes) {
				invocationKey = append(invocationKey, relativeID)
			}
		} else if document.IsAuthenticationKey(purposes) {
			authentication = append(authentication, externalPK)
		} else if document.IsAssertionKey(purposes) {
			assertionMethod = append(assertionMethod, externalPK)
		} else if document.IsAgreementKey(purposes) {
			agreementKey = append(agreementKey, externalPK)
		} else if document.IsDelegationKey(purposes) {
			delegationKey = append(delegationKey, externalPK)
		} else if document.IsInvocationKey(purposes) {
			invocationKey = append(invocationKey, externalPK)
		}
	}

	if len(publicKeys) > 0 {
		resolutionResult.Document[document.PublicKeyProperty] = publicKeys
	}

	if len(authentication) > 0 {
		resolutionResult.Document[document.AuthenticationProperty] = authentication
	}

	if len(assertionMethod) > 0 {
		resolutionResult.Document[document.AssertionMethodProperty] = assertionMethod
	}

	if len(agreementKey) > 0 {
		resolutionResult.Document[document.AgreementKeyProperty] = agreementKey
	}

	if len(delegationKey) > 0 {
		resolutionResult.Document[document.DelegationKeyProperty] = delegationKey
	}

	if len(invocationKey) > 0 {
		resolutionResult.Document[document.InvocationKeyProperty] = invocationKey
	}

	return nil
}

func getED2519PublicKey(pkJWK document.JWK) ([]byte, error) {
	jwk := &jws.JWK{
		Crv: pkJWK.Crv(),
		Kty: pkJWK.Kty(),
		X:   pkJWK.X(),
		Y:   pkJWK.Y()}

	return internaljws.GetED25519PublicKey(jwk)
}
