/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package patchvalidator

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
)

// nolint:gochecknoglobals
var (
	asciiRegex = regexp.MustCompile("^[A-Za-z0-9_-]+$")
)

const (
	jwsVerificationKey2020            = "JwsVerificationKey2020"
	jsonWebKey2020                    = "JsonWebKey2020"
	ecdsaSecp256k1VerificationKey2019 = "EcdsaSecp256k1VerificationKey2019"
	x25519KeyAgreementKey2019         = "X25519KeyAgreementKey2019"
	ed25519VerificationKey2018        = "Ed25519VerificationKey2018"

	maxPublicKeyProperties = 4

	// public keys, services id length.
	maxIDLength = 50

	maxServiceTypeLength     = 30
	maxServiceEndpointLength = 100
)

var allowedOps = map[document.KeyPurpose]bool{
	document.KeyPurposeAuth:       true,
	document.KeyPurposeGeneral:    true,
	document.KeyPurposeAssertion:  true,
	document.KeyPurposeAgreement:  true,
	document.KeyPurposeDelegation: true,
	document.KeyPurposeInvocation: true,
}

type existenceMap map[string]string

var allowedKeyTypesGeneral = existenceMap{
	jwsVerificationKey2020:            jwsVerificationKey2020,
	jsonWebKey2020:                    jsonWebKey2020,
	ecdsaSecp256k1VerificationKey2019: ecdsaSecp256k1VerificationKey2019,
	ed25519VerificationKey2018:        ed25519VerificationKey2018,
	x25519KeyAgreementKey2019:         x25519KeyAgreementKey2019,
}

var allowedKeyTypesVerification = existenceMap{
	jwsVerificationKey2020:            jwsVerificationKey2020,
	jsonWebKey2020:                    jsonWebKey2020,
	ecdsaSecp256k1VerificationKey2019: ecdsaSecp256k1VerificationKey2019,
	ed25519VerificationKey2018:        ed25519VerificationKey2018,
}

var allowedKeyTypesAgreement = existenceMap{
	// TODO: Verify appropriate agreement key types for JWS and Secp256k1
	jwsVerificationKey2020:            jwsVerificationKey2020,
	jsonWebKey2020:                    jsonWebKey2020,
	ecdsaSecp256k1VerificationKey2019: ecdsaSecp256k1VerificationKey2019,
	x25519KeyAgreementKey2019:         x25519KeyAgreementKey2019,
}

var allowedKeyTypes = map[string]existenceMap{
	document.KeyPurposeGeneral:    allowedKeyTypesGeneral,
	document.KeyPurposeAuth:       allowedKeyTypesVerification,
	document.KeyPurposeAssertion:  allowedKeyTypesVerification,
	document.KeyPurposeAgreement:  allowedKeyTypesAgreement,
	document.KeyPurposeDelegation: allowedKeyTypesVerification,
	document.KeyPurposeInvocation: allowedKeyTypesVerification,
}

// validatePublicKeys validates public keys.
func validatePublicKeys(pubKeys []document.PublicKey) error {
	ids := make(map[string]string)

	// the expected fields are id, purpose, type and jwk
	for _, pubKey := range pubKeys {
		kid := pubKey.ID()
		if err := validateKID(kid); err != nil {
			return err
		}

		if len(pubKey) != maxPublicKeyProperties {
			return errors.New("invalid number of public key properties")
		}

		if _, ok := ids[kid]; ok {
			return fmt.Errorf("duplicate public key id: %s", kid)
		}
		ids[kid] = kid

		if err := validateKeyPurpose(pubKey); err != nil {
			return err
		}

		if !validateKeyTypePurpose(pubKey) {
			return fmt.Errorf("invalid key type: %s", pubKey.Type())
		}

		if err := validateJWK(pubKey.JWK()); err != nil {
			return err
		}
	}

	return nil
}

func validateKID(kid string) error {
	if kid == "" {
		return errors.New("public key id is missing")
	}

	if err := validateID(kid); err != nil {
		return fmt.Errorf("public key: %s", err.Error())
	}

	return nil
}

// validateID validates id.
func validateID(id string) error {
	if len(id) > maxIDLength {
		return fmt.Errorf("id exceeds maximum length: %d", maxIDLength)
	}

	if !asciiRegex.MatchString(id) {
		return errors.New("id contains invalid characters")
	}

	return nil
}

// validateServices validates services.
func validateServices(services []document.Service) error {
	for _, service := range services {
		if err := validateService(service); err != nil {
			return err
		}
	}

	return nil
}

func validateService(service document.Service) error {
	// expected fields are type, id, and serviceEndpoint and some optional fields

	if err := validateServiceID(service.ID()); err != nil {
		return err
	}

	if err := validateServiceType(service.Type()); err != nil {
		return err
	}

	if err := validateServiceEndpoint(service.Endpoint()); err != nil {
		return err
	}

	return nil
}

func validateServiceID(id string) error {
	if id == "" {
		return errors.New("service id is missing")
	}

	if err := validateID(id); err != nil {
		return fmt.Errorf("service: %s", err.Error())
	}

	return nil
}

func validateServiceType(serviceType string) error {
	if serviceType == "" {
		return errors.New("service type is missing")
	}

	if len(serviceType) > maxServiceTypeLength {
		return fmt.Errorf("service type exceeds maximum length: %d", maxServiceTypeLength)
	}

	return nil
}

func validateServiceEndpoint(serviceEndpoint string) error {
	if serviceEndpoint == "" {
		return errors.New("service endpoint is missing")
	}

	if len(serviceEndpoint) > maxServiceEndpointLength {
		return fmt.Errorf("service endpoint exceeds maximum length: %d", maxServiceEndpointLength)
	}

	if _, err := url.ParseRequestURI(serviceEndpoint); err != nil {
		return fmt.Errorf("service endpoint is not valid URI: %s", err.Error())
	}

	return nil
}

// validateKeyTypePurpose validates if the public key type is valid for a certain purpose.
func validateKeyTypePurpose(pubKey document.PublicKey) bool {
	for _, purpose := range pubKey.Purpose() {
		allowed, ok := allowedKeyTypes[purpose]
		if !ok {
			return false
		}

		_, ok = allowed[pubKey.Type()]
		if !ok {
			return false
		}
	}

	return true
}

// validateJWK validates JWK.
func validateJWK(jwk document.JWK) error {
	if jwk == nil {
		return errors.New("key has to be in JWK format")
	}

	return jwk.Validate()
}

// The object MUST include a purpose property, and its value MUST be an array that includes one or more of the following:
// - ops: the key is allowed to generate DID operations for the DID.
// - general: the key is to be included in the publicKeys section of the resolved DID Document.
// - auth: the key is to be included in the authentication section of the resolved DID Document.
func validateKeyPurpose(pubKey document.PublicKey) error {
	if len(pubKey.Purpose()) == 0 {
		return fmt.Errorf("key '%s' is missing purpose", pubKey.ID())
	}

	if len(pubKey.Purpose()) > len(allowedOps) {
		return fmt.Errorf("public key purpose exceeds maximum length: %d", len(allowedOps))
	}

	for _, purpose := range pubKey.Purpose() {
		if _, ok := allowedOps[document.KeyPurpose(purpose)]; !ok {
			return fmt.Errorf("invalid purpose: %s", purpose)
		}
	}

	return nil
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}

	return false
}

func validateIds(ids []string) error {
	for _, id := range ids {
		if err := validateID(id); err != nil {
			return err
		}
	}

	return nil
}

func getRequiredArray(entry interface{}) ([]interface{}, error) {
	arr, ok := entry.([]interface{})
	if !ok {
		return nil, errors.New("expected array of interfaces")
	}

	if len(arr) == 0 {
		return nil, errors.New("required array is empty")
	}

	return arr, nil
}
