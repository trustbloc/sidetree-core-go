/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
)

// nolint:gochecknoglobals
var (
	asciiRegex = regexp.MustCompile("^[A-Za-z0-9_-]+$")
)

const (
	// ops defines key usage as operations key
	ops = "ops"
	// auth defines key usage as authentication key
	auth = "auth"
	// assertion defines key usage as assertion key
	assertion = "assertion"
	// agreement defines key usage as agreement key
	agreement = "agreement"
	// delegation defines key usage as delegation key
	delegation = "delegation"
	// invocation defines key usage as invocation key
	invocation = "invocation"
	// general defines key usage as general key
	general = "general"

	jwsVerificationKey2020            = "JwsVerificationKey2020"
	ecdsaSecp256k1VerificationKey2019 = "EcdsaSecp256k1VerificationKey2019"
	x25519KeyAgreementKey2019         = "X25519KeyAgreementKey2019"

	// Ed25519VerificationKey2018 requires special handling (convert to base58)
	Ed25519VerificationKey2018 = "Ed25519VerificationKey2018"

	maxJwkProperties       = 4
	maxPublicKeyProperties = 4

	// public keys, services id length
	maxIDLength = 20

	maxServiceTypeLength     = 30
	maxServiceEndpointLength = 100
)

var allowedOps = map[string]string{
	ops:        ops,
	auth:       auth,
	general:    general,
	assertion:  assertion,
	agreement:  agreement,
	delegation: delegation,
	invocation: invocation,
}

type existenceMap map[string]string

var allowedKeyTypesOps = existenceMap{
	jwsVerificationKey2020:            jwsVerificationKey2020,
	ecdsaSecp256k1VerificationKey2019: ecdsaSecp256k1VerificationKey2019,
}

var allowedKeyTypesGeneral = existenceMap{
	jwsVerificationKey2020:            jwsVerificationKey2020,
	ecdsaSecp256k1VerificationKey2019: ecdsaSecp256k1VerificationKey2019,
	Ed25519VerificationKey2018:        Ed25519VerificationKey2018,
	x25519KeyAgreementKey2019:         x25519KeyAgreementKey2019,
}

var allowedKeyTypesVerification = existenceMap{
	jwsVerificationKey2020:            jwsVerificationKey2020,
	ecdsaSecp256k1VerificationKey2019: ecdsaSecp256k1VerificationKey2019,
	Ed25519VerificationKey2018:        Ed25519VerificationKey2018,
}

var allowedKeyTypesAgreement = existenceMap{
	// TODO: Verify appropriate agreement key types for JWS and Secp256k1
	jwsVerificationKey2020:            jwsVerificationKey2020,
	ecdsaSecp256k1VerificationKey2019: ecdsaSecp256k1VerificationKey2019,
	x25519KeyAgreementKey2019:         x25519KeyAgreementKey2019,
}

var allowedKeyTypes = map[string]existenceMap{
	ops:        allowedKeyTypesOps,
	general:    allowedKeyTypesGeneral,
	auth:       allowedKeyTypesVerification,
	assertion:  allowedKeyTypesVerification,
	agreement:  allowedKeyTypesAgreement,
	delegation: allowedKeyTypesVerification,
	invocation: allowedKeyTypesVerification,
}

// ValidatePublicKeys validates public keys
func ValidatePublicKeys(pubKeys []PublicKey) error {
	ids := make(map[string]string)

	// the expected fields are id, usage, type and jwk
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

		if err := validateKeyUsage(pubKey); err != nil {
			return err
		}

		if IsOperationsKey(pubKey.Usage()) {
			if err := ValidateOperationsKey(pubKey); err != nil {
				return err
			}
		}

		if !validateKeyTypeUsage(pubKey) {
			return fmt.Errorf("invalid key type: %s", pubKey.Type())
		}

		if err := ValidateJWK(pubKey.JWK()); err != nil {
			return err
		}
	}

	return nil
}

func validateKID(kid string) error {
	if kid == "" {
		return errors.New("public key id is missing")
	}

	// TODO : Uncomment after integration fixes
	//if err := ValidateID(kid); err != nil {
	//	return fmt.Errorf("public key: %s", err.Error())
	//}

	return nil
}

// ValidateID validates id
func ValidateID(id string) error {
	if len(id) > maxIDLength {
		return fmt.Errorf("id exceeds maximum length: %d", maxIDLength)
	}

	if !asciiRegex.MatchString(id) {
		return errors.New("id contains invalid characters")
	}

	return nil
}

// ValidateServices validates services
func ValidateServices(services []Service) error {
	for _, service := range services {
		if err := validateService(service); err != nil {
			return err
		}
	}

	return nil
}

func validateService(service Service) error {
	// expected fields are type, id, and serviceEndpoint

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

	if err := ValidateID(id); err != nil {
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

// validateKeyTypeUsage validates if the public key type is valid for a certain usage
func validateKeyTypeUsage(pubKey PublicKey) bool {
	for _, usage := range pubKey.Usage() {
		allowed, ok := allowedKeyTypes[usage]
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

// ValidateOperationsKey validates operation key
func ValidateOperationsKey(pubKey PublicKey) error {
	if !IsOperationsKey(pubKey.Usage()) {
		return fmt.Errorf("key '%s' is not an operations key", pubKey.ID())
	}

	return ValidateJWK(pubKey.JWK())
}

// ValidateJWK validates JWK
func ValidateJWK(jwk JWK) error {
	if jwk == nil {
		return errors.New("key has to be in JWK format")
	}

	if len(jwk) != maxJwkProperties {
		return errors.New("invalid number of JWK properties")
	}

	if jwk.Crv() == "" {
		return errors.New("JWK crv is missing")
	}

	if jwk.Kty() == "" {
		return errors.New("JWK kty is missing")
	}

	if jwk.X() == "" {
		return errors.New("JWK x is missing")
	}

	return nil
}

// IsOperationsKey returns true if key is an operations key
func IsOperationsKey(usages []string) bool {
	return isUsageKey(usages, ops)
}

// IsGeneralKey returns true if key is a general key
func IsGeneralKey(usages []string) bool {
	return isUsageKey(usages, general)
}

// IsAuthenticationKey returns true if key is an authentication key
func IsAuthenticationKey(usages []string) bool {
	return isUsageKey(usages, auth)
}

// IsAssertionKey returns true if key is an assertion key
func IsAssertionKey(usages []string) bool {
	return isUsageKey(usages, assertion)
}

// IsAgreementKey returns true if key is an agreement key
func IsAgreementKey(usages []string) bool {
	return isUsageKey(usages, agreement)
}

// IsDelegationKey returns true if key is an delegation key
func IsDelegationKey(usages []string) bool {
	return isUsageKey(usages, delegation)
}

// IsInvocationKey returns true if key is an invocation key
func IsInvocationKey(usages []string) bool {
	return isUsageKey(usages, invocation)
}

func isUsageKey(usages []string, mode string) bool {
	for _, usage := range usages {
		if usage == mode {
			return true
		}
	}

	return false
}

// The object MUST include a usage property, and its value MUST be an array that includes one or more of the following:
// - ops: the key is allowed to generate DID operations for the DID.
// - general: the key is to be included in the publicKeys section of the resolved DID Document.
// - auth: the key is to be included in the authentication section of the resolved DID Document
func validateKeyUsage(pubKey PublicKey) error {
	if len(pubKey.Usage()) == 0 {
		return fmt.Errorf("key '%s' is missing usage", pubKey.ID())
	}

	if len(pubKey.Usage()) > len(allowedOps) {
		return fmt.Errorf("public key usage exceeds maximum length: %d", len(allowedOps))
	}

	for _, usage := range pubKey.Usage() {
		if _, ok := allowedOps[usage]; !ok {
			return fmt.Errorf("invalid usage: %s", usage)
		}
	}

	return nil
}
