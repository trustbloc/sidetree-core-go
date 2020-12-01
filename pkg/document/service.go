/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

// ServiceEndpointProperty describes external service endpoint property.
const ServiceEndpointProperty = "serviceEndpoint"

// Service represents any type of service the entity wishes to advertise.
type Service map[string]interface{}

// NewService creates new service.
func NewService(m map[string]interface{}) Service {
	return m
}

// ID is service ID.
func (s Service) ID() string {
	return stringEntry(s[IDProperty])
}

// Type is service type.
func (s Service) Type() string {
	return stringEntry(s[TypeProperty])
}

// ServiceEndpoint is service endpoint.
func (s Service) ServiceEndpoint() interface{} {
	return s[ServiceEndpointProperty]
}

// JSONLdObject returns map that represents JSON LD Object.
func (s Service) JSONLdObject() map[string]interface{} {
	return s
}
