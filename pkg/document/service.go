/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

// Service represents any type of service the entity wishes to advertise
type Service map[string]interface{}

// NewService creates new service
func NewService(m map[string]interface{}) Service {
	return m
}

// ID is service ID
func (s *Service) ID() interface{} {
	return (*s)[jsonldID]
}

// Type is service type
func (s *Service) Type() interface{} {
	return (*s)[jsonldType]
}

// Endpoint is service endpoint
func (s *Service) Endpoint() interface{} {
	return (*s)[jsonldServicePoint]
}
