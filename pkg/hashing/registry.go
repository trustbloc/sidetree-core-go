/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package hashing

import (
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/hashing/sha256"
)

// Option is a registry instance option
type Option func(opts *Registry)

// Registry contains hashing algorithms
type Registry struct {
	algorithms []Algorithm
}

// Algorithm defines hashing algorithm functionality
type Algorithm interface {
	Hash(value []byte) []byte
	Accept(alg string) bool
	Close() error
}

// New return new instance of hashing algorithms registry
func New(opts ...Option) *Registry {
	registry := &Registry{}

	// apply options
	for _, opt := range opts {
		opt(registry)
	}

	return registry
}

// Hash data using specified algorithm
func (r *Registry) Hash(alg string, data []byte) ([]byte, error) {
	// resolve hashing algorithm
	algorithm, err := r.resolveAlgorithm(alg)
	if err != nil {
		return nil, err
	}

	return algorithm.Hash(data), nil
}

// Close frees resources being maintained by hashing algorithm.
func (r *Registry) Close() error {
	for _, v := range r.algorithms {
		if err := v.Close(); err != nil {
			return fmt.Errorf("close algorithm: %w", err)
		}
	}

	return nil
}

func (r *Registry) resolveAlgorithm(alg string) (Algorithm, error) {
	for _, v := range r.algorithms {
		if v.Accept(alg) {
			return v, nil
		}
	}

	return nil, fmt.Errorf("hashing algorithm '%s' not supported", alg)
}

// WithAlgorithm adds hashing algorithm to the list of available algorithms
func WithAlgorithm(alg Algorithm) Option {
	return func(opts *Registry) {
		opts.algorithms = append(opts.algorithms, alg)
	}
}

// WithDefaultAlgorithms adds default hashing algorithms to the list of available algorithms
func WithDefaultAlgorithms() Option {
	return func(opts *Registry) {
		opts.algorithms = append(opts.algorithms, sha256.New())
	}
}
