/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package compression

import (
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/compression/gzip"
)

// Option is a registry instance option
type Option func(opts *Registry)

// Registry contains compression algorithms
type Registry struct {
	algorithms []Algorithm
}

// Algorithm defines compression/decompression algorithm functionality
type Algorithm interface {
	Compress(value []byte) ([]byte, error)
	Decompress(value []byte) ([]byte, error)
	Accept(alg string) bool
	Close() error
}

// New return new instance of compression algorithm registry
func New(opts ...Option) *Registry {
	registry := &Registry{}

	// apply options
	for _, opt := range opts {
		opt(registry)
	}

	return registry
}

// Compress data using specified algorithm
func (r *Registry) Compress(alg string, data []byte) ([]byte, error) {
	// resolve compression algorithm
	algorithm, err := r.resolveAlgorithm(alg)
	if err != nil {
		return nil, err
	}

	// compress data using specified algorithm
	result, err := algorithm.Compress(data)
	if err != nil {
		return nil, fmt.Errorf("compression failed for algorithm[%s]: %s", alg, err.Error())
	}

	return result, nil
}

// Decompress will decompress compressed data using specified algorithm
func (r *Registry) Decompress(alg string, data []byte) ([]byte, error) {
	// resolve compression algorithm
	algorithm, err := r.resolveAlgorithm(alg)
	if err != nil {
		return nil, err
	}

	// decompress data using specified algorithm
	result, err := algorithm.Decompress(data)
	if err != nil {
		return nil, fmt.Errorf("decompression failed for alg[%s]: %s", alg, err.Error())
	}

	return result, nil
}

// Close frees resources being maintained by compression algorithm.
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

	return nil, fmt.Errorf("compression algorithm '%s' not supported", alg)
}

// WithAlgorithm adds compression algorithm to the list of available algorithms
func WithAlgorithm(alg Algorithm) Option {
	return func(opts *Registry) {
		opts.algorithms = append(opts.algorithms, alg)
	}
}

// WithDefaultAlgorithms adds default compression algorithms to the list of available algorithms
func WithDefaultAlgorithms() Option {
	return func(opts *Registry) {
		opts.algorithms = append(opts.algorithms, gzip.New())
	}
}
