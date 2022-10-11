/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gzip

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
)

const algName = "GZIP"

// Algorithm implements gzip compression/decompression.
type Algorithm struct {
}

// New creates new gzip algorithm instance.
func New() *Algorithm {
	return &Algorithm{}
}

// Compress will compress data using gzip.
func (a *Algorithm) Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)

	_, err := zw.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write data: %s", err.Error())
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("failed to close writer: %s", err.Error())
	}

	return buf.Bytes(), nil
}

// Decompress will decompress compressed data.
func (a *Algorithm) Decompress(data []byte) ([]byte, error) {
	buf := bytes.NewBuffer(data)

	zr, err := gzip.NewReader(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create new reader: %s", err.Error())
	}

	zrBytes, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("failed to read compressed data: %s", err.Error())
	}

	if err := zr.Close(); err != nil {
		return nil, fmt.Errorf("failed to close reader: %s", err.Error())
	}

	return zrBytes, nil
}

// Accept algorithm.
func (a *Algorithm) Accept(alg string) bool {
	return alg == algName
}

// Close closes open resources.
func (a *Algorithm) Close() error {
	// nothing to do for gzip
	return nil
}
