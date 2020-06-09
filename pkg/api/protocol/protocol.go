/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protocol

// Protocol defines protocol parameters
type Protocol struct {
	// StartingBlockChainTime is inclusive starting logical blockchain time that this protocol applies to.
	StartingBlockChainTime uint
	// HashAlgorithmInMultiHashCode is hash algorithm in multihash code
	HashAlgorithmInMultiHashCode uint
	// MaxOperationsPerBatch defines maximum operations per batch
	MaxOperationsPerBatch uint
	// MaxDeltaByteSize is maximum size of the `delta` property in bytes
	MaxDeltaByteSize uint
	// CompressionAlgorithm is file compression algorithm
	CompressionAlgorithm string
	// MaxAnchorFileSize is maximum allowed size (in bytes) of anchor file stored in CAS
	MaxAnchorFileSize uint
	// MaxMapFileSize is maximum allowed size (in bytes) of map file stored in CAS
	MaxMapFileSize uint
	// MaxChunkFileSize is maximum allowed size (in bytes) of chunk file stored in CAS
	MaxChunkFileSize uint
}

// Client defines interface for accessing protocol version/information
type Client interface {

	// Current returns latest version of protocol
	Current() Protocol
}

// ClientProvider returns a protocol client for the given namespace
type ClientProvider interface {
	ForNamespace(namespace string) (Client, error)
}
