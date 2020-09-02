/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protocol

// Protocol defines protocol parameters
type Protocol struct {
	// GenesisTime is inclusive starting logical blockchain time that this protocol applies to
	// (e.g. block number in a blockchain)
	GenesisTime uint64
	// HashAlgorithmInMultiHashCode is hash algorithm in multihash code
	HashAlgorithmInMultiHashCode uint
	// MaxOperationCount defines maximum number of operations per batch
	MaxOperationCount uint
	// MaxOperationSize is maximum uncompressed operation size
	MaxOperationSize uint
	// CompressionAlgorithm is file compression algorithm
	CompressionAlgorithm string
	// MaxAnchorFileSize is maximum allowed size (in bytes) of anchor file stored in CAS
	MaxAnchorFileSize uint
	// MaxMapFileSize is maximum allowed size (in bytes) of map file stored in CAS
	MaxMapFileSize uint
	// MaxChunkFileSize is maximum allowed size (in bytes) of chunk file stored in CAS
	MaxChunkFileSize uint
	// EnableReplacePatch is used to enable replace patch (action)
	EnableReplacePatch bool
	//SignatureAlgorithms contain supported signature algorithms for signed operations (e.g. EdDSA, ES256, ES384, ES512, ES256K)
	SignatureAlgorithms []string
	//KeyAlgorithms contain supported key algorithms for signed operations (e.g. secp256k1, P-256, P-384, P-512, Ed25519)
	KeyAlgorithms []string
}

// Client defines interface for accessing protocol version/information
type Client interface {

	// Current returns latest version of protocol
	Current() (Protocol, error)

	Get(transactionTime uint64) (Protocol, error)
}

// ClientProvider returns a protocol client for the given namespace
type ClientProvider interface {
	ForNamespace(namespace string) (Client, error)
}
