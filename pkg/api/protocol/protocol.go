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
	// MaxOperationByteSize is maximum size of an operation in bytes
	MaxOperationByteSize uint
}

// Client defines interface for accessing protocol version/information
type Client interface {

	// Current returns latest version of protocol
	Current() Protocol
}
