/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protocol

import (
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

//go:generate counterfeiter -o ../../mocks/txnprocessor.gen.go --fake-name TxnProcessor . TxnProcessor
//go:generate counterfeiter -o ../../mocks/operationparser.gen.go --fake-name OperationParser . OperationParser
//go:generate counterfeiter -o ../../mocks/operationapplier.gen.go --fake-name OperationApplier . OperationApplier
//go:generate counterfeiter -o ../../mocks/protocolversion.gen.go --fake-name ProtocolVersion . Version
//go:generate counterfeiter -o ../../mocks/txnprocessor.gen.go --fake-name TxnProcessor . TxnProcessor
//go:generate counterfeiter -o ../../mocks/documentcomposer.gen.go --fake-name DocumentComposer . DocumentComposer
//go:generate counterfeiter -o ../../mocks/documentvalidator.gen.go --fake-name DocumentValidator . DocumentValidator
//go:generate counterfeiter -o ../../mocks/documenttransformer.gen.go --fake-name DocumentTransformer . DocumentTransformer
//go:generate counterfeiter -o ../../mocks/operationhandler.gen.go --fake-name OperationHandler . OperationHandler
//go:generate counterfeiter -o ../../mocks/operationprovider.gen.go --fake-name OperationProvider . OperationProvider

// Protocol defines protocol parameters.
type Protocol struct {
	// GenesisTime is inclusive starting logical blockchain time that this protocol applies to.
	// (e.g. block number in a blockchain)
	GenesisTime uint64 `json:"genesisTime"`
	// MultihashAlgorithms are supported multihash algorithm codes
	MultihashAlgorithms []uint `json:"multihashAlgorithms"`
	// MaxOperationCount defines maximum number of operations per batch.
	MaxOperationCount uint `json:"maxOperationCount"`
	// MaxOperationSize is maximum operation size in bytes (used to reject operations before parsing them)
	// It has to be greater than max delta size (big) + max proof size (medium) + other small values (operation type, suffix-data)
	MaxOperationSize uint `json:"maxOperationSize"`
	// MaxOperationHashLength is maximum operation hash length
	MaxOperationHashLength uint `json:"maxOperationHashLength"`
	// MaxDeltaSize is maximum size of operation's delta property.
	MaxDeltaSize uint `json:"maxDeltaSize"`
	// MaxCasUriLength is maximum length of CAS URI in batch files.
	MaxCasURILength uint `json:"maxCasUriLength"`
	// CompressionAlgorithm is file compression algorithm.
	CompressionAlgorithm string `json:"compressionAlgorithm"`
	// MaxCoreIndexFileSize is maximum allowed size (in bytes) of core index file stored in CAS.
	MaxCoreIndexFileSize uint `json:"maxCoreIndexFileSize"`
	// MaxProofFileSize is maximum allowed size (in bytes) of proof files stored in CAS.
	MaxProofFileSize uint `json:"maxProofFileSize"`
	// MaxProvisionalIndexFileSize is maximum allowed size (in bytes) of provisional index file stored in CAS.
	MaxProvisionalIndexFileSize uint `json:"maxProvisionalIndexFileSize"`
	// MaxChunkFileSize is maximum allowed size (in bytes) of chunk file stored in CAS.
	MaxChunkFileSize uint `json:"maxChunkFileSize"`
	// Patches contains the list of allowed patches.
	Patches []string `json:"patches"`
	// SignatureAlgorithms contain supported signature algorithms for signed operations (e.g. EdDSA, ES256, ES384, ES512, ES256K).
	SignatureAlgorithms []string `json:"signatureAlgorithms"`
	// KeyAlgorithms contain supported key algorithms for signed operations (e.g. secp256k1, P-256, P-384, P-512, Ed25519).
	KeyAlgorithms []string `json:"keyAlgorithms"`
}

// TxnProcessor defines the functions for processing a Sidetree transaction.
type TxnProcessor interface {
	Process(sidetreeTxn txn.SidetreeTxn) error
}

// OperationParser defines the functions for parsing operations.
type OperationParser interface {
	Parse(namespace string, operation []byte) (*operation.Operation, error)
	ParseDID(namespace, shortOrLongFormDID string) (string, []byte, error)
	GetRevealValue(operation []byte) (string, error)
	GetCommitment(operation []byte) (string, error)
}

// ResolutionModel contains temporary data during document resolution.
type ResolutionModel struct {
	Doc                              document.Document
	LastOperationTransactionTime     uint64
	LastOperationTransactionNumber   uint64
	LastOperationProtocolGenesisTime uint64
	UpdateCommitment                 string
	RecoveryCommitment               string
	Deactivated                      bool
}

// OperationApplier applies the given operation to the document.
type OperationApplier interface {
	Apply(op *operation.AnchoredOperation, rm *ResolutionModel) (*ResolutionModel, error)
}

// DocumentComposer applies patches to the given document.
type DocumentComposer interface {
	ApplyPatches(doc document.Document, patches []patch.Patch) (document.Document, error)
}

// OperationHandler defines an interface for creating batch files.
type OperationHandler interface {
	// GetTxnOperations operations will create relevant batch files, store them in CAS and return anchor string.
	PrepareTxnFiles(ops []*operation.QueuedOperation) (string, []*operation.Reference, error)
}

// OperationProvider retrieves the anchored operations for the given Sidetree transaction.
type OperationProvider interface {
	GetTxnOperations(sidetreeTxn *txn.SidetreeTxn) ([]*operation.AnchoredOperation, error)
}

// DocumentValidator is an interface for validating document operations.
type DocumentValidator interface {
	IsValidOriginalDocument(payload []byte) error
	IsValidPayload(payload []byte) error
}

// DocumentTransformer transforms internal resolution model into external document(resolution result).
type DocumentTransformer interface {
	TransformDocument(rm *ResolutionModel, info TransformationInfo) (*document.ResolutionResult, error)
}

// TransformationInfo contains document transformation info.
type TransformationInfo map[string]interface{}

// Version contains the protocol and corresponding implementations that are compatible with the protocol version.
type Version interface {
	Version() string
	Protocol() Protocol
	TransactionProcessor() TxnProcessor
	OperationParser() OperationParser
	OperationApplier() OperationApplier
	OperationHandler() OperationHandler
	OperationProvider() OperationProvider
	DocumentComposer() DocumentComposer
	DocumentValidator() DocumentValidator
	DocumentTransformer() DocumentTransformer
}

// Client defines interface for accessing protocol version/information.
type Client interface {
	// Current returns latest version of protocol.
	Current() (Version, error)

	// Get returns the version at the given transaction time.
	Get(transactionTime uint64) (Version, error)
}

// ClientProvider returns a protocol client for the given namespace.
type ClientProvider interface {
	ForNamespace(namespace string) (Client, error)
}
