/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnprovider

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/compression"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/doccomposer"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/operationapplier"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/operationparser"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/txnprovider/models"
)

const (
	compressionAlgorithm = "GZIP"
	maxFileSize          = 2000 // in bytes
)

func TestNewOperationProvider(t *testing.T) {
	pc := mocks.NewMockProtocolClient()

	handler := NewOperationProvider(
		pc.Protocol,
		operationparser.New(pc.Protocol),
		mocks.NewMockCasClient(nil),
		compression.New(compression.WithDefaultAlgorithms()))

	require.NotNil(t, handler)
}

func TestHandler_GetTxnOperations(t *testing.T) {
	const createOpsNum = 2
	const updateOpsNum = 3
	const deactivateOpsNum = 2
	const recoverOpsNum = 2

	pc := mocks.NewMockProtocolClient()
	parser := operationparser.New(pc.Protocol)
	cp := compression.New(compression.WithDefaultAlgorithms())

	t.Run("success", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		handler := NewOperationHandler(pc.Protocol, cas, cp)

		ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

		anchorString, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)

		provider := NewOperationProvider(pc.Protocol, parser, cas, cp)

		txnOps, err := provider.GetTxnOperations(&txn.SidetreeTxn{
			Namespace:         defaultNS,
			AnchorString:      anchorString,
			TransactionNumber: 1,
			TransactionTime:   1,
		})

		require.NoError(t, err)
		require.Equal(t, createOpsNum+updateOpsNum+deactivateOpsNum+recoverOpsNum, len(txnOps))
	})

	t.Run("error - number of operations doesn't match", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		handler := NewOperationHandler(pc.Protocol, cas, cp)

		ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

		// anchor string has 9 operations "9.anchorAddress"
		anchorString, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)

		// update number of operations in anchor string from 9 to 7
		ad, err := ParseAnchorData(anchorString)
		require.NoError(t, err)
		ad.NumberOfOperations = 7
		anchorString = ad.GetAnchorString()

		provider := NewOperationProvider(mocks.NewMockProtocolClient().Protocol, operationparser.New(pc.Protocol), cas, cp)

		txnOps, err := provider.GetTxnOperations(&txn.SidetreeTxn{
			Namespace:         defaultNS,
			AnchorString:      anchorString,
			TransactionNumber: 1,
			TransactionTime:   1,
		})

		require.Error(t, err)
		require.Nil(t, txnOps)
		require.Contains(t, err.Error(), "number of txn ops[9] doesn't match anchor string num of ops[7]")
	})

	t.Run("error - read from CAS error", func(t *testing.T) {
		protocolClient := mocks.NewMockProtocolClient()
		handler := NewOperationProvider(protocolClient.Protocol, operationparser.New(protocolClient.Protocol), mocks.NewMockCasClient(errors.New("CAS error")), cp)

		txnOps, err := handler.GetTxnOperations(&txn.SidetreeTxn{
			Namespace:         defaultNS,
			AnchorString:      "1" + delimiter + "anchor",
			TransactionNumber: 1,
			TransactionTime:   1,
		})

		require.Error(t, err)
		require.Nil(t, txnOps)
		require.Contains(t, err.Error(), "error reading anchor file[anchor]: retrieve CAS content[anchor]: CAS error")
	})

	t.Run("error - parse anchor operations error", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		handler := NewOperationHandler(pc.Protocol, cas, cp)

		ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

		anchorString, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)

		invalid := mocks.NewMockProtocolClient().Protocol
		invalid.HashAlgorithmInMultiHashCode = 55

		provider := NewOperationProvider(invalid, operationparser.New(invalid), cas, cp)

		txnOps, err := provider.GetTxnOperations(&txn.SidetreeTxn{
			Namespace:         mocks.DefaultNS,
			AnchorString:      anchorString,
			TransactionNumber: 1,
			TransactionTime:   1,
		})

		require.Error(t, err)
		require.Nil(t, txnOps)
		require.Contains(t, err.Error(), "parse anchor operations: algorithm not supported")
	})

	t.Run("error - parse anchor data error", func(t *testing.T) {
		p := mocks.NewMockProtocolClient().Protocol
		provider := NewOperationProvider(p, operationparser.New(p), mocks.NewMockCasClient(nil), cp)

		txnOps, err := provider.GetTxnOperations(&txn.SidetreeTxn{
			AnchorString:      "abc.anchor",
			TransactionNumber: 1,
			TransactionTime:   1,
		})

		require.Error(t, err)
		require.Nil(t, txnOps)
		require.Contains(t, err.Error(), "parse anchor data[abc.anchor] failed")
	})

	t.Run("success - deactivate only", func(t *testing.T) {
		const deactivateOpsNum = 2

		var ops []*batch.Operation
		ops = append(ops, generateOperations(deactivateOpsNum, batch.OperationTypeDeactivate)...)

		cas := mocks.NewMockCasClient(nil)
		handler := NewOperationHandler(pc.Protocol, cas, cp)

		anchorString, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)

		p := mocks.NewMockProtocolClient().Protocol
		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		txnOps, err := provider.GetTxnOperations(&txn.SidetreeTxn{
			Namespace:         defaultNS,
			AnchorString:      anchorString,
			TransactionNumber: 1,
			TransactionTime:   1,
		})

		require.NoError(t, err)
		require.Equal(t, deactivateOpsNum, len(txnOps))
	})
}

func TestHandler_GetAnchorFile(t *testing.T) {
	cp := compression.New(compression.WithDefaultAlgorithms())
	p := protocol.Protocol{MaxAnchorFileSize: maxFileSize, CompressionAlgorithm: compressionAlgorithm}

	cas := mocks.NewMockCasClient(nil)
	content, err := cp.Compress(compressionAlgorithm, []byte("{}"))
	require.NoError(t, err)
	address, err := cas.Write(content)
	require.NoError(t, err)

	parser := operationparser.New(p)

	t.Run("success", func(t *testing.T) {
		provider := NewOperationProvider(p, parser, cas, cp)

		file, err := provider.getAnchorFile(address)
		require.NoError(t, err)
		require.NotNil(t, file)
	})

	t.Run("error - anchor file exceeds maximum size", func(t *testing.T) {
		provider := NewOperationProvider(protocol.Protocol{MaxAnchorFileSize: 15, CompressionAlgorithm: compressionAlgorithm}, parser, cas, cp)

		file, err := provider.getAnchorFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "exceeded maximum size 15")
	})

	t.Run("error - parse anchor file error (invalid JSON)", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		content, err := cp.Compress(compressionAlgorithm, []byte("invalid"))
		require.NoError(t, err)
		address, err := cas.Write(content)

		provider := NewOperationProvider(p, parser, cas, cp)
		file, err := provider.getAnchorFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to parse content for anchor file")
	})
}

func TestHandler_GetMapFile(t *testing.T) {
	cp := compression.New(compression.WithDefaultAlgorithms())
	p := protocol.Protocol{MaxMapFileSize: maxFileSize, CompressionAlgorithm: compressionAlgorithm}

	cas := mocks.NewMockCasClient(nil)
	content, err := cp.Compress(compressionAlgorithm, []byte("{}"))
	require.NoError(t, err)
	address, err := cas.Write(content)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		file, err := provider.getMapFile(address)
		require.NoError(t, err)
		require.NotNil(t, file)
	})

	t.Run("error - map file exceeds maximum size", func(t *testing.T) {
		lowMaxFileSize := protocol.Protocol{MaxMapFileSize: 5, CompressionAlgorithm: compressionAlgorithm}
		parser := operationparser.New(lowMaxFileSize)
		provider := NewOperationProvider(lowMaxFileSize, parser, cas, cp)

		file, err := provider.getMapFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "exceeded maximum size 5")
	})

	t.Run("error - parse anchor file error (invalid JSON)", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		content, err := cp.Compress(compressionAlgorithm, []byte("invalid"))
		require.NoError(t, err)
		address, err := cas.Write(content)

		parser := operationparser.New(p)
		provider := NewOperationProvider(p, parser, cas, cp)
		file, err := provider.getMapFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to parse content for map file")
	})
}

func TestHandler_GetChunkFile(t *testing.T) {
	cp := compression.New(compression.WithDefaultAlgorithms())
	p := protocol.Protocol{MaxChunkFileSize: maxFileSize, CompressionAlgorithm: compressionAlgorithm}

	cas := mocks.NewMockCasClient(nil)
	content, err := cp.Compress(compressionAlgorithm, []byte("{}"))
	require.NoError(t, err)
	address, err := cas.Write(content)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		file, err := provider.getChunkFile(address)
		require.NoError(t, err)
		require.NotNil(t, file)
	})

	t.Run("error - chunk file exceeds maximum size", func(t *testing.T) {
		lowMaxFileSize := protocol.Protocol{MaxChunkFileSize: 10, CompressionAlgorithm: compressionAlgorithm}
		provider := NewOperationProvider(lowMaxFileSize, operationparser.New(p), cas, cp)

		file, err := provider.getChunkFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "exceeded maximum size 10")
	})

	t.Run("error - parse chunk file error (invalid JSON)", func(t *testing.T) {
		content, err := cp.Compress(compressionAlgorithm, []byte("invalid"))
		require.NoError(t, err)
		address, err := cas.Write(content)

		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)
		file, err := provider.getChunkFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to parse content for chunk file")
	})
}

func TestHandler_readFromCAS(t *testing.T) {
	cp := compression.New(compression.WithDefaultAlgorithms())
	p := protocol.Protocol{MaxChunkFileSize: maxFileSize, CompressionAlgorithm: compressionAlgorithm}

	cas := mocks.NewMockCasClient(nil)
	content, err := cp.Compress(compressionAlgorithm, []byte("{}"))
	require.NoError(t, err)
	address, err := cas.Write(content)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		file, err := provider.readFromCAS(address, compressionAlgorithm, maxFileSize)
		require.NoError(t, err)
		require.NotNil(t, file)
	})

	t.Run("error - read from CAS error", func(t *testing.T) {
		provider := NewOperationProvider(p, operationparser.New(p), mocks.NewMockCasClient(errors.New("CAS error")), cp)

		file, err := provider.getChunkFile("address")
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), " retrieve CAS content[address]: CAS error")
	})

	t.Run("error - content exceeds maximum size", func(t *testing.T) {
		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		file, err := provider.readFromCAS(address, compressionAlgorithm, 20)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "exceeded maximum size 20")
	})

	t.Run("error - decompression error", func(t *testing.T) {
		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		file, err := provider.readFromCAS(address, "alg", maxFileSize)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "compression algorithm 'alg' not supported")
	})
}

func TestHandler_assembleBatchOperations(t *testing.T) {
	p := newMockProtocolClient().Protocol

	t.Run("success", func(t *testing.T) {
		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)

		createOp, err := generateOperation(1, batch.OperationTypeCreate)
		require.NoError(t, err)

		updateOp, err := generateOperation(2, batch.OperationTypeUpdate)
		require.NoError(t, err)

		deactivateOp, err := generateOperation(3, batch.OperationTypeDeactivate)
		require.NoError(t, err)

		af := &models.AnchorFile{
			MapFileHash: "hash",
			Operations: models.Operations{
				Create:     []models.CreateOperation{{SuffixData: createOp.SuffixData}},
				Deactivate: []models.SignedOperation{{DidSuffix: deactivateOp.UniqueSuffix, SignedData: deactivateOp.SignedData}},
			},
		}

		mf := &models.MapFile{
			Chunks: []models.Chunk{},
			Operations: models.Operations{
				Update: []models.SignedOperation{{DidSuffix: updateOp.UniqueSuffix, SignedData: updateOp.SignedData}},
			},
		}

		cf := &models.ChunkFile{Deltas: []string{createOp.Delta, updateOp.Delta}}

		file, err := provider.assembleBatchOperations(af, mf, cf, &txn.SidetreeTxn{Namespace: defaultNS})
		require.NoError(t, err)
		require.NotNil(t, file)
	})

	t.Run("error - anchor, map, chunk file operation number mismatch", func(t *testing.T) {
		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)

		createOp, err := generateOperation(1, batch.OperationTypeCreate)
		require.NoError(t, err)

		updateOp, err := generateOperation(2, batch.OperationTypeUpdate)
		require.NoError(t, err)

		deactivateOp, err := generateOperation(3, batch.OperationTypeDeactivate)
		require.NoError(t, err)

		af := &models.AnchorFile{
			MapFileHash: "hash",
			Operations: models.Operations{
				Create: []models.CreateOperation{{SuffixData: createOp.SuffixData}},
				Deactivate: []models.SignedOperation{
					{DidSuffix: deactivateOp.UniqueSuffix, SignedData: deactivateOp.SignedData},
				},
			},
		}

		mf := &models.MapFile{
			Chunks: []models.Chunk{},
			Operations: models.Operations{
				Update: []models.SignedOperation{{DidSuffix: updateOp.UniqueSuffix, SignedData: updateOp.SignedData}},
			},
		}

		// don't add update operation delta to chunk file in order to cause error
		cf := &models.ChunkFile{Deltas: []string{createOp.Delta}}

		file, err := provider.assembleBatchOperations(af, mf, cf, &txn.SidetreeTxn{Namespace: defaultNS})
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(),
			"number of create+recover+update operations[2] doesn't match number of deltas[1]")
	})

	t.Run("error - duplicate operations found in anchor/map files", func(t *testing.T) {
		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)

		createOp, err := generateOperation(1, batch.OperationTypeCreate)
		require.NoError(t, err)

		updateOp, err := generateOperation(2, batch.OperationTypeUpdate)
		require.NoError(t, err)

		deactivateOp, err := generateOperation(3, batch.OperationTypeDeactivate)
		require.NoError(t, err)

		af := &models.AnchorFile{
			MapFileHash: "hash",
			Operations: models.Operations{
				Create: []models.CreateOperation{{SuffixData: createOp.SuffixData}},
				Deactivate: []models.SignedOperation{
					{DidSuffix: deactivateOp.UniqueSuffix, SignedData: deactivateOp.SignedData},
					{DidSuffix: deactivateOp.UniqueSuffix, SignedData: deactivateOp.SignedData},
				},
			},
		}

		mf := &models.MapFile{
			Chunks: []models.Chunk{},
			Operations: models.Operations{
				Update: []models.SignedOperation{
					{DidSuffix: updateOp.UniqueSuffix, SignedData: updateOp.SignedData},
					{DidSuffix: updateOp.UniqueSuffix, SignedData: updateOp.SignedData},
				},
			},
		}

		cf := &models.ChunkFile{Deltas: []string{createOp.Delta}}

		file, err := provider.assembleBatchOperations(af, mf, cf, &txn.SidetreeTxn{Namespace: defaultNS})
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(),
			"check for duplicate suffixes in anchor/map files: duplicate values found [deactivate-3 update-2]")
	})

	t.Run("error - invalid delta", func(t *testing.T) {
		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)

		createOp, err := generateOperation(1, batch.OperationTypeCreate)
		require.NoError(t, err)

		af := &models.AnchorFile{
			MapFileHash: "hash",
			Operations: models.Operations{
				Create: []models.CreateOperation{{SuffixData: createOp.SuffixData}},
			},
		}

		mf := &models.MapFile{
			Chunks: []models.Chunk{},
		}

		cf := &models.ChunkFile{Deltas: []string{"invalid-delta"}}

		file, err := provider.assembleBatchOperations(af, mf, cf, &txn.SidetreeTxn{Namespace: defaultNS})
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "parse delta: illegal base64 data")
	})
}

func newMockProtocolClient() *mocks.MockProtocolClient {
	pc := mocks.NewMockProtocolClient()
	parser := operationparser.New(pc.Protocol)
	dc := doccomposer.New()
	oa := operationapplier.New(pc.Protocol, parser, dc)

	pv := pc.CurrentVersion
	pv.OperationParserReturns(parser)
	pv.OperationApplierReturns(oa)
	pv.DocumentComposerReturns(dc)

	return pc
}
