/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnhandler

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/compression"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/txnhandler/models"
)

const compressionAlgorithm = "GZIP"
const maxFileSize = 2000 // in bytes

func TestNewOperationProvider(t *testing.T) {
	handler := NewOperationProvider(mocks.NewMockCasClient(nil),
		mocks.NewMockProtocolClientProvider(),
		compression.New(compression.WithDefaultAlgorithms()))

	require.NotNil(t, handler)
}

func TestHandler_GetTxnOperations(t *testing.T) {
	const createOpsNum = 2
	const updateOpsNum = 3
	const deactivateOpsNum = 2
	const recoverOpsNum = 2

	pc := mocks.NewMockProtocolClient()
	cp := compression.New(compression.WithDefaultAlgorithms())

	t.Run("success", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		handler := NewOperationHandler(cas, pc, cp)

		ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

		anchorString, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)

		provider := NewOperationProvider(cas, mocks.NewMockProtocolClientProvider(), cp)

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
		handler := NewOperationHandler(cas, pc, cp)

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

		provider := NewOperationProvider(cas, mocks.NewMockProtocolClientProvider(), cp)

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
		handler := NewOperationProvider(
			mocks.NewMockCasClient(errors.New("CAS error")),
			mocks.NewMockProtocolClientProvider(),
			cp)

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
		handler := NewOperationHandler(cas, pc, cp)

		ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

		anchorString, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)

		invalid := mocks.NewMockProtocolClient()
		invalid.Versions[0].HashAlgorithmInMultiHashCode = 55

		pcp := mocks.NewMockProtocolClientProvider()
		pcp.ProtocolClients[mocks.DefaultNS] = invalid
		provider := NewOperationProvider(cas, pcp, cp)

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
		provider := NewOperationProvider(mocks.NewMockCasClient(nil), mocks.NewMockProtocolClientProvider(), cp)

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
		handler := NewOperationHandler(cas, pc, cp)

		anchorString, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)

		provider := NewOperationProvider(cas, mocks.NewMockProtocolClientProvider(), cp)

		txnOps, err := provider.GetTxnOperations(&txn.SidetreeTxn{
			Namespace:         defaultNS,
			AnchorString:      anchorString,
			TransactionNumber: 1,
			TransactionTime:   1,
		})

		require.NoError(t, err)
		require.Equal(t, deactivateOpsNum, len(txnOps))
	})

	t.Run("error - protocol client not found for namespace", func(t *testing.T) {
		const createOpsNum = 2

		var ops []*batch.Operation
		ops = append(ops, generateOperations(createOpsNum, batch.OperationTypeCreate)...)
		anchorBytes, err := json.Marshal(models.CreateAnchorFile("", ops))
		require.NoError(t, err)
		require.NotEmpty(t, anchorBytes)

		cas := mocks.NewMockCasClient(nil)
		anchor, err := cas.Write(anchorBytes)
		require.NoError(t, err)

		pcp := mocks.NewMockProtocolClientProvider()
		// delete namespace to cause error in the protocol client provider
		delete(pcp.ProtocolClients, mocks.DefaultNS)

		provider := NewOperationProvider(cas, pcp, cp)

		txnOps, err := provider.GetTxnOperations(&txn.SidetreeTxn{
			Namespace:         defaultNS,
			AnchorString:      "1" + delimiter + anchor,
			TransactionNumber: 1,
			TransactionTime:   1,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "protocol client not found for namespace [did:sidetree]")
		require.Nil(t, txnOps)
	})
}

func TestHandler_GetAnchorFile(t *testing.T) {
	pcp := mocks.NewMockProtocolClientProvider()
	cp := compression.New(compression.WithDefaultAlgorithms())
	p := protocol.Protocol{MaxAnchorFileSize: maxFileSize, CompressionAlgorithm: compressionAlgorithm}

	cas := mocks.NewMockCasClient(nil)
	content, err := cp.Compress(compressionAlgorithm, []byte("{}"))
	require.NoError(t, err)
	address, err := cas.Write(content)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		provider := NewOperationProvider(cas, pcp, cp)

		file, err := provider.getAnchorFile(address, p)
		require.NoError(t, err)
		require.NotNil(t, file)
	})

	t.Run("error - anchor file exceeds maximum size", func(t *testing.T) {
		provider := NewOperationProvider(cas, pcp, cp)

		lowMaxFileSize := protocol.Protocol{MaxAnchorFileSize: 15, CompressionAlgorithm: compressionAlgorithm}

		file, err := provider.getAnchorFile(address, lowMaxFileSize)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "exceeded maximum size 15")
	})

	t.Run("error - parse anchor file error (invalid JSON)", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		content, err := cp.Compress(compressionAlgorithm, []byte("invalid"))
		require.NoError(t, err)
		address, err := cas.Write(content)

		provider := NewOperationProvider(cas, pcp, cp)
		file, err := provider.getAnchorFile(address, p)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to parse content for anchor file")
	})
}

func TestHandler_GetMapFile(t *testing.T) {
	pcp := mocks.NewMockProtocolClientProvider()
	cp := compression.New(compression.WithDefaultAlgorithms())
	p := protocol.Protocol{MaxMapFileSize: maxFileSize, CompressionAlgorithm: compressionAlgorithm}

	cas := mocks.NewMockCasClient(nil)
	content, err := cp.Compress(compressionAlgorithm, []byte("{}"))
	require.NoError(t, err)
	address, err := cas.Write(content)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		provider := NewOperationProvider(cas, pcp, cp)

		file, err := provider.getMapFile(address, p)
		require.NoError(t, err)
		require.NotNil(t, file)
	})

	t.Run("error - map file exceeds maximum size", func(t *testing.T) {
		provider := NewOperationProvider(cas, pcp, cp)

		lowMaxFileSize := protocol.Protocol{MaxMapFileSize: 5, CompressionAlgorithm: compressionAlgorithm}

		file, err := provider.getMapFile(address, lowMaxFileSize)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "exceeded maximum size 5")
	})

	t.Run("error - parse anchor file error (invalid JSON)", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		content, err := cp.Compress(compressionAlgorithm, []byte("invalid"))
		require.NoError(t, err)
		address, err := cas.Write(content)

		provider := NewOperationProvider(cas, pcp, cp)
		file, err := provider.getMapFile(address, p)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to parse content for map file")
	})
}

func TestHandler_GetChunkFile(t *testing.T) {
	pcp := mocks.NewMockProtocolClientProvider()
	cp := compression.New(compression.WithDefaultAlgorithms())
	p := protocol.Protocol{MaxChunkFileSize: maxFileSize, CompressionAlgorithm: compressionAlgorithm}

	cas := mocks.NewMockCasClient(nil)
	content, err := cp.Compress(compressionAlgorithm, []byte("{}"))
	require.NoError(t, err)
	address, err := cas.Write(content)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		provider := NewOperationProvider(cas, pcp, cp)

		file, err := provider.getChunkFile(address, p)
		require.NoError(t, err)
		require.NotNil(t, file)
	})

	t.Run("error - chunk file exceeds maximum size", func(t *testing.T) {
		provider := NewOperationProvider(cas, pcp, cp)

		lowMaxFileSize := protocol.Protocol{MaxChunkFileSize: 10, CompressionAlgorithm: compressionAlgorithm}

		file, err := provider.getChunkFile(address, lowMaxFileSize)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "exceeded maximum size 10")
	})

	t.Run("error - parse chunk file error (invalid JSON)", func(t *testing.T) {
		content, err := cp.Compress(compressionAlgorithm, []byte("invalid"))
		require.NoError(t, err)
		address, err := cas.Write(content)

		provider := NewOperationProvider(cas, pcp, cp)
		file, err := provider.getChunkFile(address, p)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to parse content for chunk file")
	})
}

func TestHandler_readFromCAS(t *testing.T) {
	pcp := mocks.NewMockProtocolClientProvider()
	cp := compression.New(compression.WithDefaultAlgorithms())
	p := protocol.Protocol{MaxChunkFileSize: maxFileSize, CompressionAlgorithm: compressionAlgorithm}

	cas := mocks.NewMockCasClient(nil)
	content, err := cp.Compress(compressionAlgorithm, []byte("{}"))
	require.NoError(t, err)
	address, err := cas.Write(content)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		provider := NewOperationProvider(cas, pcp, cp)

		file, err := provider.readFromCAS(address, compressionAlgorithm, maxFileSize)
		require.NoError(t, err)
		require.NotNil(t, file)
	})

	t.Run("error - read from CAS error", func(t *testing.T) {
		provider := NewOperationProvider(mocks.NewMockCasClient(errors.New("CAS error")), pcp, cp)

		file, err := provider.getChunkFile("address", p)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), " retrieve CAS content[address]: CAS error")
	})

	t.Run("error - content exceeds maximum size", func(t *testing.T) {
		provider := NewOperationProvider(cas, pcp, cp)

		file, err := provider.readFromCAS(address, compressionAlgorithm, 20)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "exceeded maximum size 20")
	})

	t.Run("error - decompression error", func(t *testing.T) {
		provider := NewOperationProvider(cas, pcp, cp)

		file, err := provider.readFromCAS(address, "alg", maxFileSize)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "compression algorithm 'alg' not supported")
	})
}

func TestHandler_assembleBatchOperations(t *testing.T) {
	pcp := mocks.NewMockProtocolClientProvider()

	t.Run("success", func(t *testing.T) {
		provider := NewOperationProvider(nil, pcp, nil)

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
		provider := NewOperationProvider(nil, pcp, nil)

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
					{DidSuffix: deactivateOp.UniqueSuffix, SignedData: deactivateOp.SignedData}},
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

	t.Run("error - invalid delta", func(t *testing.T) {
		provider := NewOperationProvider(nil, pcp, nil)

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
