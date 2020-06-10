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
		invalid.Protocol.HashAlgorithmInMultiHashCode = 55

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
