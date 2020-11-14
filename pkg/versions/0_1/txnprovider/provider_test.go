/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/compression"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/doccomposer"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
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
		handler := NewOperationHandler(pc.Protocol, cas, cp, operationparser.New(pc.Protocol))

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
		handler := NewOperationHandler(pc.Protocol, cas, cp, operationparser.New(pc.Protocol))

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
		require.Contains(t, err.Error(), "error reading core index file: retrieve CAS content at uri[anchor]: CAS error")
	})

	t.Run("error - parse core index operations error", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		handler := NewOperationHandler(pc.Protocol, cas, cp, operationparser.New(pc.Protocol))

		ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

		anchorString, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)

		invalid := mocks.NewMockProtocolClient().Protocol
		invalid.MultihashAlgorithm = 55

		provider := NewOperationProvider(invalid, operationparser.New(invalid), cas, cp)

		txnOps, err := provider.GetTxnOperations(&txn.SidetreeTxn{
			Namespace:         mocks.DefaultNS,
			AnchorString:      anchorString,
			TransactionNumber: 1,
			TransactionTime:   1,
		})

		require.Error(t, err)
		require.Nil(t, txnOps)
		require.Contains(t, err.Error(), "failed to validate suffix data")
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

		var ops []*operation.QueuedOperation
		ops = append(ops, generateOperations(deactivateOpsNum, operation.TypeDeactivate)...)

		cas := mocks.NewMockCasClient(nil)
		handler := NewOperationHandler(pc.Protocol, cas, cp, operationparser.New(pc.Protocol))

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

func TestHandler_GetCoreIndexFile(t *testing.T) {
	cp := compression.New(compression.WithDefaultAlgorithms())
	p := protocol.Protocol{MaxCoreIndexFileSize: maxFileSize, CompressionAlgorithm: compressionAlgorithm}

	cas := mocks.NewMockCasClient(nil)
	content, err := cp.Compress(compressionAlgorithm, []byte("{}"))
	require.NoError(t, err)
	address, err := cas.Write(content)
	require.NoError(t, err)

	parser := operationparser.New(p)

	t.Run("success", func(t *testing.T) {
		provider := NewOperationProvider(p, parser, cas, cp)

		file, err := provider.getCoreIndexFile(address)
		require.NoError(t, err)
		require.NotNil(t, file)
	})

	t.Run("error - core index file exceeds maximum size", func(t *testing.T) {
		provider := NewOperationProvider(protocol.Protocol{MaxCoreIndexFileSize: 15, CompressionAlgorithm: compressionAlgorithm}, parser, cas, cp)

		file, err := provider.getCoreIndexFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "exceeded maximum size 15")
	})

	t.Run("error - parse core index file error (invalid JSON)", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		content, err := cp.Compress(compressionAlgorithm, []byte("invalid"))
		require.NoError(t, err)
		address, err := cas.Write(content)

		provider := NewOperationProvider(p, parser, cas, cp)
		file, err := provider.getCoreIndexFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to parse content for core index file")
	})

	t.Run("error - validate core index file (invalid suffix data)", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate suffix data for first create
		batchFiles.CoreIndex.Operations.Create[0].SuffixData = &model.SuffixDataModel{
			DeltaHash:          "",
			RecoveryCommitment: "",
		}

		invalidCif, err := json.Marshal(batchFiles.CoreIndex)
		require.NoError(t, err)

		cas := mocks.NewMockCasClient(nil)
		content, err := cp.Compress(compressionAlgorithm, invalidCif)
		require.NoError(t, err)
		address, err := cas.Write(content)

		provider := NewOperationProvider(p, parser, cas, cp)
		file, err := provider.getCoreIndexFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to validate suffix data for create[0]")
	})
}

func TestHandler_ValidateCoreIndexFile(t *testing.T) {
	p := mocks.NewMockProtocolClient().Protocol

	t.Run("success", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateCoreIndexFile(batchFiles.CoreIndex)
		require.NoError(t, err)
	})

	t.Run("error - invalid suffix data for create", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate signed data for first recover
		batchFiles.CoreIndex.Operations.Create[0].SuffixData = &model.SuffixDataModel{}

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateCoreIndexFile(batchFiles.CoreIndex)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate suffix data for create[0]")
	})
}

func TestHandler_GetProvisionalIndexFile(t *testing.T) {
	cp := compression.New(compression.WithDefaultAlgorithms())
	p := protocol.Protocol{MaxProvisionalIndexFileSize: maxFileSize, CompressionAlgorithm: compressionAlgorithm}

	cas := mocks.NewMockCasClient(nil)
	content, err := cp.Compress(compressionAlgorithm, []byte("{}"))
	require.NoError(t, err)
	address, err := cas.Write(content)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		file, err := provider.getProvisionalIndexFile(address)
		require.NoError(t, err)
		require.NotNil(t, file)
	})

	t.Run("error - provisional index file exceeds maximum size", func(t *testing.T) {
		lowMaxFileSize := protocol.Protocol{MaxProvisionalIndexFileSize: 5, CompressionAlgorithm: compressionAlgorithm}
		parser := operationparser.New(lowMaxFileSize)
		provider := NewOperationProvider(lowMaxFileSize, parser, cas, cp)

		file, err := provider.getProvisionalIndexFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "exceeded maximum size 5")
	})

	t.Run("error - parse provisional index file error (invalid JSON)", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		content, err := cp.Compress(compressionAlgorithm, []byte("invalid"))
		require.NoError(t, err)
		address, err := cas.Write(content)

		parser := operationparser.New(p)
		provider := NewOperationProvider(p, parser, cas, cp)
		file, err := provider.getProvisionalIndexFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to parse content for provisional index file")
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

	t.Run("error - validate chunk file (invalid delta)", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate first delta
		batchFiles.Chunk.Deltas[0] = &model.DeltaModel{}

		invalid, err := json.Marshal(batchFiles.Chunk)
		require.NoError(t, err)

		cas := mocks.NewMockCasClient(nil)
		content, err := cp.Compress(compressionAlgorithm, invalid)
		require.NoError(t, err)
		address, err := cas.Write(content)

		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)
		file, err := provider.getChunkFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to validate delta[0]")
	})
}

func TestHandler_ValidateChunkFile(t *testing.T) {
	p := mocks.NewMockProtocolClient().Protocol

	t.Run("success", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateChunkFile(batchFiles.Chunk)
		require.NoError(t, err)
	})

	t.Run("error - invalid delta", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate first delta
		batchFiles.Chunk.Deltas[0] = &model.DeltaModel{}

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateChunkFile(batchFiles.Chunk)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate delta[0]")
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
		require.Contains(t, err.Error(), " retrieve CAS content at uri[address]: CAS error")
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

func TestHandler_GetCorePoofFile(t *testing.T) {
	cp := compression.New(compression.WithDefaultAlgorithms())
	p := protocol.Protocol{MaxProofFileSize: maxFileSize, CompressionAlgorithm: compressionAlgorithm}

	cas := mocks.NewMockCasClient(nil)
	content, err := cp.Compress(compressionAlgorithm, []byte("{}"))
	require.NoError(t, err)
	uri, err := cas.Write(content)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		file, err := provider.getCoreProofFile(uri)
		require.NoError(t, err)
		require.NotNil(t, file)
	})

	t.Run("error - core proof file exceeds maximum size", func(t *testing.T) {
		lowMaxFileSize := protocol.Protocol{MaxProofFileSize: 10, CompressionAlgorithm: compressionAlgorithm}
		provider := NewOperationProvider(lowMaxFileSize, operationparser.New(p), cas, cp)

		file, err := provider.getCoreProofFile(uri)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "exceeded maximum size 10")
	})

	t.Run("error - parse core proof file error (invalid JSON)", func(t *testing.T) {
		content, err := cp.Compress(compressionAlgorithm, []byte("invalid"))
		require.NoError(t, err)
		address, err := cas.Write(content)

		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)
		file, err := provider.getCoreProofFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to parse content for core proof file")
	})

	t.Run("error - validate core proof file (invalid signed data)", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate signed data for first recover
		batchFiles.CoreProof.Operations.Recover[0] = "invalid-jws"

		invalid, err := json.Marshal(batchFiles.CoreProof)
		require.NoError(t, err)

		cas := mocks.NewMockCasClient(nil)
		content, err := cp.Compress(compressionAlgorithm, invalid)
		require.NoError(t, err)
		address, err := cas.Write(content)

		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)
		file, err := provider.getCoreProofFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to validate signed data for recover[0]")
	})
}

func TestHandler_ValidateCorePoofFile(t *testing.T) {
	p := mocks.NewMockProtocolClient().Protocol

	t.Run("success", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateCoreProofFile(batchFiles.CoreProof)
		require.NoError(t, err)
	})

	t.Run("error - invalid signed data for recover", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate signed data for first recover
		batchFiles.CoreProof.Operations.Recover[0] = "recover-jws"

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateCoreProofFile(batchFiles.CoreProof)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate signed data for recover[0]")
	})

	t.Run("error - invalid signed data for deactivate", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate signed data for first deactivate
		batchFiles.CoreProof.Operations.Deactivate[0] = "deactivate-jws"

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateCoreProofFile(batchFiles.CoreProof)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate signed data for deactivate[0]")
	})
}

func TestHandler_GetProvisionalPoofFile(t *testing.T) {
	cp := compression.New(compression.WithDefaultAlgorithms())
	p := protocol.Protocol{MaxProofFileSize: maxFileSize, CompressionAlgorithm: compressionAlgorithm}

	cas := mocks.NewMockCasClient(nil)
	content, err := cp.Compress(compressionAlgorithm, []byte("{}"))
	require.NoError(t, err)
	uri, err := cas.Write(content)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		file, err := provider.getProvisionalProofFile(uri)
		require.NoError(t, err)
		require.NotNil(t, file)
	})

	t.Run("error - core provisional file exceeds maximum size", func(t *testing.T) {
		lowMaxFileSize := protocol.Protocol{MaxProofFileSize: 10, CompressionAlgorithm: compressionAlgorithm}
		provider := NewOperationProvider(lowMaxFileSize, operationparser.New(p), cas, cp)

		file, err := provider.getProvisionalProofFile(uri)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "exceeded maximum size 10")
	})

	t.Run("error - parse provisional proof file error (invalid JSON)", func(t *testing.T) {
		content, err := cp.Compress(compressionAlgorithm, []byte("invalid"))
		require.NoError(t, err)
		address, err := cas.Write(content)

		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)
		file, err := provider.getProvisionalProofFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to parse content for provisional proof file")
	})

	t.Run("error - validate provisional proof file (invalid signed data)", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate signed data for first update
		batchFiles.ProvisionalProof.Operations.Update[0] = "invalid-jws"

		invalid, err := json.Marshal(batchFiles.ProvisionalProof)
		require.NoError(t, err)

		cas := mocks.NewMockCasClient(nil)
		content, err := cp.Compress(compressionAlgorithm, invalid)
		require.NoError(t, err)
		address, err := cas.Write(content)

		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)
		file, err := provider.getProvisionalProofFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to validate signed data for update[0]")
	})
}

func TestHandler_ValidateProvisionalPoofFile(t *testing.T) {
	p := mocks.NewMockProtocolClient().Protocol

	t.Run("success", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateProvisionalProofFile(batchFiles.ProvisionalProof)
		require.NoError(t, err)
	})

	t.Run("error - invalid signed data for update", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate signed data for first update
		batchFiles.ProvisionalProof.Operations.Update[0] = "jws"

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateProvisionalProofFile(batchFiles.ProvisionalProof)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate signed data for update[0]")
	})
}

func TestHandler_GetBatchFiles(t *testing.T) {
	cp := compression.New(compression.WithDefaultAlgorithms())

	cas := mocks.NewMockCasClient(nil)
	content, err := cp.Compress(compressionAlgorithm, []byte("{}"))
	require.NoError(t, err)
	uri, err := cas.Write(content)
	require.NoError(t, err)

	provisionalIndexFile, err := cp.Compress(compressionAlgorithm, []byte(fmt.Sprintf(`{"provisionalProofFileUri":"%s","chunks":[{"chunkFileUri":"%s"}]}`, uri, uri)))
	require.NoError(t, err)
	mapURI, err := cas.Write(provisionalIndexFile)
	require.NoError(t, err)

	af := &models.CoreIndexFile{
		ProvisionalIndexFileURI: mapURI,
		CoreProofFileURI:        uri,
	}

	t.Run("success", func(t *testing.T) {
		p := newMockProtocolClient().Protocol
		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		file, err := provider.getBatchFiles(af)
		require.NoError(t, err)
		require.NotNil(t, file)
	})

	t.Run("error - retrieve provisional index file", func(t *testing.T) {
		p := newMockProtocolClient().Protocol
		p.MaxProvisionalIndexFileSize = 10

		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		file, err := provider.getBatchFiles(af)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "exceeded maximum size 10")
	})

	t.Run("error - retrieve core proof file", func(t *testing.T) {
		p := newMockProtocolClient().Protocol
		p.MaxProofFileSize = 7

		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		file, err := provider.getBatchFiles(af)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "exceeded maximum size 7")
	})

	t.Run("error - retrieve provisional proof file", func(t *testing.T) {
		p := newMockProtocolClient().Protocol

		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		content, err := cp.Compress(compressionAlgorithm, []byte("invalid"))
		ppfURI, err := cas.Write(content)
		require.NoError(t, err)

		provisionalIndexFile, err := cp.Compress(compressionAlgorithm, []byte(fmt.Sprintf(`{"provisionalProofFileUri":"%s","chunks":[{"chunkFileUri":"%s"}]}`, ppfURI, uri)))
		require.NoError(t, err)
		provisionalIndexURI, err := cas.Write(provisionalIndexFile)
		require.NoError(t, err)

		af2 := &models.CoreIndexFile{
			ProvisionalIndexFileURI: provisionalIndexURI,
			CoreProofFileURI:        uri,
		}

		file, err := provider.getBatchFiles(af2)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to unmarshal provisional proof file: invalid character")
	})

	t.Run("error - provisional index file is missing chunk file URI", func(t *testing.T) {
		p := newMockProtocolClient().Protocol

		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		af2 := &models.CoreIndexFile{
			ProvisionalIndexFileURI: uri,
			CoreProofFileURI:        uri,
		}

		file, err := provider.getBatchFiles(af2)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "provisional index file is missing chunk file URI")
	})

	t.Run("error - retrieve chunk file", func(t *testing.T) {
		p := newMockProtocolClient().Protocol
		p.MaxChunkFileSize = 10

		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		file, err := provider.getBatchFiles(af)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "exceeded maximum size 10")
	})

	t.Run("error - missing core proof URI", func(t *testing.T) {
		p := newMockProtocolClient().Protocol
		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		recoverOp, err := generateOperation(1, operation.TypeRecover)
		require.NoError(t, err)

		cif := &models.CoreIndexFile{
			ProvisionalIndexFileURI: "provisionalIndexURI",
			CoreProofFileURI:        "",
			Operations: models.CoreOperations{
				Recover: []models.SignedOperation{
					{
						DidSuffix:   recoverOp.UniqueSuffix,
						RevealValue: recoverOp.RevealValue,
					},
				},
			},
		}

		file, err := provider.getBatchFiles(cif)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "missing core proof file URI")
	})

	t.Run("error - missing provisional proof URI", func(t *testing.T) {
		p := newMockProtocolClient().Protocol
		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		updateOp, err := generateOperation(1, operation.TypeUpdate)
		require.NoError(t, err)

		pif := &models.ProvisionalIndexFile{
			ProvisionalProofFileURI: "",
			Operations: models.ProvisionalOperations{
				Update: []models.SignedOperation{
					{
						DidSuffix:   updateOp.UniqueSuffix,
						RevealValue: updateOp.RevealValue,
					},
				},
			},
		}

		pifBytes, err := json.Marshal(pif)
		require.NoError(t, err)

		compressed, err := cp.Compress(compressionAlgorithm, pifBytes)
		require.NoError(t, err)
		pifURI, err := cas.Write(compressed)
		require.NoError(t, err)

		cif := &models.CoreIndexFile{
			ProvisionalIndexFileURI: pifURI,
		}

		file, err := provider.getBatchFiles(cif)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "missing provisional proof file URI")
	})

	t.Run("error - validate batch counts", func(t *testing.T) {
		p := newMockProtocolClient().Protocol
		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		recoverOp, err := generateOperation(3, operation.TypeRecover)
		require.NoError(t, err)

		cpf := &models.CoreProofFile{
			Operations: models.CoreProofOperations{
				Recover: []string{},
			},
		}

		cpfBytes, err := json.Marshal(cpf)
		require.NoError(t, err)

		compressed, err := cp.Compress(compressionAlgorithm, cpfBytes)
		require.NoError(t, err)
		cpfURI, err := cas.Write(compressed)
		require.NoError(t, err)

		cif := &models.CoreIndexFile{
			CoreProofFileURI: cpfURI,
			Operations: models.CoreOperations{
				Recover: []models.SignedOperation{
					{
						DidSuffix:   recoverOp.UniqueSuffix,
						RevealValue: recoverOp.RevealValue,
					},
				},
			},
		}

		file, err := provider.getBatchFiles(cif)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "number of recover ops[1] in core index doesn't match number of recover ops[0] in core proof")
	})

	t.Run("error - provisional index file is missing chunk file URI", func(t *testing.T) {
		p := newMockProtocolClient().Protocol

		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		af2 := &models.CoreIndexFile{
			ProvisionalIndexFileURI: uri,
			CoreProofFileURI:        uri,
		}

		file, err := provider.getBatchFiles(af2)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "provisional index file is missing chunk file URI")
	})
}

func TestHandler_assembleBatchOperations(t *testing.T) {
	p := newMockProtocolClient().Protocol

	t.Run("success", func(t *testing.T) {
		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)

		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		anchoredOps, err := provider.assembleAnchoredOperations(batchFiles, &txn.SidetreeTxn{Namespace: defaultNS})
		require.NoError(t, err)
		require.Equal(t, 4, len(anchoredOps))
	})

	t.Run("error - core/provisional index, chunk file operation number mismatch", func(t *testing.T) {
		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)

		createOp, err := generateOperation(1, operation.TypeCreate)
		require.NoError(t, err)

		updateOp, err := generateOperation(2, operation.TypeUpdate)
		require.NoError(t, err)

		deactivateOp, err := generateOperation(3, operation.TypeDeactivate)
		require.NoError(t, err)

		cif := &models.CoreIndexFile{
			ProvisionalIndexFileURI: "hash",
			Operations: models.CoreOperations{
				Create: []models.CreateOperation{{SuffixData: createOp.SuffixData}},
				Deactivate: []models.SignedOperation{
					{DidSuffix: deactivateOp.UniqueSuffix, RevealValue: deactivateOp.RevealValue},
				},
			},
		}

		pif := &models.ProvisionalIndexFile{
			Chunks: []models.Chunk{},
			Operations: models.ProvisionalOperations{
				Update: []models.SignedOperation{{DidSuffix: updateOp.UniqueSuffix, RevealValue: updateOp.RevealValue}},
			},
		}

		// don't add update operation delta to chunk file in order to cause error
		cf := &models.ChunkFile{Deltas: []*model.DeltaModel{createOp.Delta}}

		cpf := &models.CoreProofFile{
			Operations: models.CoreProofOperations{
				Deactivate: []string{deactivateOp.SignedData},
			},
		}

		ppf := &models.ProvisionalProofFile{
			Operations: models.ProvisionalProofOperations{
				Update: []string{updateOp.SignedData},
			},
		}

		batchFiles := &batchFiles{
			CoreIndex:        cif,
			CoreProof:        cpf,
			ProvisionalIndex: pif,
			ProvisionalProof: ppf,
			Chunk:            cf,
		}

		anchoredOps, err := provider.assembleAnchoredOperations(batchFiles, &txn.SidetreeTxn{Namespace: defaultNS})
		require.Error(t, err)
		require.Nil(t, anchoredOps)
		require.Contains(t, err.Error(),
			"number of create+recover+update operations[2] doesn't match number of deltas[1]")
	})

	t.Run("error - duplicate operations found in core/provisional index files", func(t *testing.T) {
		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)

		createOp, err := generateOperation(1, operation.TypeCreate)
		require.NoError(t, err)

		updateOp, err := generateOperation(2, operation.TypeUpdate)
		require.NoError(t, err)

		deactivateOp, err := generateOperation(3, operation.TypeDeactivate)
		require.NoError(t, err)

		cif := &models.CoreIndexFile{
			ProvisionalIndexFileURI: "hash",
			Operations: models.CoreOperations{
				Create: []models.CreateOperation{{SuffixData: createOp.SuffixData}},
				Deactivate: []models.SignedOperation{
					{DidSuffix: deactivateOp.UniqueSuffix, RevealValue: deactivateOp.RevealValue},
					{DidSuffix: deactivateOp.UniqueSuffix, RevealValue: deactivateOp.RevealValue},
				},
			},
		}

		pif := &models.ProvisionalIndexFile{
			Chunks: []models.Chunk{},
			Operations: models.ProvisionalOperations{
				Update: []models.SignedOperation{
					{DidSuffix: updateOp.UniqueSuffix, RevealValue: updateOp.RevealValue},
					{DidSuffix: updateOp.UniqueSuffix, RevealValue: updateOp.RevealValue},
				},
			},
		}

		cf := &models.ChunkFile{Deltas: []*model.DeltaModel{createOp.Delta}}

		cpf := &models.CoreProofFile{
			Operations: models.CoreProofOperations{
				Deactivate: []string{deactivateOp.SignedData, deactivateOp.SignedData},
			},
		}

		batchFiles := &batchFiles{
			CoreIndex:        cif,
			CoreProof:        cpf,
			ProvisionalIndex: pif,
			Chunk:            cf,
		}

		anchoredOps, err := provider.assembleAnchoredOperations(batchFiles, &txn.SidetreeTxn{Namespace: defaultNS})
		require.Error(t, err)
		require.Nil(t, anchoredOps)
		require.Contains(t, err.Error(),
			"check for duplicate suffixes in core/provisional index files: duplicate values found [deactivate-3 update-2]")
	})
}

func TestValidateBatchFileCounts(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		err = validateBatchFileCounts(batchFiles)
		require.NoError(t, err)
	})

	t.Run("error - deactivate ops number mismatch", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		batchFiles.CoreProof.Operations.Deactivate = []string{}

		err = validateBatchFileCounts(batchFiles)
		require.Error(t, err)
		require.Contains(t, err.Error(), "number of deactivate ops[1] in core index doesn't match number of deactivate ops[0] in core proof")
	})

	t.Run("error - recover ops number mismatch", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		batchFiles.CoreProof.Operations.Recover = []string{}

		err = validateBatchFileCounts(batchFiles)
		require.Error(t, err)
		require.Contains(t, err.Error(), "number of recover ops[1] in core index doesn't match number of recover ops[0] in core proof")
	})

	t.Run("error - update ops number mismatch", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		batchFiles.ProvisionalProof.Operations.Update = []string{}

		err = validateBatchFileCounts(batchFiles)
		require.Error(t, err)
		require.Contains(t, err.Error(), "number of update ops[1] in provisional index doesn't match number of update ops[0] in provisional proof")
	})

	t.Run("error - delta mismatch", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		batchFiles.Chunk.Deltas = []*model.DeltaModel{}

		err = validateBatchFileCounts(batchFiles)
		require.Error(t, err)
		require.Contains(t, err.Error(), "number of create+recover+update operations[3] doesn't match number of deltas[0]")
	})
}

func generateDefaultBatchFiles() (*batchFiles, error) {
	createOp, err := generateOperation(1, operation.TypeCreate)
	if err != nil {
		return nil, err
	}

	updateOp, err := generateOperation(2, operation.TypeUpdate)
	if err != nil {
		return nil, err
	}

	recoverOp, err := generateOperation(3, operation.TypeRecover)
	if err != nil {
		return nil, err
	}

	deactivateOp, err := generateOperation(4, operation.TypeDeactivate)
	if err != nil {
		return nil, err
	}

	cif := &models.CoreIndexFile{
		ProvisionalIndexFileURI: "provisionalIndexURI",
		CoreProofFileURI:        "coreProofURI",
		Operations: models.CoreOperations{
			Create: []models.CreateOperation{{SuffixData: createOp.SuffixData}},
			Recover: []models.SignedOperation{
				{
					DidSuffix:   recoverOp.UniqueSuffix,
					RevealValue: recoverOp.RevealValue,
				},
			},
			Deactivate: []models.SignedOperation{
				{
					DidSuffix:   deactivateOp.UniqueSuffix,
					RevealValue: deactivateOp.RevealValue,
				},
			},
		},
	}

	pif := &models.ProvisionalIndexFile{
		Chunks:                  []models.Chunk{{ChunkFileURI: "chunkURI"}},
		ProvisionalProofFileURI: "provisionalProofURI",
		Operations: models.ProvisionalOperations{
			Update: []models.SignedOperation{
				{
					DidSuffix:   updateOp.UniqueSuffix,
					RevealValue: updateOp.RevealValue,
				},
			},
		},
	}

	cf := &models.ChunkFile{Deltas: []*model.DeltaModel{createOp.Delta, recoverOp.Delta, updateOp.Delta}}

	cpf := &models.CoreProofFile{
		Operations: models.CoreProofOperations{
			Recover:    []string{recoverOp.SignedData},
			Deactivate: []string{deactivateOp.SignedData},
		},
	}

	ppf := &models.ProvisionalProofFile{
		Operations: models.ProvisionalProofOperations{
			Update: []string{updateOp.SignedData},
		},
	}

	return &batchFiles{
		CoreIndex:        cif,
		CoreProof:        cpf,
		ProvisionalIndex: pif,
		ProvisionalProof: ppf,
		Chunk:            cf,
	}, nil
}

func newMockProtocolClient() *mocks.MockProtocolClient {
	pc := mocks.NewMockProtocolClient()
	parser := operationparser.New(pc.Protocol)
	dc := doccomposer.New()

	pv := pc.CurrentVersion
	pv.OperationParserReturns(parser)
	pv.DocumentComposerReturns(dc)

	return pc
}
