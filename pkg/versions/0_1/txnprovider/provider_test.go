/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnprovider

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
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

	sampleCasURI = "bafkreih6ot2yfqcerzp5l2qupc77it2vdmepfhszitmswnpdtk34m4ura4"
	longValue    = "bafkreih6ot2yfqcerzp5l2qupc77it2vdmepfhszitmswnpdtk34m4ura4bafkreih6ot2yfqcerzp5l2qupc77it2vdmepfhszitmswnpdtk34m4ura4"
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

		anchorString, refs, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)
		require.Equal(t, len(refs), createOpsNum+updateOpsNum+deactivateOpsNum+recoverOpsNum)

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

	t.Run("error - delta exceeds maximum delta size in chunk file", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		handler := NewOperationHandler(pc.Protocol, cas, cp, operationparser.New(pc.Protocol))

		ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

		anchorString, refs, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)
		require.Equal(t, len(refs), createOpsNum+updateOpsNum+deactivateOpsNum+recoverOpsNum)

		smallDeltaProofSize := mocks.GetDefaultProtocolParameters()
		smallDeltaProofSize.MaxDeltaSize = 50

		provider := NewOperationProvider(smallDeltaProofSize, operationparser.New(smallDeltaProofSize), cas, cp)

		txnOps, err := provider.GetTxnOperations(&txn.SidetreeTxn{
			Namespace:         defaultNS,
			AnchorString:      anchorString,
			TransactionNumber: 1,
			TransactionTime:   1,
		})

		require.Error(t, err)
		require.Nil(t, txnOps)
		require.Contains(t, err.Error(), "failed to validate delta[0]: delta size[160] exceeds maximum delta size[50]")
	})

	t.Run("error - number of operations doesn't match", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		handler := NewOperationHandler(pc.Protocol, cas, cp, operationparser.New(pc.Protocol))

		ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

		// anchor string has 9 operations "9.coreIndexURI"
		anchorString, _, err := handler.PrepareTxnFiles(ops)
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
			AnchorString:      "1" + delimiter + "coreIndexURI",
			TransactionNumber: 1,
			TransactionTime:   1,
		})

		require.Error(t, err)
		require.Nil(t, txnOps)
		require.Contains(t, err.Error(), "error reading core index file: retrieve CAS content at uri[coreIndexURI]: CAS error")
	})

	t.Run("error - parse core index operations error", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		handler := NewOperationHandler(pc.Protocol, cas, cp, operationparser.New(pc.Protocol))

		ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

		anchorString, _, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)

		invalid := mocks.NewMockProtocolClient().Protocol
		invalid.MultihashAlgorithms = []uint{55}

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

		anchorString, refs, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)
		require.Equal(t, len(refs), deactivateOpsNum)
		require.Equal(t, refs[0].Type, operation.TypeDeactivate)

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

	t.Run("success - update only", func(t *testing.T) {
		const updateOpsNum = 2

		var ops []*operation.QueuedOperation
		ops = append(ops, generateOperations(updateOpsNum, operation.TypeUpdate)...)

		cas := mocks.NewMockCasClient(nil)
		handler := NewOperationHandler(pc.Protocol, cas, cp, operationparser.New(pc.Protocol))

		anchorString, refs, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)
		require.Equal(t, len(refs), updateOpsNum)
		require.Equal(t, refs[0].Type, operation.TypeUpdate)

		p := mocks.NewMockProtocolClient().Protocol
		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		txnOps, err := provider.GetTxnOperations(&txn.SidetreeTxn{
			Namespace:         defaultNS,
			AnchorString:      anchorString,
			TransactionNumber: 1,
			TransactionTime:   1,
		})

		require.NoError(t, err)
		require.Equal(t, updateOpsNum, len(txnOps))
	})

	t.Run("success - create only", func(t *testing.T) {
		const createOpsNum = 2

		var ops []*operation.QueuedOperation
		ops = append(ops, generateOperations(createOpsNum, operation.TypeCreate)...)

		cas := mocks.NewMockCasClient(nil)
		handler := NewOperationHandler(pc.Protocol, cas, cp, operationparser.New(pc.Protocol))

		anchorString, refs, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)
		require.Equal(t, len(refs), createOpsNum)
		require.Equal(t, refs[0].Type, operation.TypeCreate)

		p := mocks.NewMockProtocolClient().Protocol
		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		txnOps, err := provider.GetTxnOperations(&txn.SidetreeTxn{
			Namespace:         defaultNS,
			AnchorString:      anchorString,
			TransactionNumber: 1,
			TransactionTime:   1,
		})

		require.NoError(t, err)
		require.Equal(t, createOpsNum, len(txnOps))
	})

	t.Run("success - recover only", func(t *testing.T) {
		const recoverOpsNum = 2

		var ops []*operation.QueuedOperation
		ops = append(ops, generateOperations(recoverOpsNum, operation.TypeRecover)...)

		cas := mocks.NewMockCasClient(nil)
		handler := NewOperationHandler(pc.Protocol, cas, cp, operationparser.New(pc.Protocol))

		anchorString, refs, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)
		require.Equal(t, len(refs), recoverOpsNum)
		require.Equal(t, refs[0].Type, operation.TypeRecover)

		p := mocks.NewMockProtocolClient().Protocol
		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		txnOps, err := provider.GetTxnOperations(&txn.SidetreeTxn{
			Namespace:         defaultNS,
			AnchorString:      anchorString,
			TransactionNumber: 1,
			TransactionTime:   1,
		})

		require.NoError(t, err)
		require.Equal(t, recoverOpsNum, len(txnOps))
	})
}

func TestHandler_GetCoreIndexFile(t *testing.T) {
	cp := compression.New(compression.WithDefaultAlgorithms())
	p := protocol.Protocol{
		MaxCoreIndexFileSize: maxFileSize,
		CompressionAlgorithm: compressionAlgorithm,
		MaxCasURILength:      100,
		MultihashAlgorithms:  []uint{sha2_256},
	}

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

	t.Run("error - missing core proof URI", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate signed data for first recover
		batchFiles.CoreIndex.CoreProofFileURI = ""

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateCoreIndexFile(batchFiles.CoreIndex)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing core proof file URI")
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

	t.Run("error - missing core proof URI", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate core proof URI
		batchFiles.CoreIndex.CoreProofFileURI = ""

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateCoreIndexFile(batchFiles.CoreIndex)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing core proof file URI")
	})

	t.Run("error - core proof URI present without recover and deactivate ops", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate deactivate and recover operations
		batchFiles.CoreIndex.Operations.Deactivate = nil
		batchFiles.CoreIndex.Operations.Recover = nil

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateCoreIndexFile(batchFiles.CoreIndex)
		require.Error(t, err)
		require.Contains(t, err.Error(), "core proof file URI should be empty if there are no recover and/or deactivate operations")
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

	t.Run("error - invalid did suffix for recover", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate did suffix for first recover
		batchFiles.CoreIndex.Operations.Recover[0].DidSuffix = ""

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateCoreIndexFile(batchFiles.CoreIndex)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate operation reference for recover[0]: missing did suffix")
	})

	t.Run("error - invalid reveal value for deactivate", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate reveal value for first deactivate
		batchFiles.CoreIndex.Operations.Deactivate[0].RevealValue = ""

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateCoreIndexFile(batchFiles.CoreIndex)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate operation reference for deactivate[0]: missing reveal value")
	})

	t.Run("error - reveal value exceeds maximum hash length", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate reveal value for first deactivate
		batchFiles.CoreIndex.Operations.Deactivate[0].RevealValue = longValue

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateCoreIndexFile(batchFiles.CoreIndex)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate operation reference for deactivate[0]: reveal value length[118] exceeds maximum hash length[100]")
	})

	t.Run("error - did suffix exceeds maximum hash length", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate reveal value for first deactivate
		batchFiles.CoreIndex.Operations.Recover[0].DidSuffix = longValue

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateCoreIndexFile(batchFiles.CoreIndex)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate operation reference for recover[0]: did suffix length[118] exceeds maximum hash length[100]")
	})

	t.Run("error - recovery commitment length exceeds max hash length", func(t *testing.T) {
		lowMaxHashLength := mocks.GetDefaultProtocolParameters()
		lowMaxHashLength.MaxOperationHashLength = 10

		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		provider := NewOperationProvider(lowMaxHashLength, operationparser.New(lowMaxHashLength), nil, nil)
		err = provider.validateCoreIndexFile(batchFiles.CoreIndex)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate suffix data for create[0]: recovery commitment length[46] exceeds maximum hash length[10]")
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

func TestHandler_ValidateProvisionalIndexFile(t *testing.T) {
	p := mocks.NewMockProtocolClient().Protocol

	t.Run("success", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateProvisionalIndexFile(batchFiles.ProvisionalIndex)
		require.NoError(t, err)
	})

	t.Run("error - missing provisional proof file", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate provisional proof URI
		batchFiles.ProvisionalIndex.ProvisionalProofFileURI = ""

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateProvisionalIndexFile(batchFiles.ProvisionalIndex)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing provisional proof file URI")
	})

	t.Run("error - provisional proof file uri present without update ops", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// remove update operations
		batchFiles.ProvisionalIndex.Operations.Update = nil

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateProvisionalIndexFile(batchFiles.ProvisionalIndex)
		require.Error(t, err)
		require.Contains(t, err.Error(), "provisional proof file URI should be empty if there are no update operations")
	})

	t.Run("error - missing did suffix", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate did suffix
		batchFiles.ProvisionalIndex.Operations.Update[0].DidSuffix = ""

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateProvisionalIndexFile(batchFiles.ProvisionalIndex)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate operation reference for update[0]: missing did suffix")
	})

	t.Run("error - missing reveal value", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// invalidate did suffix
		batchFiles.ProvisionalIndex.Operations.Update[0].RevealValue = ""

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateProvisionalIndexFile(batchFiles.ProvisionalIndex)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to validate operation reference for update[0]: missing reveal value")
	})

	t.Run("success - validate IPFS CID", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// set valid IPFS CID
		batchFiles.ProvisionalIndex.ProvisionalProofFileURI = sampleCasURI

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateProvisionalIndexFile(batchFiles.ProvisionalIndex)
		require.NoError(t, err)
	})

	t.Run("error - provisional proof URI too long", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		batchFiles.ProvisionalIndex.ProvisionalProofFileURI = longValue

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateProvisionalIndexFile(batchFiles.ProvisionalIndex)
		require.Error(t, err)
		require.Contains(t, err.Error(), "provisional proof URI: CAS URI length[118] exceeds maximum CAS URI length[100]")
	})

	t.Run("error - chunk URI too long", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		batchFiles.ProvisionalIndex.Chunks[0].ChunkFileURI = longValue

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateProvisionalIndexFile(batchFiles.ProvisionalIndex)
		require.Error(t, err)
		require.Contains(t, err.Error(), "chunk URI: CAS URI length[118] exceeds maximum CAS URI length[100]")
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

	t.Run("success - validate IPFS CID", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		// set valid IPFS CID
		batchFiles.CoreIndex.CoreProofFileURI = sampleCasURI

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateCoreIndexFile(batchFiles.CoreIndex)
		require.NoError(t, err)
	})

	t.Run("error - core proof URI too long", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		batchFiles.CoreIndex.CoreProofFileURI = longValue

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateCoreIndexFile(batchFiles.CoreIndex)
		require.Error(t, err)
		require.Contains(t, err.Error(), "core proof URI: CAS URI length[118] exceeds maximum CAS URI length[100]")
	})

	t.Run("error - provisional index URI too long", func(t *testing.T) {
		batchFiles, err := generateDefaultBatchFiles()
		require.NoError(t, err)

		batchFiles.CoreIndex.ProvisionalIndexFileURI = longValue

		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)
		err = provider.validateCoreIndexFile(batchFiles.CoreIndex)
		require.Error(t, err)
		require.Contains(t, err.Error(), "provisional index URI: CAS URI length[118] exceeds maximum CAS URI length[100]")
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

	updateOp, err := generateOperation(1, operation.TypeUpdate)
	require.NoError(t, err)

	recoverOp, err := generateOperation(2, operation.TypeRecover)
	require.NoError(t, err)

	ppf := &models.ProvisionalProofFile{
		Operations: models.ProvisionalProofOperations{
			Update: []string{updateOp.SignedData},
		},
	}

	ppfURI, err := writeToCAS(ppf, cas)
	require.NoError(t, err)

	cf := &models.ChunkFile{Deltas: []*model.DeltaModel{recoverOp.Delta, updateOp.Delta}}

	chunkURI, err := writeToCAS(cf, cas)
	require.NoError(t, err)

	pif := &models.ProvisionalIndexFile{
		Chunks:                  []models.Chunk{{ChunkFileURI: chunkURI}},
		ProvisionalProofFileURI: ppfURI,
		Operations: &models.ProvisionalOperations{
			Update: []models.OperationReference{
				{
					DidSuffix:   updateOp.UniqueSuffix,
					RevealValue: updateOp.RevealValue,
				},
			},
		},
	}

	pifURI, err := writeToCAS(pif, cas)
	require.NoError(t, err)

	cpf := &models.CoreProofFile{
		Operations: models.CoreProofOperations{
			Recover: []string{recoverOp.SignedData},
		},
	}

	cpfURI, err := writeToCAS(cpf, cas)
	require.NoError(t, err)

	af := &models.CoreIndexFile{
		ProvisionalIndexFileURI: pifURI,
		CoreProofFileURI:        cpfURI,
		Operations: &models.CoreOperations{
			Recover: []models.OperationReference{
				{
					DidSuffix:   recoverOp.UniqueSuffix,
					RevealValue: recoverOp.RevealValue,
				},
			},
		},
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
		invalidContentURI, err := cas.Write(content)
		require.NoError(t, err)

		pif2 := &models.ProvisionalIndexFile{
			Chunks:                  []models.Chunk{{ChunkFileURI: chunkURI}},
			ProvisionalProofFileURI: invalidContentURI,
			Operations: &models.ProvisionalOperations{
				Update: []models.OperationReference{
					{
						DidSuffix:   updateOp.UniqueSuffix,
						RevealValue: updateOp.RevealValue,
					},
				},
			},
		}

		provisionalIndexURI, err := writeToCAS(pif2, cas)
		require.NoError(t, err)

		af2 := &models.CoreIndexFile{
			ProvisionalIndexFileURI: provisionalIndexURI,
			CoreProofFileURI:        "",
		}

		file, err := provider.getBatchFiles(af2)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to unmarshal provisional proof file: invalid character")
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

	t.Run("error - missing provisional proof URI", func(t *testing.T) {
		p := newMockProtocolClient().Protocol
		provider := NewOperationProvider(p, operationparser.New(p), cas, cp)

		updateOp, err := generateOperation(1, operation.TypeUpdate)
		require.NoError(t, err)

		pif2 := &models.ProvisionalIndexFile{
			ProvisionalProofFileURI: "",
			Operations: &models.ProvisionalOperations{
				Update: []models.OperationReference{
					{
						DidSuffix:   updateOp.UniqueSuffix,
						RevealValue: updateOp.RevealValue,
					},
				},
			},
		}

		pif2URI, err := writeToCAS(pif2, cas)
		require.NoError(t, err)

		cif := &models.CoreIndexFile{
			ProvisionalIndexFileURI: pif2URI,
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
			Operations: &models.CoreOperations{
				Recover: []models.OperationReference{
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

		missingChunkURI, err := writeToCAS(&models.ProvisionalIndexFile{}, cas)
		require.NoError(t, err)

		file, err := provider.getBatchFiles(&models.CoreIndexFile{
			ProvisionalIndexFileURI: missingChunkURI,
		})
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
			Operations: &models.CoreOperations{
				Create: []models.CreateReference{{SuffixData: createOp.SuffixData}},
				Deactivate: []models.OperationReference{
					{DidSuffix: deactivateOp.UniqueSuffix, RevealValue: deactivateOp.RevealValue},
				},
			},
		}

		pif := &models.ProvisionalIndexFile{
			Chunks: []models.Chunk{},
			Operations: &models.ProvisionalOperations{
				Update: []models.OperationReference{{DidSuffix: updateOp.UniqueSuffix, RevealValue: updateOp.RevealValue}},
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
			Operations: &models.CoreOperations{
				Create: []models.CreateReference{{SuffixData: createOp.SuffixData}},
				Deactivate: []models.OperationReference{
					{DidSuffix: "test-suffix", RevealValue: deactivateOp.RevealValue},
				},
			},
		}

		pif := &models.ProvisionalIndexFile{
			Chunks: []models.Chunk{},
			Operations: &models.ProvisionalOperations{
				Update: []models.OperationReference{
					{DidSuffix: "test-suffix", RevealValue: updateOp.RevealValue},
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
			"check for duplicate suffixes in core/provisional index files: duplicate values found [test-suffix]")
	})

	t.Run("error - duplicate operations found in core index file", func(t *testing.T) {
		provider := NewOperationProvider(p, operationparser.New(p), nil, nil)

		createOp, err := generateOperation(1, operation.TypeCreate)
		require.NoError(t, err)

		updateOp, err := generateOperation(2, operation.TypeUpdate)
		require.NoError(t, err)

		deactivateOp, err := generateOperation(3, operation.TypeDeactivate)
		require.NoError(t, err)

		cif := &models.CoreIndexFile{
			ProvisionalIndexFileURI: "hash",
			Operations: &models.CoreOperations{
				Create: []models.CreateReference{{SuffixData: createOp.SuffixData}},
				Deactivate: []models.OperationReference{
					{DidSuffix: deactivateOp.UniqueSuffix, RevealValue: deactivateOp.RevealValue},
					{DidSuffix: deactivateOp.UniqueSuffix, RevealValue: deactivateOp.RevealValue},
				},
			},
		}

		pif := &models.ProvisionalIndexFile{
			Chunks: []models.Chunk{},
			Operations: &models.ProvisionalOperations{
				Update: []models.OperationReference{
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
			"check for duplicate suffixes in core index files: duplicate values found [deactivate-3]")
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
		Operations: &models.CoreOperations{
			Create: []models.CreateReference{{SuffixData: createOp.SuffixData}},
			Recover: []models.OperationReference{
				{
					DidSuffix:   recoverOp.UniqueSuffix,
					RevealValue: recoverOp.RevealValue,
				},
			},
			Deactivate: []models.OperationReference{
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
		Operations: &models.ProvisionalOperations{
			Update: []models.OperationReference{
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

func writeToCAS(value interface{}, cas cas.Client) (string, error) {
	bytes, err := canonicalizer.MarshalCanonical(value)
	if err != nil {
		return "", err
	}

	cp := compression.New(compression.WithDefaultAlgorithms())

	compressed, err := cp.Compress(compressionAlgorithm, bytes)
	if err != nil {
		return "", err
	}

	return cas.Write(compressed)
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
