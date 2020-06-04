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
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/txnhandler/models"
)

func TestNewOperationProvider(t *testing.T) {
	handler := NewOperationProvider(mocks.NewMockCasClient(nil), mocks.NewMockProtocolClientProvider())
	require.NotNil(t, handler)
}

func TestHandler_GetTxnOperations(t *testing.T) {
	const createOpsNum = 2
	const updateOpsNum = 3
	const deactivateOpsNum = 2
	const recoverOpsNum = 2

	t.Run("success", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		handler := NewOperationHandler(cas)

		ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

		anchorString, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)

		provider := NewOperationProvider(cas, mocks.NewMockProtocolClientProvider())

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
		handler := NewOperationProvider(mocks.NewMockCasClient(errors.New("CAS error")), mocks.NewMockProtocolClientProvider())

		txnOps, err := handler.GetTxnOperations(&txn.SidetreeTxn{
			AnchorString:      "1" + delimiter + "anchor",
			TransactionNumber: 1,
			TransactionTime:   1,
		})

		require.Error(t, err)
		require.Nil(t, txnOps)
		require.Contains(t, err.Error(), "failed to retrieve content for anchor file[anchor]")
	})

	t.Run("error - parse anchor operations error", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		handler := NewOperationHandler(cas)

		ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

		anchorString, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)

		pc := mocks.NewMockProtocolClient()
		pc.Protocol = protocol.Protocol{
			HashAlgorithmInMultiHashCode: 55,
		}

		pcp := mocks.NewMockProtocolClientProvider()
		pcp.ProtocolClients[mocks.DefaultNS] = pc
		provider := NewOperationProvider(cas, pcp)

		txnOps, err := provider.GetTxnOperations(&txn.SidetreeTxn{
			Namespace:         defaultNS,
			AnchorString:      anchorString,
			TransactionNumber: 1,
			TransactionTime:   1,
		})

		require.Error(t, err)
		require.Nil(t, txnOps)
		require.Contains(t, err.Error(), "parse anchor operations: algorithm not supported")
	})

	t.Run("error - parse anchor data error", func(t *testing.T) {
		provider := NewOperationProvider(mocks.NewMockCasClient(nil), mocks.NewMockProtocolClientProvider())

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
		handler := NewOperationHandler(cas)

		anchorString, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)

		provider := NewOperationProvider(cas, mocks.NewMockProtocolClientProvider())

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

		provider := NewOperationProvider(cas, pcp)

		txnOps, err := provider.GetTxnOperations(&txn.SidetreeTxn{
			AnchorString:      "1" + delimiter + anchor,
			TransactionNumber: 1,
			TransactionTime:   1,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse anchor operations: protocol client not found for namespace")
		require.Nil(t, txnOps)
	})
}

func TestHandler_GetAnchorFile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		address, err := cas.Write([]byte("{}"))
		require.NoError(t, err)

		provider := NewOperationProvider(cas, mocks.NewMockProtocolClientProvider())
		file, err := provider.getAnchorFile(address)
		require.NoError(t, err)
		require.NotNil(t, file)
	})

	t.Run("error - read from CAS error", func(t *testing.T) {
		provider := NewOperationProvider(mocks.NewMockCasClient(errors.New("CAS error")), mocks.NewMockProtocolClientProvider())
		file, err := provider.getAnchorFile("address")
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to retrieve content for anchor file[address]: CAS error")
	})

	t.Run("error - parse anchor file error (invalid JSON)", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		address, err := cas.Write([]byte("invalid"))
		require.NoError(t, err)

		provider := NewOperationProvider(cas, mocks.NewMockProtocolClientProvider())
		file, err := provider.getAnchorFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to parse content for anchor file")
	})
}

func TestHandler_GetMapFile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		address, err := cas.Write([]byte("{}"))
		require.NoError(t, err)

		provider := NewOperationProvider(cas, mocks.NewMockProtocolClientProvider())
		file, err := provider.getMapFile(address)
		require.NoError(t, err)
		require.NotNil(t, file)
	})

	t.Run("error - read from CAS error", func(t *testing.T) {
		provider := NewOperationProvider(mocks.NewMockCasClient(errors.New("CAS error")), mocks.NewMockProtocolClientProvider())
		file, err := provider.getMapFile("address")
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to retrieve content for map file[address]: CAS error")
	})

	t.Run("error - parse anchor file error (invalid JSON)", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		address, err := cas.Write([]byte("invalid"))
		require.NoError(t, err)

		provider := NewOperationProvider(cas, mocks.NewMockProtocolClientProvider())
		file, err := provider.getMapFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to parse content for map file")
	})
}

func TestHandler_GetChunkFile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		address, err := cas.Write([]byte("{}"))
		require.NoError(t, err)

		provider := NewOperationProvider(cas, mocks.NewMockProtocolClientProvider())
		file, err := provider.getChunkFile(address)
		require.NoError(t, err)
		require.NotNil(t, file)
	})

	t.Run("error - read from CAS error", func(t *testing.T) {
		provider := NewOperationProvider(mocks.NewMockCasClient(errors.New("CAS error")), mocks.NewMockProtocolClientProvider())
		file, err := provider.getChunkFile("address")
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to retrieve content for chunk file[address]: CAS error")
	})

	t.Run("error - parse chunk file error (invalid JSON)", func(t *testing.T) {
		cas := mocks.NewMockCasClient(nil)
		address, err := cas.Write([]byte("invalid"))
		require.NoError(t, err)

		provider := NewOperationProvider(cas, mocks.NewMockProtocolClientProvider())
		file, err := provider.getChunkFile(address)
		require.Error(t, err)
		require.Nil(t, file)
		require.Contains(t, err.Error(), "failed to parse content for chunk file")
	})
}
