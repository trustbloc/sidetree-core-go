/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/txnprocessor"
)

func TestStartObserver(t *testing.T) {
	const (
		namespace1 = "ns1"
		namespace2 = "ns2"
	)

	t.Run("test channel close", func(t *testing.T) {
		sidetreeTxnCh := make(chan []txn.SidetreeTxn, 100)

		providers := &Providers{
			Ledger: mockLedger{registerForSidetreeTxnValue: sidetreeTxnCh},
		}

		o := New(providers)
		require.NotNil(t, o)

		o.Start()
		defer o.Stop()

		close(sidetreeTxnCh)
		time.Sleep(200 * time.Millisecond)
	})

	t.Run("test success", func(t *testing.T) {
		sidetreeTxnCh := make(chan []txn.SidetreeTxn, 100)

		tp := &mocks.TxnProcessor{}

		pc := mocks.NewMockProtocolClient()
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].TransactionProcessorReturns(tp)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		providers := &Providers{
			Ledger:                 mockLedger{registerForSidetreeTxnValue: sidetreeTxnCh},
			ProtocolClientProvider: mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace1, pc),
		}

		o := New(providers)
		require.NotNil(t, o)

		o.Start()
		defer o.Stop()

		sidetreeTxnCh <- []txn.SidetreeTxn{
			{Namespace: namespace1, ProtocolGenesisTime: 0, TransactionTime: 10, TransactionNumber: 0, AnchorString: "1.address"},
			{Namespace: namespace1, ProtocolGenesisTime: 20, TransactionTime: 21, TransactionNumber: 2, AnchorString: "1.address"},
			{Namespace: namespace2, ProtocolGenesisTime: 100, TransactionTime: 200, TransactionNumber: 2, AnchorString: "2.address"},
		}
		time.Sleep(200 * time.Millisecond)

		require.Equal(t, 1, tp.ProcessCallCount())
	})
}

func TestTxnProcessor_Process(t *testing.T) {
	t.Run("test error from txn operations provider", func(t *testing.T) {
		errExpected := fmt.Errorf("txn operations provider error")

		opp := &mockTxnOpsProvider{
			err: errExpected,
		}

		providers := &txnprocessor.Providers{
			OpStore:                   &mockOperationStore{},
			OperationProtocolProvider: opp,
		}

		p := txnprocessor.New(providers)
		err := p.Process(txn.SidetreeTxn{})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

type mockLedger struct {
	registerForSidetreeTxnValue chan []txn.SidetreeTxn
}

func (m mockLedger) RegisterForSidetreeTxn() <-chan []txn.SidetreeTxn {
	return m.registerForSidetreeTxnValue
}

type mockOperationStore struct {
	putFunc func(ops []*operation.AnchoredOperation) error
	getFunc func(suffix string) ([]*operation.AnchoredOperation, error)
}

func (m *mockOperationStore) Put(ops []*operation.AnchoredOperation) error {
	if m.putFunc != nil {
		return m.putFunc(ops)
	}

	return nil
}

func (m *mockOperationStore) Get(suffix string) ([]*operation.AnchoredOperation, error) {
	if m.getFunc != nil {
		return m.getFunc(suffix)
	}

	return nil, nil
}

type mockTxnOpsProvider struct {
	err error
}

func (m *mockTxnOpsProvider) GetTxnOperations(txn *txn.SidetreeTxn) ([]*operation.AnchoredOperation, error) {
	if m.err != nil {
		return nil, m.err
	}

	op := &operation.AnchoredOperation{
		UniqueSuffix: "abc",
	}

	return []*operation.AnchoredOperation{op}, nil
}
