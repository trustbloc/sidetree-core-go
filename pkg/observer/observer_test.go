/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/txnhandler"
)

const anchorString = "1.anchorAddress"

func TestStartObserver(t *testing.T) {
	t.Run("test error from ProcessSidetreeTxn", func(t *testing.T) {
		sidetreeTxnCh := make(chan []txn.SidetreeTxn, 100)
		isCalled := false
		var rw sync.RWMutex
		readFunc := func(key string) ([]byte, error) {
			rw.Lock()
			isCalled = true
			rw.Unlock()
			return nil, fmt.Errorf("read error")
		}

		providers := &Providers{
			Ledger:           mockLedger{registerForSidetreeTxnValue: sidetreeTxnCh},
			TxnOpsProvider:   txnhandler.NewOperationProvider(&mockDCAS{readFunc: readFunc}, mocks.NewMockProtocolClientProvider()),
			OpFilterProvider: &NoopOperationFilterProvider{},
		}

		o := New(providers)
		require.NotNil(t, o)

		o.Start()
		defer o.Stop()

		sidetreeTxnCh <- []txn.SidetreeTxn{{TransactionTime: 20, TransactionNumber: 2, AnchorString: "1.address"}}
		time.Sleep(200 * time.Millisecond)
		rw.RLock()
		require.True(t, isCalled)
		rw.RUnlock()
	})

	t.Run("test channel close", func(t *testing.T) {
		sidetreeTxnCh := make(chan []txn.SidetreeTxn, 100)

		providers := &Providers{
			Ledger:           mockLedger{registerForSidetreeTxnValue: sidetreeTxnCh},
			OpFilterProvider: &NoopOperationFilterProvider{},
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
		isCalled := false

		var rw sync.RWMutex
		opStore := &mockOperationStore{putFunc: func(ops []*batch.Operation) error {
			rw.Lock()
			isCalled = true
			rw.Unlock()
			return nil
		}}

		providers := &Providers{
			Ledger:           mockLedger{registerForSidetreeTxnValue: sidetreeTxnCh},
			TxnOpsProvider:   &mockTxnOpsProvider{},
			OpStoreProvider:  &mockOperationStoreProvider{opStore: opStore},
			OpFilterProvider: &NoopOperationFilterProvider{},
		}

		o := New(providers)
		require.NotNil(t, o)

		o.Start()
		defer o.Stop()

		sidetreeTxnCh <- []txn.SidetreeTxn{{TransactionTime: 20, TransactionNumber: 2, AnchorString: "1.address"}}
		time.Sleep(200 * time.Millisecond)
		rw.RLock()
		require.True(t, isCalled)
		rw.RUnlock()
	})
}

func TestTxnProcessor_Process(t *testing.T) {
	t.Run("test error from txn operations provider", func(t *testing.T) {
		providers := &Providers{
			TxnOpsProvider:   &mockTxnOpsProvider{err: errors.New("txn operations provider error")},
			OpFilterProvider: &NoopOperationFilterProvider{},
		}

		p := NewTxnProcessor(providers)
		err := p.Process(txn.SidetreeTxn{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to retrieve operations for anchor string")
	})
}

func TestProcessTxnOperations(t *testing.T) {
	t.Run("test error from operationStoreProvider ForNamespace", func(t *testing.T) {
		errExpected := errors.New("injected store provider error")

		providers := &Providers{
			OpStoreProvider:  &mockOperationStoreProvider{err: errExpected},
			OpFilterProvider: &NoopOperationFilterProvider{},
		}

		p := NewTxnProcessor(providers)
		err := p.processTxnOperations([]*batch.Operation{{ID: "doc:method:abc"}}, txn.SidetreeTxn{AnchorString: anchorString})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("test error from operationStore Put", func(t *testing.T) {
		opStore := &mockOperationStore{putFunc: func(ops []*batch.Operation) error {
			return fmt.Errorf("put error")
		}}

		providers := &Providers{
			OpStoreProvider:  &mockOperationStoreProvider{opStore: opStore},
			OpFilterProvider: &NoopOperationFilterProvider{},
		}

		p := NewTxnProcessor(providers)
		err := p.processTxnOperations([]*batch.Operation{{ID: "doc:method:abc"}}, txn.SidetreeTxn{AnchorString: anchorString})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to store operation from anchor string")
	})

	t.Run("test success", func(t *testing.T) {
		providers := &Providers{
			TxnOpsProvider:   &mockTxnOpsProvider{},
			OpStoreProvider:  &mockOperationStoreProvider{opStore: &mockOperationStore{}},
			OpFilterProvider: &NoopOperationFilterProvider{},
		}

		p := NewTxnProcessor(providers)
		batchOps, err := p.TxnOpsProvider.GetTxnOperations(&txn.SidetreeTxn{AnchorString: anchorString})
		require.NoError(t, err)

		err = p.processTxnOperations(batchOps, txn.SidetreeTxn{AnchorString: anchorString})
		require.NoError(t, err)
	})
}

func TestUpdateOperation(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		updatedOps := updateOperation(&batch.Operation{ID: "did:sidetree:abc"},
			1, txn.SidetreeTxn{TransactionTime: 20, TransactionNumber: 2})
		require.Equal(t, uint64(20), updatedOps.TransactionTime)
		require.Equal(t, uint64(2), updatedOps.TransactionNumber)
		require.Equal(t, uint(1), updatedOps.OperationIndex)
	})
}

type mockLedger struct {
	registerForSidetreeTxnValue chan []txn.SidetreeTxn
}

func (m mockLedger) RegisterForSidetreeTxn() <-chan []txn.SidetreeTxn {
	return m.registerForSidetreeTxnValue
}

type mockDCAS struct {
	readFunc func(key string) ([]byte, error)
}

func (m mockDCAS) Read(key string) ([]byte, error) {
	if m.readFunc != nil {
		return m.readFunc(key)
	}
	return nil, nil
}

func (m mockDCAS) Write(content []byte) (string, error) {
	return "", errors.New("not implemented")
}

type mockOperationStore struct {
	putFunc func(ops []*batch.Operation) error
	getFunc func(suffix string) ([]*batch.Operation, error)
}

func (m *mockOperationStore) Put(ops []*batch.Operation) error {
	if m.putFunc != nil {
		return m.putFunc(ops)
	}
	return nil
}

func (m *mockOperationStore) Get(suffix string) ([]*batch.Operation, error) {
	if m.getFunc != nil {
		return m.getFunc(suffix)
	}
	return nil, nil
}

type mockOperationStoreProvider struct {
	opStore OperationStore
	err     error
}

func (m *mockOperationStoreProvider) ForNamespace(string) (OperationStore, error) {
	if m.err != nil {
		return nil, m.err
	}

	return m.opStore, nil
}

type mockTxnOpsProvider struct {
	err error
}

func (m *mockTxnOpsProvider) GetTxnOperations(txn *txn.SidetreeTxn) ([]*batch.Operation, error) {
	if m.err != nil {
		return nil, m.err
	}

	op := &batch.Operation{
		ID: "did:sidetree:abc",
	}

	return []*batch.Operation{op}, nil
}
