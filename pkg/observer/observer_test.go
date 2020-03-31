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
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

const anchorAddressKey = "anchorAddress"

func TestStartObserver(t *testing.T) {
	t.Run("test error from ProcessSidetreeTxn", func(t *testing.T) {
		sidetreeTxnCh := make(chan []SidetreeTxn, 100)
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
			DCASClient:       mockDCAS{readFunc: readFunc},
			OpFilterProvider: &NoopOperationFilterProvider{},
		}

		o := New(providers)
		require.NotNil(t, o)

		o.Start()
		defer o.Stop()

		sidetreeTxnCh <- []SidetreeTxn{{TransactionTime: 20, TransactionNumber: 2, AnchorAddress: "address"}}
		time.Sleep(200 * time.Millisecond)
		rw.RLock()
		require.True(t, isCalled)
		rw.RUnlock()
	})

	t.Run("test channel close", func(t *testing.T) {
		sidetreeTxnCh := make(chan []SidetreeTxn, 100)

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
		sidetreeTxnCh := make(chan []SidetreeTxn, 100)
		isCalled := false

		var rw sync.RWMutex
		opStore := &mockOperationStore{putFunc: func(ops []*batch.Operation) error {
			rw.Lock()
			isCalled = true
			rw.Unlock()
			return nil
		}}

		providers := &Providers{
			Ledger: mockLedger{registerForSidetreeTxnValue: sidetreeTxnCh},
			DCASClient: mockDCAS{readFunc: func(key string) ([]byte, error) {
				if key == anchorAddressKey {
					return docutil.MarshalCanonical(&AnchorFile{})
				}
				b, err := docutil.MarshalCanonical(batch.Operation{ID: "did:sideteree:123456"})
				require.NoError(t, err)
				return docutil.MarshalCanonical(&BatchFile{Operations: []string{docutil.EncodeToString(b)}})
			}},
			OpStoreProvider:  &mockOperationStoreProvider{opStore: opStore},
			OpFilterProvider: &NoopOperationFilterProvider{},
		}

		o := New(providers)
		require.NotNil(t, o)

		o.Start()
		defer o.Stop()

		sidetreeTxnCh <- []SidetreeTxn{{TransactionTime: 20, TransactionNumber: 2, AnchorAddress: "address"}}
		time.Sleep(200 * time.Millisecond)
		rw.RLock()
		require.True(t, isCalled)
		rw.RUnlock()
	})
}

func TestTxnProcessor_Process(t *testing.T) {
	t.Run("test error from dacs read", func(t *testing.T) {
		providers := &Providers{
			DCASClient:       mockDCAS{readFunc: func(key string) ([]byte, error) { return nil, fmt.Errorf("read error") }},
			OpFilterProvider: &NoopOperationFilterProvider{},
		}

		p := NewTxnProcessor(providers)
		err := p.Process(SidetreeTxn{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to retrieve content for anchor")
	})

	t.Run("test error from getAnchorFile", func(t *testing.T) {
		providers := &Providers{
			DCASClient:       mockDCAS{readFunc: func(key string) ([]byte, error) { return []byte("1"), nil }},
			OpFilterProvider: &NoopOperationFilterProvider{},
		}

		p := NewTxnProcessor(providers)
		err := p.Process(SidetreeTxn{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal anchor")
	})

	t.Run("test error from processBatchFile", func(t *testing.T) {
		providers := &Providers{
			DCASClient: mockDCAS{readFunc: func(key string) ([]byte, error) {
				if key == anchorAddressKey {
					return docutil.MarshalCanonical(&AnchorFile{})
				}
				return nil, fmt.Errorf("read error")
			}},
			OpFilterProvider: &NoopOperationFilterProvider{},
		}

		p := NewTxnProcessor(providers)
		err := p.Process(SidetreeTxn{AnchorAddress: anchorAddressKey})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to retrieve content for batch")
	})
}

func TestProcessBatchFile(t *testing.T) {
	t.Run("test error from getBatchFile", func(t *testing.T) {
		providers := &Providers{
			DCASClient: mockDCAS{readFunc: func(key string) ([]byte, error) {
				if key == anchorAddressKey {
					return docutil.MarshalCanonical(&AnchorFile{})
				}
				return []byte("1"), nil
			}},
			OpFilterProvider: &NoopOperationFilterProvider{},
		}

		p := NewTxnProcessor(providers)
		err := p.processBatchFile("", SidetreeTxn{AnchorAddress: anchorAddressKey})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal batch")
	})

	t.Run("test error from updateOperation", func(t *testing.T) {
		providers := &Providers{
			DCASClient: mockDCAS{readFunc: func(key string) ([]byte, error) {
				if key == anchorAddressKey {
					return docutil.MarshalCanonical(&AnchorFile{})
				}

				return docutil.MarshalCanonical(&BatchFile{Operations: []string{"1"}})
			}},
			OpFilterProvider: &NoopOperationFilterProvider{},
		}

		p := NewTxnProcessor(providers)
		err := p.processBatchFile("", SidetreeTxn{AnchorAddress: anchorAddressKey})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to update operation with blockchain metadata")
	})

	t.Run("test error from operationStoreProvider ForNamespace", func(t *testing.T) {
		errExpected := errors.New("injected store provider error")

		providers := &Providers{
			DCASClient: mockDCAS{readFunc: func(key string) ([]byte, error) {
				if key == anchorAddressKey {
					return docutil.MarshalCanonical(&AnchorFile{})
				}
				b, err := docutil.MarshalCanonical(batch.Operation{ID: "did:sideteree:123456"})
				require.NoError(t, err)
				return docutil.MarshalCanonical(&BatchFile{Operations: []string{docutil.EncodeToString(b)}})
			}},
			OpStoreProvider:  &mockOperationStoreProvider{err: errExpected},
			OpFilterProvider: &NoopOperationFilterProvider{},
		}

		p := NewTxnProcessor(providers)
		err := p.processBatchFile("", SidetreeTxn{AnchorAddress: anchorAddressKey})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("test error from operationStore Put", func(t *testing.T) {
		opStore := &mockOperationStore{putFunc: func(ops []*batch.Operation) error {
			return fmt.Errorf("put error")
		}}

		providers := &Providers{
			DCASClient: mockDCAS{readFunc: func(key string) ([]byte, error) {
				if key == anchorAddressKey {
					return docutil.MarshalCanonical(&AnchorFile{})
				}
				b, err := docutil.MarshalCanonical(batch.Operation{ID: "did:sideteree:123456"})
				require.NoError(t, err)
				return docutil.MarshalCanonical(&BatchFile{Operations: []string{docutil.EncodeToString(b)}})
			}},
			OpStoreProvider:  &mockOperationStoreProvider{opStore: opStore},
			OpFilterProvider: &NoopOperationFilterProvider{},
		}

		p := NewTxnProcessor(providers)
		err := p.processBatchFile("", SidetreeTxn{AnchorAddress: anchorAddressKey})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to store operation from batch")
	})

	t.Run("test success", func(t *testing.T) {
		providers := &Providers{
			DCASClient: mockDCAS{readFunc: func(key string) ([]byte, error) {
				if key == anchorAddressKey {
					return docutil.MarshalCanonical(&AnchorFile{})
				}
				b, err := docutil.MarshalCanonical(batch.Operation{ID: "did:sideteree:123456"})
				require.NoError(t, err)
				return docutil.MarshalCanonical(&BatchFile{Operations: []string{docutil.EncodeToString(b)}})
			}},
			OpStoreProvider:  &mockOperationStoreProvider{opStore: &mockOperationStore{}},
			OpFilterProvider: &NoopOperationFilterProvider{},
		}

		p := NewTxnProcessor(providers)
		err := p.processBatchFile("", SidetreeTxn{AnchorAddress: anchorAddressKey})
		require.NoError(t, err)
	})
}

func TestUpdateOperation(t *testing.T) {
	t.Run("test error from unmarshal decoded ops", func(t *testing.T) {
		_, err := updateOperation(docutil.EncodeToString([]byte("ops")), 1, SidetreeTxn{AnchorAddress: anchorAddressKey})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal decoded ops")
	})

	t.Run("test success", func(t *testing.T) {
		b, err := docutil.MarshalCanonical(batch.Operation{ID: "did:sideteree:123456"})
		require.NoError(t, err)
		updatedOps, err := updateOperation(docutil.EncodeToString(b), 1, SidetreeTxn{TransactionTime: 20, TransactionNumber: 2})
		require.NoError(t, err)
		require.Equal(t, uint64(20), updatedOps.TransactionTime)
		require.Equal(t, uint64(2), updatedOps.TransactionNumber)
		require.Equal(t, uint(1), updatedOps.OperationIndex)
	})
}

func TestGetNamespace(t *testing.T) {
	const namespace = "did:sidetree"
	const suffix = "123456"

	t.Run("Valid ID", func(t *testing.T) {
		ns, err := namespaceFromDocID(namespace + docutil.NamespaceDelimiter + suffix)
		require.NoError(t, err)
		require.Equal(t, namespace, ns)
	})

	t.Run("Invalid ID", func(t *testing.T) {
		ns, err := namespaceFromDocID(suffix)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid ID")
		require.Empty(t, ns)
	})
}

type mockLedger struct {
	registerForSidetreeTxnValue chan []SidetreeTxn
}

func (m mockLedger) RegisterForSidetreeTxn() <-chan []SidetreeTxn {
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
