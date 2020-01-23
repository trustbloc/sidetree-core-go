/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package batch

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/trustbloc/sidetree-core-go/pkg/batch/filehandler"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"

	"github.com/stretchr/testify/require"
)

var testOp = []byte("Test Operation")

func TestNew(t *testing.T) {
	ctx := newMockContext()
	writer, err := New(ctx)
	require.Nil(t, err)
	require.NotNil(t, writer)

	writer, err = New(ctx, WithBatchTimeout(10*time.Second))
	require.Nil(t, err)
	require.NotNil(t, writer)
	require.EqualValues(t, writer.batchTimeout, 10*time.Second)

	writer, err = New(ctx, withError())
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "failed to read opts: test error")
	require.Nil(t, writer)

	opsHandler := &mockOpsHandler{}
	writer, err = New(ctx, WithOperationHandler(opsHandler))
	require.Nil(t, err)
	require.NotNil(t, writer)
	require.EqualValues(t, writer.opsHandler, opsHandler)
}

func TestStart(t *testing.T) {
	ctx := newMockContext()
	writer, err := New(ctx)
	require.Nil(t, err)

	writer.Start()
	defer writer.Stop()

	operations := generateOperations(8)

	for _, op := range operations {
		err = writer.Add(op)
		require.Nil(t, err)
	}

	time.Sleep(time.Second)

	// we should have 4 anchors: 8 operations % max 2 operations per batch
	require.Equal(t, 4, len(ctx.BlockchainClient.GetAnchors()))

	// Check that first anchor has two operations per batch
	bytes, err := ctx.CasClient.Read(ctx.BlockchainClient.GetAnchors()[0])
	require.Nil(t, err)
	require.NotNil(t, bytes)

	var af filehandler.AnchorFile
	err = json.Unmarshal(bytes, &af)
	require.Nil(t, err)
	require.NotNil(t, af)

	bytes, err = ctx.CasClient.Read(af.BatchFileHash)
	require.Nil(t, err)
	require.NotNil(t, bytes)

	var bf filehandler.BatchFile
	err = json.Unmarshal(bytes, &bf)
	require.Nil(t, err)
	require.NotNil(t, bf)
	require.Equal(t, 2, len(bf.Operations))
}

func TestBatchTimer(t *testing.T) {
	ctx := newMockContext()
	writer, err := New(ctx, WithBatchTimeout(2*time.Second))
	require.Nil(t, err)

	writer.Start()
	defer writer.Stop()

	err = writer.Add(testOp)
	require.Nil(t, err)

	// Batch will be cut after 2 seconds even though
	// maximum operations(=2) have not been reached
	time.Sleep(3 * time.Second)

	require.Equal(t, 1, len(ctx.BlockchainClient.GetAnchors()))

	bytes, err := ctx.CasClient.Read(ctx.BlockchainClient.GetAnchors()[0])
	require.Nil(t, err)
	require.NotNil(t, bytes)

	var af filehandler.AnchorFile
	err = json.Unmarshal(bytes, &af)
	require.Nil(t, err)
	require.NotNil(t, af)

	bytes, err = ctx.CasClient.Read(af.BatchFileHash)
	require.Nil(t, err)
	require.NotNil(t, bytes)

	var bf filehandler.BatchFile
	err = json.Unmarshal(bytes, &bf)
	require.Nil(t, err)
	require.NotNil(t, bf)
	require.Equal(t, 1, len(bf.Operations))
}

func TestCasError(t *testing.T) {
	ctx := newMockContext()
	writer, err := New(ctx, WithBatchTimeout(2*time.Second))
	require.Nil(t, err)

	ctx.CasClient = mocks.NewMockCasClient(fmt.Errorf("CAS Error"))

	writer.Start()
	defer writer.Stop()

	operations := generateOperations(3)
	for _, op := range operations {
		err = writer.Add(op)
		require.Nil(t, err)
	}

	time.Sleep(3 * time.Second)

	require.Equal(t, 0, len(ctx.BlockchainClient.GetAnchors()))
}

func TestBlockchainError(t *testing.T) {
	ctx := newMockContext()
	writer, err := New(ctx, WithBatchTimeout(2*time.Second))
	require.Nil(t, err)

	ctx.BlockchainClient = mocks.NewMockBlockchainClient(fmt.Errorf("blockchain error"))
	writer.Start()
	defer writer.Stop()

	operations := generateOperations(3)
	for _, op := range operations {
		err = writer.Add(op)
		require.Nil(t, err)
	}

	time.Sleep(3 * time.Second)

	require.Equal(t, 0, len(ctx.BlockchainClient.GetAnchors()))
}

func TestProcessBatchError(t *testing.T) {
	ctx := newMockContext()
	ctx.ProtocolClient.Protocol = protocol.Protocol{
		HashAlgorithmInMultiHashCode: 101, // non-existent hash code
		MaxOperationsPerBatch:        2,
	}

	// Error will be generated in the context
	writer, err := New(ctx, WithBatchTimeout(2*time.Second))
	require.Nil(t, err)

	writer.Start()
	defer writer.Stop()

	operations := generateOperations(3)
	for _, op := range operations {
		err = writer.Add(op)
		require.Nil(t, err)
	}

	time.Sleep(3 * time.Second)

	require.Equal(t, 0, len(ctx.BlockchainClient.GetAnchors()))
}

func TestAddAfterStop(t *testing.T) {
	writer, err := New(newMockContext())
	require.Nil(t, err)

	writer.Stop()

	err = writer.Add(testOp)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "message from exit channel")
}

func TestProcessBatchErrorRecovery(t *testing.T) {
	ctx := newMockContext()
	ctx.ProtocolClient.Protocol.MaxOperationsPerBatch = 2
	ctx.CasClient = mocks.NewMockCasClient(fmt.Errorf("CAS Error"))

	writer, err := New(ctx, WithBatchTimeout(500*time.Millisecond))
	require.Nil(t, err)

	writer.Start()
	defer writer.Stop()

	const n = 12
	const numBatchesExpected = 7

	require.NoError(t, writer.Add([]byte("first-op")))
	time.Sleep(1 * time.Second)

	for _, op := range generateOperations(n) {
		require.NoError(t, writer.Add(op))
	}

	// Clear the error. The batch writer should recover by processing all of the pending batches
	ctx.CasClient.SetError(nil)
	time.Sleep(1 * time.Second)

	require.Equal(t, numBatchesExpected, len(ctx.BlockchainClient.GetAnchors()))
}

//withError allows for testing an error in options
func withError() Option {
	return func(o *Options) error {
		return fmt.Errorf("test error")
	}
}

func generateOperations(numOfOperations int) (ops [][]byte) {
	for j := 1; j <= numOfOperations; j++ {
		ops = append(ops, []byte(fmt.Sprintf("op%d", j)))
	}
	return
}

// mockContext implements mock batch writer context
type mockContext struct {
	ProtocolClient   *mocks.MockProtocolClient
	CasClient        *mocks.MockCasClient
	BlockchainClient *mocks.MockBlockchainClient
}

// newMockContext returns a new mockContext object
func newMockContext() *mockContext {
	ctx := &mockContext{
		ProtocolClient:   mocks.NewMockProtocolClient(),
		CasClient:        mocks.NewMockCasClient(nil),
		BlockchainClient: mocks.NewMockBlockchainClient(nil),
	}

	return ctx
}

// Protocol returns the Client
func (m *mockContext) Protocol() protocol.Client {
	return m.ProtocolClient
}

// Blockchain returns the block chain client
func (m *mockContext) Blockchain() BlockchainClient {
	return m.BlockchainClient
}

// CAS returns the CAS client
func (m *mockContext) CAS() CASClient {
	return m.CasClient
}

// mockOpsHandler mocks creates batch/anchor files from operations
type mockOpsHandler struct{}

// CreateBatchFile mocks creating batch file bytes
func (h *mockOpsHandler) CreateBatchFile(operations [][]byte) ([]byte, error) {
	return nil, nil
}

// CreateAnchorFile mocks creating anchor file bytes
func (h *mockOpsHandler) CreateAnchorFile(operations [][]byte, batchAddress string, multihashCode uint) ([]byte, error) {
	return nil, nil
}
