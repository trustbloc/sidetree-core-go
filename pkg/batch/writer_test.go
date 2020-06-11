/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package batch

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/cutter"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/opqueue"
	"github.com/trustbloc/sidetree-core-go/pkg/compression"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/helper"
	"github.com/trustbloc/sidetree-core-go/pkg/txnhandler"
	"github.com/trustbloc/sidetree-core-go/pkg/txnhandler/models"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
)

//go:generate counterfeiter -o ../mocks/operationqueue.gen.go --fake-name OperationQueue ./cutter OperationQueue

const sha2_256 = 18
const namespace = "did:sidetree"
const compressionAlgorithm = "GZIP"

func TestNew(t *testing.T) {
	ctx := newMockContext()
	writer, err := New(namespace, ctx)
	require.Nil(t, err)
	require.NotNil(t, writer)

	writer, err = New(namespace, ctx, WithBatchTimeout(10*time.Second))
	require.Nil(t, err)
	require.NotNil(t, writer)
	require.EqualValues(t, writer.batchTimeout, 10*time.Second)

	writer, err = New(namespace, ctx, withError())
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "failed to read opts: test error")
	require.Nil(t, writer)

	opsHandler := &mockOpsHandler{}
	writer, err = New(namespace, ctx, WithOperationHandler(opsHandler))
	require.Nil(t, err)
	require.NotNil(t, writer)
	require.EqualValues(t, writer.opsHandler, opsHandler)

	writer, err = New(namespace, ctx, WithCompressionProvider(compression.New(compression.WithDefaultAlgorithms())))
	require.Nil(t, err)
	require.NotNil(t, writer)
}

func TestStart(t *testing.T) {
	ctx := newMockContext()
	writer, err := New(namespace, ctx)
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

	ad, err := txnhandler.ParseAnchorData(ctx.BlockchainClient.GetAnchors()[0])
	require.NoError(t, err)

	// Check that first anchor has two operations per batch
	af, mf, cf, err := getBatchFiles(ctx.CasClient, ad.AnchorAddress)
	require.Nil(t, err)

	require.Equal(t, 2, len(af.Operations.Create))
	require.Equal(t, 0, len(mf.Operations.Update))
	require.Equal(t, 2, len(cf.Deltas))
}

func getBatchFiles(cc cas.Client, anchor string) (*models.AnchorFile, *models.MapFile, *models.ChunkFile, error) { //nolint: interfacer
	bytes, err := cc.Read(anchor)
	if err != nil {
		return nil, nil, nil, err
	}

	compression := compression.New(compression.WithDefaultAlgorithms())

	content, err := compression.Decompress(compressionAlgorithm, bytes)
	if err != nil {
		return nil, nil, nil, err
	}

	var af models.AnchorFile
	err = json.Unmarshal(content, &af)
	if err != nil {
		return nil, nil, nil, err
	}

	bytes, err = cc.Read(af.MapFileHash)
	if err != nil {
		return nil, nil, nil, err
	}

	content, err = compression.Decompress(compressionAlgorithm, bytes)
	if err != nil {
		return nil, nil, nil, err
	}

	var mf models.MapFile
	err = json.Unmarshal(content, &mf)
	if err != nil {
		return nil, nil, nil, err
	}

	bytes, err = cc.Read(mf.Chunks[0].ChunkFileURI)
	if err != nil {
		return nil, nil, nil, err
	}

	content, err = compression.Decompress(compressionAlgorithm, bytes)
	if err != nil {
		return nil, nil, nil, err
	}

	var cf models.ChunkFile
	err = json.Unmarshal(content, &cf)
	if err != nil {
		return nil, nil, nil, err
	}

	return &af, &mf, &cf, nil
}

func TestBatchTimer(t *testing.T) {
	ctx := newMockContext()
	writer, err := New(namespace, ctx, WithBatchTimeout(2*time.Second))
	require.Nil(t, err)

	writer.Start()
	defer writer.Stop()

	testOp, err := generateOperation(0)
	require.NoError(t, err)

	err = writer.Add(testOp)
	require.Nil(t, err)

	// Batch will be cut after 2 seconds even though
	// maximum operations(=2) have not been reached
	time.Sleep(3 * time.Second)

	require.Equal(t, 1, len(ctx.BlockchainClient.GetAnchors()))

	ad, err := txnhandler.ParseAnchorData(ctx.BlockchainClient.GetAnchors()[0])
	require.NoError(t, err)

	af, mf, cf, err := getBatchFiles(ctx.CasClient, ad.AnchorAddress)
	require.Nil(t, err)

	require.Equal(t, 1, len(af.Operations.Create))
	require.Equal(t, 0, len(af.Operations.Recover))
	require.Equal(t, 0, len(af.Operations.Deactivate))

	require.Equal(t, 0, len(mf.Operations.Update))

	require.Equal(t, 1, len(cf.Deltas))
}

func TestDiscardDuplicateSuffixInBatchFile(t *testing.T) {
	ctx := newMockContext()
	writer, err := New(namespace, ctx)
	require.Nil(t, err)

	writer.Start()
	defer writer.Stop()

	operation, err := generateOperation(1)
	require.NoError(t, err)

	err = writer.Add(operation)
	require.Nil(t, err)

	// add same operation again
	err = writer.Add(operation)
	require.Nil(t, err)

	time.Sleep(time.Second)

	// we should have 1 anchors: 2 operations % max 2 operations per batch
	require.Equal(t, 1, len(ctx.BlockchainClient.GetAnchors()))

	ad, err := txnhandler.ParseAnchorData(ctx.BlockchainClient.GetAnchors()[0])
	require.NoError(t, err)

	// Check that first anchor has one operation per batch; second one has been discarded
	af, mf, cf, err := getBatchFiles(ctx.CasClient, ad.AnchorAddress)
	require.Nil(t, err)

	require.Equal(t, 1, len(af.Operations.Create))
	require.Equal(t, 0, len(af.Operations.Recover))
	require.Equal(t, 0, len(af.Operations.Deactivate))

	require.Equal(t, 0, len(mf.Operations.Update))

	require.Equal(t, 1, len(cf.Deltas))
}

func TestProcessOperationsError(t *testing.T) {
	ctx := newMockContext()
	ctx.CasClient = mocks.NewMockCasClient(fmt.Errorf("CAS Error"))

	writer, err := New(namespace, ctx, WithBatchTimeout(2*time.Second))
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
	writer, err := New(namespace, ctx, WithBatchTimeout(2*time.Second))
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

func TestAddAfterStop(t *testing.T) {
	writer, err := New(namespace, newMockContext())
	require.Nil(t, err)
	require.False(t, writer.Stopped())

	writer.Stop()
	// Should be able to call stop multiple times
	writer.Stop()

	require.True(t, writer.Stopped())

	testOp, err := generateOperation(100)
	require.NoError(t, err)

	err = writer.Add(testOp)
	require.EqualError(t, err, "writer is stopped")
}

func TestProcessBatchErrorRecovery(t *testing.T) {
	ctx := newMockContext()
	ctx.ProtocolClient.Protocol.MaxOperationsPerBatch = 2
	ctx.CasClient = mocks.NewMockCasClient(fmt.Errorf("CAS Error"))

	writer, err := New(namespace, ctx, WithBatchTimeout(500*time.Millisecond))
	require.Nil(t, err)

	writer.Start()
	defer writer.Stop()

	const n = 12
	const numBatchesExpected = 7

	firstOp, err := generateOperation(0)
	require.NoError(t, err)

	require.NoError(t, writer.Add(firstOp))
	time.Sleep(1 * time.Second)

	for _, op := range generateOperations(n) {
		require.NoError(t, writer.Add(op))
	}

	// Clear the error. The batch writer should recover by processing all of the pending batches
	ctx.CasClient.SetError(nil)
	time.Sleep(1 * time.Second)

	require.Equal(t, numBatchesExpected, len(ctx.BlockchainClient.GetAnchors()))
}

func TestAddError(t *testing.T) {
	errExpected := errors.New("injected operation queue error")
	q := &mocks.OperationQueue{}
	q.AddReturns(0, errExpected)

	ctx := newMockContext()
	ctx.OpQueue = q

	writer, err := New(namespace, ctx)
	require.NoError(t, err)
	require.EqualError(t, writer.Add(&batch.OperationInfo{}), errExpected.Error())
}

func TestStartWithExistingItems(t *testing.T) {
	const numOperations = 23
	const maxOperationsPerBatch = 4
	const numBatchesExpected = 6

	opQueue := &opqueue.MemQueue{}

	ctx := newMockContext()
	ctx.ProtocolClient.Protocol.MaxOperationsPerBatch = maxOperationsPerBatch
	ctx.OpQueue = opQueue

	writer, err := New(namespace, ctx)
	require.Nil(t, err)

	// Add operations to the queue directly
	for _, op := range generateOperations(numOperations) {
		_, err = opQueue.Add(op)
		require.Nil(t, err)
	}

	writer.Start()
	defer writer.Stop()

	time.Sleep(time.Second)
	require.Equal(t, numBatchesExpected, len(ctx.BlockchainClient.GetAnchors()))
}

func TestProcessError(t *testing.T) {
	t.Run("process operation error", func(t *testing.T) {
		q := &mocks.OperationQueue{}

		invalidQueue := []*batch.OperationInfo{{Data: []byte(""), UniqueSuffix: "unique", Namespace: "ns"}}

		q.LenReturns(1)
		q.PeekReturns(invalidQueue, nil)

		ctx := newMockContext()
		ctx.ProtocolClient.Protocol.MaxOperationsPerBatch = 1
		ctx.OpQueue = q

		writer, err := New("test1", ctx, WithBatchTimeout(10*time.Millisecond))
		require.NoError(t, err)

		writer.Start()
		defer writer.Stop()

		time.Sleep(50 * time.Millisecond)

		require.Zero(t, len(ctx.BlockchainClient.GetAnchors()))
	})

	t.Run("Cut error", func(t *testing.T) {
		errExpected := errors.New("injected operation queue error")
		q := &mocks.OperationQueue{}

		const numOperations = 3
		q.LenReturns(numOperations)
		q.PeekReturns(nil, errExpected)

		ctx := newMockContext()
		ctx.ProtocolClient.Protocol.MaxOperationsPerBatch = 2
		ctx.OpQueue = q

		writer, err := New("test1", ctx, WithBatchTimeout(10*time.Millisecond))
		require.NoError(t, err)

		writer.Start()
		defer writer.Stop()

		time.Sleep(50 * time.Millisecond)

		require.Zero(t, len(ctx.BlockchainClient.GetAnchors()))
	})

	t.Run("Cutter commit error", func(t *testing.T) {
		errExpected := errors.New("injected operation queue error")
		q := &mocks.OperationQueue{}

		const numOperations = 3
		q.LenReturns(numOperations)
		q.PeekReturns(generateOperations(numOperations), nil)
		q.RemoveReturns(0, 1, errExpected)

		ctx := newMockContext()
		ctx.ProtocolClient.Protocol.MaxOperationsPerBatch = 2
		ctx.OpQueue = q

		writer, err := New("test2", ctx, WithBatchTimeout(10*time.Millisecond))
		require.NoError(t, err)

		writer.Start()
		defer writer.Stop()

		time.Sleep(50 * time.Millisecond)

		require.Truef(t, writer.Stopped(), "The batch writer should have been stopped due to a remove error")
	})
}

//withError allows for testing an error in options
func withError() Option {
	return func(o *Options) error {
		return fmt.Errorf("test error")
	}
}

func generateOperations(numOfOperations int) (ops []*batch.OperationInfo) {
	for j := 1; j <= numOfOperations; j++ {
		op, err := generateOperation(j)
		if err != nil {
			panic(err)
		}

		ops = append(ops, op)
	}
	return
}

func generateOperation(num int) (*batch.OperationInfo, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	jwk, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	doc := fmt.Sprintf(`{"test":%d}`, num)
	info := &helper.CreateRequestInfo{OpaqueDocument: doc,
		RecoveryKey:   jwk,
		MultihashCode: sha2_256}

	request, err := helper.NewCreateRequest(info)
	if err != nil {
		return nil, err
	}

	op := &batch.OperationInfo{
		Namespace:    "did:sidetree",
		UniqueSuffix: string(num),
		Data:         request,
	}

	return op, nil
}

// mockContext implements mock batch writer context
type mockContext struct {
	ProtocolClient   *mocks.MockProtocolClient
	CasClient        *mocks.MockCasClient
	BlockchainClient *mocks.MockBlockchainClient
	OpQueue          cutter.OperationQueue
}

// newMockContext returns a new mockContext object
func newMockContext() *mockContext {
	ctx := &mockContext{
		ProtocolClient:   mocks.NewMockProtocolClient(),
		CasClient:        mocks.NewMockCasClient(nil),
		BlockchainClient: mocks.NewMockBlockchainClient(nil),
		OpQueue:          &opqueue.MemQueue{},
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
func (m *mockContext) CAS() cas.Client {
	return m.CasClient
}

// OperationQueue returns the queue containing the pending operations
func (m *mockContext) OperationQueue() cutter.OperationQueue {
	return m.OpQueue
}

// mockOpsHandler mocks creating batch files from operations
type mockOpsHandler struct{}

// PrepareTxnFiles mocks preparing batch files from operations
func (h *mockOpsHandler) PrepareTxnFiles(ops []*batch.Operation) (string, error) {
	return "", nil
}
