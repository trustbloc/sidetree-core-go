/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package batch

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/cutter"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/opqueue"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/compression"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/client"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/doccomposer"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/operationapplier"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/operationparser"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/txnprovider"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/txnprovider/models"
)

//go:generate counterfeiter -o ../mocks/operationqueue.gen.go --fake-name OperationQueue ./cutter OperationQueue

const (
	sha2_256             = 18
	namespace            = "did:sidetree"
	compressionAlgorithm = "GZIP"
)

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
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read opts: test error")
	require.Nil(t, writer)

	writer, err = New(namespace, ctx)
	require.Nil(t, err)
	require.NotNil(t, writer)

	writer, err = New(namespace, ctx)
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
		err = writer.Add(op, 0)
		require.Nil(t, err)
	}

	time.Sleep(time.Second)

	// we should have 4 anchors: 8 operations % max 2 operations per batch
	require.Equal(t, 4, len(ctx.BlockchainClient.GetAnchors()))

	ad, err := txnprovider.ParseAnchorData(ctx.BlockchainClient.GetAnchors()[0])
	require.NoError(t, err)

	// Check that first anchor has two operations per batch
	cif, pif, cf, err := getBatchFiles(ctx.ProtocolClient.CasClient, ad.CoreIndexFileURI)
	require.Nil(t, err)

	require.Equal(t, 2, len(cif.Operations.Create))
	require.Nil(t, pif.Operations)
	require.Equal(t, 2, len(cf.Deltas))
}

func getBatchFiles(cc cas.Client, anchor string) (*models.CoreIndexFile, *models.ProvisionalIndexFile, *models.ChunkFile, error) { //nolint: interfacer
	bytes, err := cc.Read(anchor)
	if err != nil {
		return nil, nil, nil, err
	}

	compression := compression.New(compression.WithDefaultAlgorithms())

	content, err := compression.Decompress(compressionAlgorithm, bytes)
	if err != nil {
		return nil, nil, nil, err
	}

	var cif models.CoreIndexFile
	err = json.Unmarshal(content, &cif)
	if err != nil {
		return nil, nil, nil, err
	}

	bytes, err = cc.Read(cif.ProvisionalIndexFileURI)
	if err != nil {
		return nil, nil, nil, err
	}

	content, err = compression.Decompress(compressionAlgorithm, bytes)
	if err != nil {
		return nil, nil, nil, err
	}

	var pif models.ProvisionalIndexFile
	err = json.Unmarshal(content, &pif)
	if err != nil {
		return nil, nil, nil, err
	}

	bytes, err = cc.Read(pif.Chunks[0].ChunkFileURI)
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

	return &cif, &pif, &cf, nil
}

func TestBatchTimer(t *testing.T) {
	ctx := newMockContext()
	writer, err := New(namespace, ctx, WithBatchTimeout(2*time.Second))
	require.Nil(t, err)

	writer.Start()
	defer writer.Stop()

	testOp, err := generateOperation(0)
	require.NoError(t, err)

	err = writer.Add(testOp, 0)
	require.Nil(t, err)

	// Batch will be cut after 2 seconds even though
	// maximum operations(=2) have not been reached
	time.Sleep(3 * time.Second)

	require.Equal(t, 1, len(ctx.BlockchainClient.GetAnchors()))

	ad, err := txnprovider.ParseAnchorData(ctx.BlockchainClient.GetAnchors()[0])
	require.NoError(t, err)

	cif, pif, cf, err := getBatchFiles(ctx.ProtocolClient.CasClient, ad.CoreIndexFileURI)
	require.Nil(t, err)

	require.Equal(t, 1, len(cif.Operations.Create))
	require.Equal(t, 0, len(cif.Operations.Recover))
	require.Equal(t, 0, len(cif.Operations.Deactivate))

	require.Nil(t, pif.Operations)

	require.Equal(t, 1, len(cf.Deltas))
}

func TestDiscardDuplicateSuffixInBatchFile(t *testing.T) {
	ctx := newMockContext()
	writer, err := New(namespace, ctx)
	require.Nil(t, err)

	writer.Start()
	defer writer.Stop()

	op, err := generateOperation(1)
	require.NoError(t, err)

	err = writer.Add(op, 0)
	require.Nil(t, err)

	// add same operation again
	err = writer.Add(op, 0)
	require.Nil(t, err)

	time.Sleep(time.Second)

	// we should have 1 anchors: 2 operations % max 2 operations per batch
	require.Equal(t, 1, len(ctx.BlockchainClient.GetAnchors()))

	ad, err := txnprovider.ParseAnchorData(ctx.BlockchainClient.GetAnchors()[0])
	require.NoError(t, err)

	// Check that first anchor has one operation per batch; second one has been discarded
	cif, pif, cf, err := getBatchFiles(ctx.ProtocolClient.CasClient, ad.CoreIndexFileURI)
	require.Nil(t, err)

	require.Equal(t, 1, len(cif.Operations.Create))
	require.Equal(t, 0, len(cif.Operations.Recover))
	require.Equal(t, 0, len(cif.Operations.Deactivate))

	require.Nil(t, pif.Operations)

	require.Equal(t, 1, len(cf.Deltas))
}

func TestProcessOperationsError(t *testing.T) {
	ctx := newMockContext()
	ctx.ProtocolClient.CasClient.SetError(fmt.Errorf("CAS Error"))

	writer, err := New(namespace, ctx, WithBatchTimeout(2*time.Second))
	require.Nil(t, err)

	writer.Start()
	defer writer.Stop()

	operations := generateOperations(3)
	for _, op := range operations {
		err = writer.Add(op, 0)
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
		err = writer.Add(op, 0)
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

	testOp, err := generateOperation(0)
	require.NoError(t, err)

	err = writer.Add(testOp, 0)
	require.EqualError(t, err, "writer is stopped")
}

func TestProcessBatchErrorRecovery(t *testing.T) {
	ctx := newMockContext()
	ctx.ProtocolClient.Protocol.MaxOperationCount = 2
	ctx.ProtocolClient.CasClient = mocks.NewMockCasClient(fmt.Errorf("CAS Error"))

	writer, err := New(namespace, ctx, WithBatchTimeout(500*time.Millisecond))
	require.Nil(t, err)

	writer.Start()
	defer writer.Stop()

	const n = 12
	const numBatchesExpected = 7

	firstOp, err := generateOperation(0)
	require.NoError(t, err)

	require.NoError(t, writer.Add(firstOp, 0))
	time.Sleep(1 * time.Second)

	for _, op := range generateOperations(n) {
		require.NoError(t, writer.Add(op, 0))
	}

	// Clear the error. The batch writer should recover by processing all of the pending batches
	ctx.ProtocolClient.CasClient.SetError(nil)
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
	require.EqualError(t, writer.Add(&operation.QueuedOperation{}, 0), errExpected.Error())
}

func TestStartWithExistingItems(t *testing.T) {
	const numOperations = 23
	const maxOperationsPerBatch = 4
	const numBatchesExpected = 6

	opQueue := &opqueue.MemQueue{}

	ctx := newMockContext()
	ctx.ProtocolClient.Protocol.MaxOperationCount = maxOperationsPerBatch
	ctx.ProtocolClient.CurrentVersion.ProtocolReturns(ctx.ProtocolClient.Protocol)
	ctx.OpQueue = opQueue

	writer, err := New(namespace, ctx)
	require.Nil(t, err)

	// Add operations to the queue directly
	for _, op := range generateOperations(numOperations) {
		_, err = opQueue.Add(op, 0)
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

		invalidQueue := []*operation.QueuedOperationAtTime{{QueuedOperation: operation.QueuedOperation{OperationBuffer: []byte(""), UniqueSuffix: "unique", Namespace: "ns"}}}

		q.LenReturns(1)
		q.PeekReturns(invalidQueue, nil)

		ctx := newMockContext()
		ctx.ProtocolClient.Protocol.MaxOperationCount = 1
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
		ctx.ProtocolClient.Protocol.MaxOperationCount = 2
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
		q.PeekReturns(generateOperationsAtTime(numOperations, 0), nil)
		q.RemoveReturns(0, 1, errExpected)

		ctx := newMockContext()
		ctx.ProtocolClient.Protocol.MaxOperationCount = 2
		ctx.OpQueue = q

		writer, err := New("test2", ctx, WithBatchTimeout(10*time.Millisecond))
		require.NoError(t, err)

		writer.Start()
		defer writer.Stop()

		time.Sleep(50 * time.Millisecond)

		require.Truef(t, writer.Stopped(), "The batch writer should have been stopped due to a remove error")
	})
}

// withError allows for testing an error in options.
func withError() Option {
	return func(o *Options) error {
		return fmt.Errorf("test error")
	}
}

func generateOperations(numOfOperations int) (ops []*operation.QueuedOperation) {
	for j := 1; j <= numOfOperations; j++ {
		op, err := generateOperation(j)
		if err != nil {
			panic(err)
		}

		ops = append(ops, op)
	}

	return
}

func generateOperationsAtTime(numOfOperations int, protocolGenesisTime uint64) (ops []*operation.QueuedOperationAtTime) {
	for j := 1; j <= numOfOperations; j++ {
		op, err := generateOperation(j)
		if err != nil {
			panic(err)
		}

		ops = append(ops, &operation.QueuedOperationAtTime{
			QueuedOperation:     *op,
			ProtocolGenesisTime: protocolGenesisTime,
		})
	}

	return
}

func generateOperation(num int) (*operation.QueuedOperation, error) {
	updateJwk := &jws.JWK{
		Crv: "crv",
		Kty: "kty",
		X:   "x",
	}

	recoverJWK := &jws.JWK{
		Crv: "crv",
		Kty: "kty",
		X:   "x",
		Y:   "y",
	}

	updateCommitment, err := commitment.Calculate(updateJwk, sha2_256)
	if err != nil {
		return nil, err
	}

	recoverComitment, err := commitment.Calculate(recoverJWK, sha2_256)
	if err != nil {
		return nil, err
	}

	doc := fmt.Sprintf(`{"test":%d}`, num)
	info := &client.CreateRequestInfo{
		OpaqueDocument:     doc,
		RecoveryCommitment: recoverComitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      sha2_256,
	}

	request, err := client.NewCreateRequest(info)
	if err != nil {
		return nil, err
	}

	op := &operation.QueuedOperation{
		Namespace:       "did:sidetree",
		UniqueSuffix:    fmt.Sprint(num),
		OperationBuffer: request,
	}

	return op, nil
}

// mockContext implements mock batch writer context.
type mockContext struct {
	ProtocolClient   *mocks.MockProtocolClient
	BlockchainClient *mocks.MockBlockchainClient
	OpQueue          cutter.OperationQueue
}

// newMockContext returns a new mockContext object.
func newMockContext() *mockContext {
	return &mockContext{
		ProtocolClient:   newMockProtocolClient(),
		BlockchainClient: mocks.NewMockBlockchainClient(nil),
		OpQueue:          &opqueue.MemQueue{},
	}
}

// Protocol returns the Client.
func (m *mockContext) Protocol() protocol.Client {
	return m.ProtocolClient
}

// Blockchain returns the block chain client.
func (m *mockContext) Blockchain() BlockchainClient {
	return m.BlockchainClient
}

// OperationQueue returns the queue containing the pending operations.
func (m *mockContext) OperationQueue() cutter.OperationQueue {
	return m.OpQueue
}

func newMockProtocolClient() *mocks.MockProtocolClient {
	pc := mocks.NewMockProtocolClient()
	parser := operationparser.New(pc.Protocol)
	dc := doccomposer.New()
	oa := operationapplier.New(pc.Protocol, parser, dc)

	pc.CasClient = mocks.NewMockCasClient(nil)
	th := txnprovider.NewOperationHandler(pc.Protocol, pc.CasClient, compression.New(compression.WithDefaultAlgorithms()), parser)

	pv := pc.CurrentVersion
	pv.OperationParserReturns(parser)
	pv.OperationApplierReturns(oa)
	pv.DocumentComposerReturns(dc)
	pv.OperationHandlerReturns(th)
	pv.OperationParserReturns(parser)

	return pc
}
