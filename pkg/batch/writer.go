/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package batch batches multiple operations into batch files and stores the batch files in a distributed
// content-addressable storage (DCAS or CAS). A reference to the main batch file (core index) is then
// anchored on the blockchain as Sidetree transaction.
//
// Batch Writer basic flow:
//
// 1) accept operations being delivered via Add method
// 2) 'cut' configurable number of operations into batch files
// 3) store batch files into CAS (content addressable storage)
// 4) write the anchor string referencing core index file URI to the underlying blockchain
package batch

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/cutter"
)

var logger = log.New("sidetree-core-writer")

const (
	defaultBatchTimeout    = 2 * time.Second
	defaultSendChannelSize = 100
)

// Option defines Writer options such as batch timeout.
type Option func(opts *Options) error

type batchCutter interface {
	Add(operation *operation.QueuedOperation, protocolGenesisTime uint64) (uint, error)
	Cut(force bool) (cutter.Result, error)
}

type process struct {
	// force indicates that the operation is to be processed
	// immediately, i.e. don't wait for the batch timeout
	force bool
}

// Writer implements batch writer.
type Writer struct {
	namespace    string
	context      Context
	batchCutter  batchCutter
	sendChan     chan process
	exitChan     chan struct{}
	batchTimeout time.Duration
	stopped      uint32
	protocol     protocol.Client
}

// Context contains batch writer context.
// 1) protocol information client
// 2) content addressable storage client
// 3) blockchain client.
type Context interface {
	Protocol() protocol.Client
	Blockchain() BlockchainClient
	OperationQueue() cutter.OperationQueue
}

// BlockchainClient defines an interface to access the underlying blockchain.
type BlockchainClient interface {
	// WriteAnchor writes the anchor string as a transaction to blockchain
	WriteAnchor(anchor string, ops []*operation.Reference, protocolGenesisTime uint64) error
	// Read ledger transaction
	Read(sinceTransactionNumber int) (bool, *txn.SidetreeTxn)
}

// CompressionProvider defines an interface for handling different types of compression.
type CompressionProvider interface {

	// Compress will compress data using specified algorithm.
	Compress(alg string, data []byte) ([]byte, error)
}

// New creates a new Writer with the given namespace.
// Writer accepts operations being delivered via Add, orders them, and then uses the batch
// cutter to form the operations batch files. The URI of main batch file (index core)
// will be written as part of anchor string to the given ledger.
func New(namespace string, context Context, options ...Option) (*Writer, error) {
	rOpts, err := prepareOptsFromOptions(options...)
	if err != nil {
		return nil, fmt.Errorf("failed to read opts: %s", err)
	}

	batchTimeout := defaultBatchTimeout
	if rOpts.BatchTimeout != 0 {
		batchTimeout = rOpts.BatchTimeout
	}

	return &Writer{
		namespace:    namespace,
		batchCutter:  cutter.New(context.Protocol(), context.OperationQueue()),
		sendChan:     make(chan process, defaultSendChannelSize),
		exitChan:     make(chan struct{}),
		batchTimeout: batchTimeout,
		context:      context,
		protocol:     context.Protocol(),
	}, nil
}

// Start periodic anchoring of operation batches to blockchain.
func (r *Writer) Start() {
	go r.main()
}

// Stop frees the resources which were allocated by start.
func (r *Writer) Stop() {
	if !atomic.CompareAndSwapUint32(&r.stopped, 0, 1) {
		// Already stopped
		return
	}

	select {
	case <-r.exitChan:
		// Allow multiple halts without panic
	default:
		close(r.exitChan)
	}
}

// Stopped returns true if the writer has been stopped.
func (r *Writer) Stopped() bool {
	return atomic.LoadUint32(&r.stopped) == 1
}

// Add the given operation to a queue of operations to be batched and anchored on blockchain.
func (r *Writer) Add(op *operation.QueuedOperation, protocolGenesisTime uint64) error {
	if r.Stopped() {
		return errors.New("writer is stopped")
	}

	_, err := r.batchCutter.Add(op, protocolGenesisTime)
	if err != nil {
		return err
	}

	select {
	case r.sendChan <- process{force: false}:
		// Send a notification that an operation was added to the queue
		logger.Infof("[%s] operation added to the queue", op.UniqueSuffix)

		return nil
	case <-r.exitChan:
		return fmt.Errorf("message from exit channel")
	}
}

func (r *Writer) main() {
	var timer <-chan time.Time

	// On startup, there may be operations in the queue. Send a notification
	// so that any pending items in the queue may be immediately processed.
	r.sendChan <- process{force: true}

	for {
		select {
		case p := <-r.sendChan:
			logger.Infof("[%s] Handling process notification for batch writer: %v", r.namespace, p)
			pending := r.processAvailable(p.force) > 0
			timer = r.handleTimer(timer, pending)

		case <-timer:
			logger.Infof("[%s] Handling batch writer timeout", r.namespace)
			pending := r.processAvailable(true) > 0
			timer = r.handleTimer(nil, pending)

		case <-r.exitChan:
			logger.Infof("[%s] exiting batch writer", r.namespace)

			return
		}
	}
}

func (r *Writer) processAvailable(forceCut bool) uint {
	// First drain the queue of all of the operations that are ready to form a batch
	pending, err := r.drain()
	if err != nil {
		logger.Warnf("[%s] Error draining operations queue: %s. Pending operations: %d.", r.namespace, err, pending)

		return pending
	}

	if pending == 0 || !forceCut {
		logger.Debugf("[%s] No further processing necessary. Pending operations: %d", r.namespace, pending)

		return pending
	}

	logger.Infof("[%s] Forcefully processing operations. Pending operations: %d", r.namespace, pending)

	// Now process the remaining operations
	n, pending, err := r.cutAndProcess(true)
	if err != nil {
		logger.Warnf("[%s] Error processing operations: %s. Pending operations: %d.", r.namespace, err, pending)
	} else {
		logger.Infof("[%s] Successfully processed %d operations. Pending operations: %d.", r.namespace, n, pending)
	}

	return pending
}

// drain cuts and processes all pending operations that are ready to form a batch.
func (r *Writer) drain() (pending uint, err error) {
	logger.Debugf("[%s] Draining operations queue...", r.namespace)
	for {
		n, pending, err := r.cutAndProcess(false)
		if err != nil {
			logger.Errorf("[%s] Error draining operations: cutting and processing returned an error: %s", r.namespace, err)

			return pending, err
		}
		if n == 0 {
			logger.Infof("[%s] ... drain - no outstanding batches to be processed. Pending operations: %d", r.namespace, pending)

			return pending, nil
		}
		logger.Infof("[%s] ... drain processed %d operations into batch. Pending operations: %d", r.namespace, n, pending)
	}
}

func (r *Writer) cutAndProcess(forceCut bool) (numProcessed int, pending uint, err error) {
	result, err := r.batchCutter.Cut(forceCut)
	if err != nil {
		logger.Errorf("[%s] Error cutting batch: %s", r.namespace, err)

		return 0, 0, err
	}

	if len(result.Operations) == 0 {
		logger.Debugf("[%s] No operations to be processed", r.namespace)

		return 0, result.Pending, nil
	}

	logger.Infof("[%s] processing %d batch operations for protocol genesis time[%d]...", r.namespace, len(result.Operations), result.ProtocolGenesisTime)

	err = r.process(result.Operations, result.ProtocolGenesisTime)
	if err != nil {
		logger.Errorf("[%s] Error processing %d batch operations: %s", r.namespace, len(result.Operations), err)

		return 0, result.Pending + uint(len(result.Operations)), err
	}

	logger.Infof("[%s] Successfully processed %d batch operations. Committing to batch cutter ...", r.namespace, len(result.Operations))

	pending, err = result.Commit()
	if err != nil {
		logger.Errorf("[%s] Batch operations were committed but could not be removed from the queue due to error [%s]. Stopping the batch writer so that no further ops are added.", r.namespace, err)
		r.Stop()

		return 0, pending, errors.WithMessagef(err, "operations were committed but could not be removed from the queue")
	}

	logger.Infof("[%s] Successfully committed to batch cutter. Pending operations: %d", r.namespace, pending)

	return len(result.Operations), pending, nil
}

func (r *Writer) process(ops []*operation.QueuedOperation, protocolGenesisTime uint64) error {
	if len(ops) == 0 {
		return errors.New("create batch called with no pending operations, should not happen")
	}

	p, err := r.protocol.Get(protocolGenesisTime)
	if err != nil {
		return err
	}

	anchorString, dids, err := p.OperationHandler().PrepareTxnFiles(ops)
	if err != nil {
		return err
	}

	logger.Infof("[%s] writing anchor string: %s", r.namespace, anchorString)

	// Create Sidetree transaction in blockchain (write anchor string)
	return r.context.Blockchain().WriteAnchor(anchorString, dids, protocolGenesisTime)
}

func (r *Writer) handleTimer(timer <-chan time.Time, pending bool) <-chan time.Time {
	switch {
	case timer != nil && !pending:
		// Timer is already running but there are no messages pending, stop the timer
		return nil
	case timer == nil && pending:
		// Timer is not already running and there are messages pending, so start it
		return time.After(r.batchTimeout)
	default:
		// Do nothing when:
		// 1. Timer is already running and there are messages pending
		// 2. Timer is not set and there are no messages pending
		return timer
	}
}

// WithBatchTimeout allows for specifying batch timeout.
func WithBatchTimeout(batchTimeout time.Duration) Option {
	return func(o *Options) error {
		o.BatchTimeout = batchTimeout

		return nil
	}
}

// Options allows the user to specify more advanced options.
type Options struct {
	BatchTimeout time.Duration
}

// prepareOptsFromOptions reads options.
func prepareOptsFromOptions(options ...Option) (Options, error) {
	rOpts := Options{}
	for _, option := range options {
		err := option(&rOpts)
		if err != nil {
			return rOpts, err
		}
	}

	return rOpts, nil
}
