/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package batch batches multiple operations into batch files and stores the batch files in a distributed
// content-addressable storage (DCAS or CAS). A reference to the main batch file (core index) is then
// anchored on the anchoring system as Sidetree transaction.
//
// Batch Writer basic flow:
//
// 1) accept operations being delivered via Add method
// 2) 'cut' configurable number of operations into batch files
// 3) store batch files into CAS (content addressable storage)
// 4) write the anchor string referencing core index file URI to the underlying anchoring system
package batch

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/cutter"
	logfields "github.com/trustbloc/sidetree-core-go/pkg/internal/log"
)

const (
	loggerModule = "sidetree-core-writer"

	defaultBatchTimeout    = 2 * time.Second
	defaultMonitorInterval = time.Second
)

// Option defines Writer options such as batch timeout.
type Option func(opts *Options) error

type batchCutter interface {
	Add(operation *operation.QueuedOperation, protocolVersion uint64) (uint, error)
	Cut(force bool) (cutter.Result, error)
}

// Writer implements batch writer.
type Writer struct {
	namespace          string
	context            Context
	batchCutter        batchCutter
	exitChan           chan struct{}
	stopped            uint32
	protocol           protocol.Client
	monitorTicker      *time.Ticker
	batchTimeoutTicker *time.Ticker
	logger             *log.Log
}

// Context contains batch writer context.
// 1) protocol information client
// 2) content addressable storage client
// 3) anchor writer.
type Context interface {
	Protocol() protocol.Client
	Anchor() AnchorWriter
	OperationQueue() cutter.OperationQueue
}

// AnchorWriter defines an interface to access the underlying anchoring system.
type AnchorWriter interface {
	// WriteAnchor writes the anchor string as a transaction to anchoring system
	WriteAnchor(anchor string, artifacts []*protocol.AnchorDocument, ops []*operation.Reference, protocolVersion uint64) error
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

	monitorInterval := defaultMonitorInterval
	if rOpts.MonitorInterval != 0 {
		monitorInterval = rOpts.MonitorInterval
	}

	return &Writer{
		namespace:          namespace,
		batchCutter:        cutter.New(context.Protocol(), context.OperationQueue()),
		exitChan:           make(chan struct{}),
		context:            context,
		protocol:           context.Protocol(),
		batchTimeoutTicker: time.NewTicker(batchTimeout),
		monitorTicker:      time.NewTicker(monitorInterval),
		logger:             log.New(loggerModule, log.WithFields(logfields.WithNamespace(namespace))),
	}, nil
}

// Start periodic anchoring of operation batches to anchoring system.
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

// Add the given operation to a queue of operations to be batched and anchored on anchoring system.
func (r *Writer) Add(op *operation.QueuedOperation, protocolVersion uint64) error {
	if r.Stopped() {
		return errors.New("writer is stopped")
	}

	_, err := r.batchCutter.Add(op, protocolVersion)
	if err != nil {
		return err
	}

	return nil
}

func (r *Writer) main() {
	// On startup, there may be operations in the queue. Process them immediately.
	r.processAvailable(true)

	for {
		select {
		case <-r.monitorTicker.C:
			r.processAvailable(false)

		case <-r.batchTimeoutTicker.C:
			r.processAvailable(true)

		case <-r.exitChan:
			r.logger.Info("Exiting batch writer")

			return
		}
	}
}

func (r *Writer) processAvailable(forceCut bool) uint {
	// First drain the queue of all of the operations that are ready to form a batch
	pending, err := r.drain()
	if err != nil {
		r.logger.Warn("Error draining operations queue.",
			log.WithError(err), logfields.WithTotalPending(pending))

		return pending
	}

	if pending == 0 || !forceCut {
		return pending
	}

	r.logger.Debug("Forcefully processing operations", logfields.WithTotalPending(pending))

	// Now process the remaining operations
	n, pending, err := r.cutAndProcess(true)
	if err != nil {
		r.logger.Warn("Error processing operations", log.WithError(err), logfields.WithTotalPending(pending))
	} else {
		r.logger.Info("Successfully processed operations.", logfields.WithTotal(n), logfields.WithTotalPending(pending))
	}

	return pending
}

// drain cuts and processes all pending operations that are ready to form a batch.
func (r *Writer) drain() (pending uint, err error) {
	for {
		n, pending, err := r.cutAndProcess(false)
		if err != nil {
			r.logger.Error("Error draining operations: cutting and processing returned an error", log.WithError(err))

			return pending, err
		}

		if n == 0 {
			return pending, nil
		}

		r.logger.Info(" ... drain processed operations into batch.", logfields.WithTotal(n), logfields.WithTotalPending(pending))
	}
}

func (r *Writer) cutAndProcess(forceCut bool) (numProcessed int, pending uint, err error) {
	result, err := r.batchCutter.Cut(forceCut)
	if err != nil {
		r.logger.Error("Error cutting batch", log.WithError(err))

		return 0, 0, err
	}

	if len(result.Operations) == 0 {
		return 0, result.Pending, nil
	}

	r.logger.Info("Processing batch operations for protocol genesis time...",
		logfields.WithTotal(len(result.Operations)), logfields.WithGenesisTime(result.ProtocolVersion))

	err = r.process(result.Operations, result.ProtocolVersion)
	if err != nil {
		r.logger.Error("Error processing batch operations", logfields.WithTotal(len(result.Operations)), log.WithError(err))

		result.Nack()

		return 0, result.Pending + uint(len(result.Operations)), err
	}

	r.logger.Info("Successfully processed batch operations. Committing to batch cutter ...",
		logfields.WithTotal(len(result.Operations)))

	pending = result.Ack()

	r.logger.Info("Successfully committed to batch cutter.", logfields.WithTotalPending(pending))

	return len(result.Operations), pending, nil
}

func (r *Writer) process(ops []*operation.QueuedOperation, protocolVersion uint64) error {
	if len(ops) == 0 {
		return errors.New("create batch called with no pending operations, should not happen")
	}

	p, err := r.protocol.Get(protocolVersion)
	if err != nil {
		return err
	}

	anchoringInfo, err := p.OperationHandler().PrepareTxnFiles(ops)
	if err != nil {
		return err
	}

	// Sidetree spec allows for one operation per suffix in the batch
	// Process additional operations for suffix in the next batch
	for _, op := range anchoringInfo.AdditionalOperations {
		err = r.Add(op, protocolVersion)
		if err != nil {
			// this error should never happen since parsing of this operation has already been done for the previous batch
			r.logger.Warn("Unable to add additional operation to the next batch",
				logfields.WithSuffix(op.UniqueSuffix), log.WithError(err))
		}
	}

	r.logger.Info("Writing anchor string", logfields.WithAnchorString(anchoringInfo.AnchorString))

	// Create Sidetree transaction in anchoring system (write anchor string)
	return r.context.Anchor().WriteAnchor(anchoringInfo.AnchorString, anchoringInfo.Artifacts,
		anchoringInfo.OperationReferences, protocolVersion)
}

// WithBatchTimeout allows for specifying batch timeout.
func WithBatchTimeout(batchTimeout time.Duration) Option {
	return func(o *Options) error {
		o.BatchTimeout = batchTimeout

		return nil
	}
}

// WithMonitorInterval specifies the interval in which the operation queue is monitored in order to see
// if the maximum batch size has been reached.
func WithMonitorInterval(interval time.Duration) Option {
	return func(o *Options) error {
		o.MonitorInterval = interval

		return nil
	}
}

// Options allows the user to specify more advanced options.
type Options struct {
	BatchTimeout    time.Duration
	MonitorInterval time.Duration
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
