/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package batch

import (
	"fmt"
	"time"

	"gitlab.com/NebulousLabs/errors"

	"github.com/trustbloc/sidetree-core-go/pkg/batch/filehandler"

	"github.com/trustbloc/sidetree-core-go/pkg/api"

	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/batch/cutter"
)

const defaultBatchTimeout = 2 * time.Second

// Option defines Writer options such as batch timeout
type Option func(opts *Options) error

// Writer implements batch writer
type Writer struct {
	context      Context
	batchCutter  cutter.Cutter
	sendChan     chan []byte
	exitChan     chan struct{}
	batchTimeout time.Duration
	opsHandler   OperationHandler
}

// Context contains batch writer context
// 1) protocol information client
// 2) content addressable storage client
// 3) blockchain client
type Context interface {
	Protocol() api.ProtocolClient
	CAS() CASClient
	Blockchain() BlockchainClient
}

// BlockchainClient defines an interface to access the underlying blockchain
type BlockchainClient interface {
	// WriteAnchor writes the anchor file hash as a transaction to blockchain
	WriteAnchor(anchor string) error
}

// CASClient defines interface for accessing the underlying content addressable storage
type CASClient interface {
	// Write writes the given content to CASClient.
	// returns the SHA256 hash in base64url encoding which represents the address of the content.
	Write(content []byte) (string, error)

	// Read reads the content of the given address in CASClient.
	// returns the content of the given address.
	Read(address string) ([]byte, error)
}

// OperationHandler defines an interface for creating batch and anchor files
type OperationHandler interface {
	// CreateBatchFile will create batch file bytes
	CreateBatchFile(operations [][]byte) ([]byte, error)

	// CreateAnchorFile will create anchor file bytes for Sidetree transaction
	CreateAnchorFile(operations [][]byte, batchAddress string, multihashCode uint) ([]byte, error)
}

// New creates a new Writer. Writer accepts operations being delivered via Add, orders them, and then uses the batch
// cutter to form the operations batch file. This batch file will then be used to generate Merkle tree and create
// an anchor file. The hash of anchor file will be written to the given ledger.
func New(context Context, options ...Option) (*Writer, error) {

	rOpts, err := prepareOptsFromOptions(options...)
	if err != nil {
		return nil, fmt.Errorf("failed to read opts: %s", err)
	}

	batchTimeout := defaultBatchTimeout
	if rOpts.BatchTimeout != 0 {
		batchTimeout = rOpts.BatchTimeout
	}

	var opsHandler OperationHandler
	if rOpts.OpsHandler != nil {
		opsHandler = rOpts.OpsHandler
	} else {
		opsHandler = filehandler.New()
	}

	return &Writer{
		batchCutter:  cutter.New(),
		sendChan:     make(chan []byte),
		exitChan:     make(chan struct{}),
		batchTimeout: batchTimeout,
		context:      context,
		opsHandler:   opsHandler,
	}, nil
}

// Start periodic anchoring of operation batches to blockchain.
func (r *Writer) Start() {
	go r.main()
}

// Stop frees the resources which were allocated by start.
func (r *Writer) Stop() {
	select {
	case <-r.exitChan:
		// Allow multiple halts without panic
	default:
		close(r.exitChan)
	}
}

// Add the given operation to a queue of operations to be batched and anchored on blockchain.
func (r *Writer) Add(operation []byte) error {
	select {
	case r.sendChan <- operation:
		return nil
	case <-r.exitChan:
		return fmt.Errorf("message from exit channel")
	}
}

func (r *Writer) main() {

	var timer <-chan time.Time

	for {

		select {
		case op := <-r.sendChan:

			protocol := r.context.Protocol().Current()
			operations, pending := r.batchCutter.Add(op, protocol.MaxOperationsPerBatch)

			if len(operations) > 0 {

				log.Debug("processing batch operations after adding document ...")

				err := r.processOperations(operations, protocol.HashAlgorithmInMultiHashCode)
				if err != nil {
					// log error for now, recovery will be handled later
					log.Errorf("failed to process operations after adding document: %s", err.Error())
				}
			}

			timer = r.handleTimer(timer, pending)

		case <-timer:
			//clear the timer
			timer = nil

			log.Debug("processing batch operations after batch timeout ...")

			operations := r.batchCutter.Cut()
			err := r.processOperations(operations, r.context.Protocol().Current().HashAlgorithmInMultiHashCode)
			if err != nil {
				// log error for now, recovery will be handled later
				log.Errorf("failed to process batch operations after batch timeout: %s", err.Error())
			}

		case <-r.exitChan:
			log.Info("exiting batch writer")
			return
		}
	}
}

func (r *Writer) processOperations(operations [][]byte, multihashCode uint) error {

	if len(operations) == 0 {
		return errors.New("create batch called with no pending operations, should not happen")
	}

	batchBytes, err := r.opsHandler.CreateBatchFile(operations)
	if err != nil {
		return err
	}

	log.Debugf("batch: %s", string(batchBytes))

	// Make the batch file available in CAS
	batchAddr, err := r.context.CAS().Write(batchBytes)
	if err != nil {
		return err
	}

	anchorBytes, err := r.opsHandler.CreateAnchorFile(operations, batchAddr, multihashCode)
	if err != nil {
		return err
	}

	log.Debugf("anchor: %s", string(anchorBytes))

	// Make the anchor file available in CAS
	anchorAddr, err := r.context.CAS().Write(anchorBytes)
	if err != nil {
		return err
	}

	// Create Sidetree transaction in blockchain
	return r.context.Blockchain().WriteAnchor(anchorAddr)
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

//WithBatchTimeout allows for specifying batch timeout
func WithBatchTimeout(batchTimeout time.Duration) Option {
	return func(o *Options) error {
		o.BatchTimeout = batchTimeout
		return nil
	}
}

//WithOperationHandler allows for specifying handler for creating anchor/batch files
func WithOperationHandler(opsHandler OperationHandler) Option {
	return func(o *Options) error {
		o.OpsHandler = opsHandler
		return nil
	}
}

// Options allows the user to specify more advanced options
type Options struct {
	BatchTimeout time.Duration
	OpsHandler   OperationHandler
}

//prepareOptsFromOptions reads options
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
