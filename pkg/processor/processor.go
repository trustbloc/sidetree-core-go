/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package processor

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	logfields "github.com/trustbloc/sidetree-core-go/pkg/internal/log"
)

const loggerModule = "sidetree-core-processor"

// OperationProcessor will process document operations in chronological order and create final document during resolution.
// It uses operation store client to retrieve all operations that are related to requested document.
type OperationProcessor struct {
	store OperationStoreClient
	pc    protocol.Client

	unpublishedOperationStore unpublishedOperationStore
	logger                    *log.Log
}

// OperationStoreClient defines interface for retrieving all operations related to document.
type OperationStoreClient interface {
	// Get retrieves all operations related to document
	Get(uniqueSuffix string) ([]*operation.AnchoredOperation, error)
}

type unpublishedOperationStore interface {
	// Get retrieves unpublished operation related to document, we can have only one unpublished operation.
	Get(uniqueSuffix string) ([]*operation.AnchoredOperation, error)
}

// New returns new operation processor with the given name. (Note that name is only used for logging.)
func New(name string, store OperationStoreClient, pc protocol.Client, opts ...Option) *OperationProcessor {
	op := &OperationProcessor{
		store: store,
		pc:    pc, unpublishedOperationStore: &noopUnpublishedOpsStore{},
		logger: log.New(loggerModule, log.WithFields(logfields.WithNamespace(name))),
	}

	// apply options
	for _, opt := range opts {
		opt(op)
	}

	return op
}

// Option is an option for operation processor.
type Option func(opts *OperationProcessor)

// WithUnpublishedOperationStore stores unpublished operation into unpublished operation store.
func WithUnpublishedOperationStore(store unpublishedOperationStore) Option {
	return func(opts *OperationProcessor) {
		opts.unpublishedOperationStore = store
	}
}

// Resolve document based on the given unique suffix.
// Parameters:
// uniqueSuffix - unique portion of ID to resolve. for example "abc123" in "did:sidetree:abc123".
func (s *OperationProcessor) Resolve(uniqueSuffix string, opts ...document.ResolutionOption) (*protocol.ResolutionModel, error) {
	var unpublishedOps []*operation.AnchoredOperation

	unpubOps, err := s.unpublishedOperationStore.Get(uniqueSuffix)
	if err == nil {
		s.logger.Debug("Found unpublished operations for unique suffix",
			logfields.WithTotal(len(unpubOps)), logfields.WithSuffix(uniqueSuffix))

		unpublishedOps = append(unpublishedOps, unpubOps...)
	}

	publishedOps, err := s.store.Get(uniqueSuffix)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		return nil, err
	}

	publishedOps, unpublishedOps, filteredOps, err := s.processOperations(publishedOps, unpublishedOps, uniqueSuffix, opts...)
	if err != nil {
		return nil, err
	}

	// return all operations in response - versionId is considered just like view of information
	rm := &protocol.ResolutionModel{PublishedOperations: publishedOps, UnpublishedOperations: unpublishedOps}

	// split operations into 'create', 'update' and 'full' operations
	createOps, updateOps, fullOps := splitOperations(filteredOps)
	if len(createOps) == 0 {
		return nil, fmt.Errorf("create operation not found")
	}

	// Ensure that all published 'create' operations are processed first (in case there are
	// unpublished 'create' operations in the collection due to race condition).
	sort.SliceStable(createOps, func(i, j int) bool {
		return createOps[i].CanonicalReference != ""
	})

	// apply 'create' operations first
	rm = s.applyFirstValidCreateOperation(createOps, rm)
	if rm == nil {
		return nil, errors.New("valid create operation not found")
	}

	// apply 'full' operations first
	if len(fullOps) > 0 {
		s.logger.Debug("Applying full operations", logfields.WithTotal(len(fullOps)), logfields.WithSuffix(uniqueSuffix))

		rm = s.applyOperations(fullOps, rm, getRecoveryCommitment)
		if rm.Deactivated {
			// document was deactivated, stop processing
			return rm, nil
		}
	}

	// next apply update ops since last 'full' transaction
	filteredUpdateOps := getOpsWithTxnGreaterThanOrUnpublished(updateOps, rm.LastOperationTransactionTime, rm.LastOperationTransactionNumber)
	if len(filteredUpdateOps) > 0 {
		s.logger.Debug("Applying update operations after last full operation", logfields.WithTotal(len(filteredUpdateOps)),
			logfields.WithSuffix(uniqueSuffix))
		rm = s.applyOperations(filteredUpdateOps, rm, getUpdateCommitment)
	}

	return rm, nil
}

func (s *OperationProcessor) processOperations(
	publishedOps []*operation.AnchoredOperation,
	unpublishedOps []*operation.AnchoredOperation,
	uniqueSuffix string,
	opts ...document.ResolutionOption,
) ([]*operation.AnchoredOperation, []*operation.AnchoredOperation, []*operation.AnchoredOperation, error) {
	resOpts, err := document.GetResolutionOptions(opts...)
	if err != nil {
		return nil, nil, nil, err
	}

	pubOps, unpubOps, ops, err := s.applyResolutionOptions(uniqueSuffix, publishedOps, unpublishedOps, resOpts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to apply resolution options for document id[%s]: %s", uniqueSuffix, err.Error())
	}

	return pubOps, unpubOps, ops, nil
}

func (s *OperationProcessor) filterOps(ops []*operation.AnchoredOperation, opts document.ResolutionOptions,
	uniqueSuffx string) ([]*operation.AnchoredOperation, error) {
	if opts.VersionID != "" {
		s.logger.Debug("Filtering operations for unique suffix by version", logfields.WithSuffix(uniqueSuffx),
			logfields.WithVersion(opts.VersionID))

		return filterOpsByVersionID(ops, opts.VersionID)
	}

	if opts.VersionTime != "" {
		s.logger.Debug("Filtering operations for unique suffix by versionTime", logfields.WithSuffix(uniqueSuffx),
			logfields.WithVersionTime(opts.VersionTime))

		return filterOpsByVersionTime(ops, opts.VersionTime)
	}

	return ops, nil
}

func filterOpsByVersionID(ops []*operation.AnchoredOperation, versionID string) ([]*operation.AnchoredOperation, error) {
	for index, op := range ops {
		if op.CanonicalReference == versionID {
			return ops[:index+1], nil
		}
	}

	return nil, fmt.Errorf("'%s' is not a valid versionId", versionID)
}

func filterOpsByVersionTime(ops []*operation.AnchoredOperation, timeStr string) ([]*operation.AnchoredOperation, error) {
	var filteredOps []*operation.AnchoredOperation

	vt, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse version time[%s]: %w", timeStr, err)
	}

	for _, op := range ops {
		if op.TransactionTime <= uint64(vt.Unix()) {
			filteredOps = append(filteredOps, op)
		}
	}

	if len(filteredOps) == 0 {
		return nil, fmt.Errorf("no operations found for version time %s", timeStr)
	}

	return filteredOps, nil
}

func (s *OperationProcessor) applyResolutionOptions(uniqueSuffix string, published, unpublished []*operation.AnchoredOperation,
	opts document.ResolutionOptions) ([]*operation.AnchoredOperation, []*operation.AnchoredOperation, []*operation.AnchoredOperation, error) {
	canonicalIds := getCanonicalMap(published)

	for _, op := range opts.AdditionalOperations {
		if op.CanonicalReference == "" {
			unpublished = append(unpublished, op)
		} else if _, ok := canonicalIds[op.CanonicalReference]; !ok {
			published = append(published, op)
		}
	}

	sortOperations(published)
	sortOperations(unpublished)

	ops := append(published, unpublished...) //nolint:gocritic

	s.logger.Debug("Found operations for unique suffix", logfields.WithTotalOperations(len(ops)),
		logfields.WithSuffix(uniqueSuffix), logfields.WithOperations(ops))

	filteredOps, err := s.filterOps(ops, opts, uniqueSuffix)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to filter document id[%s] operations: %s", uniqueSuffix, err.Error())
	}

	if len(filteredOps) == len(ops) {
		// base case : nothing got filtered
		return published, unpublished, ops, nil
	}

	var filteredPublishedOps []*operation.AnchoredOperation
	var filteredUnpublishedOps []*operation.AnchoredOperation

	for _, op := range filteredOps {
		if op.CanonicalReference == "" {
			filteredUnpublishedOps = append(filteredUnpublishedOps, op)
		} else {
			filteredPublishedOps = append(filteredPublishedOps, op)
		}
	}

	return filteredPublishedOps, filteredUnpublishedOps, filteredOps, nil
}

func getCanonicalMap(published []*operation.AnchoredOperation) map[string]bool {
	canonicalMap := make(map[string]bool)

	for _, op := range published {
		canonicalMap[op.CanonicalReference] = true
	}

	return canonicalMap
}

func (s *OperationProcessor) createOperationHashMap(ops []*operation.AnchoredOperation) map[string][]*operation.AnchoredOperation {
	opMap := make(map[string][]*operation.AnchoredOperation)

	for _, op := range ops {
		rv, err := s.getRevealValue(op)
		if err != nil {
			s.logger.Info("Skipped bad operation while creating operation hash map", logfields.WithSuffix(op.UniqueSuffix),
				logfields.WithOperationType(string(op.Type)), logfields.WithTransactionTime(op.TransactionTime),
				logfields.WithTransactionNumber(op.TransactionNumber), log.WithError(err))

			continue
		}

		c, err := commitment.GetCommitmentFromRevealValue(rv)
		if err != nil {
			s.logger.Info("Skipped calculating commitment while creating operation hash map", logfields.WithSuffix(op.UniqueSuffix),
				logfields.WithOperationType(string(op.Type)), logfields.WithTransactionTime(op.TransactionTime),
				logfields.WithTransactionNumber(op.TransactionNumber), log.WithError(err))

			continue
		}

		opMap[c] = append(opMap[c], op)
	}

	return opMap
}

func splitOperations(ops []*operation.AnchoredOperation) (createOps, updateOps, fullOps []*operation.AnchoredOperation) {
	for _, op := range ops {
		switch op.Type {
		case operation.TypeCreate:
			createOps = append(createOps, op)
		case operation.TypeUpdate:
			updateOps = append(updateOps, op)
		case operation.TypeRecover:
			fullOps = append(fullOps, op)
		case operation.TypeDeactivate:
			fullOps = append(fullOps, op)
		}
	}

	return createOps, updateOps, fullOps
}

func getOpsWithTxnGreaterThanOrUnpublished(ops []*operation.AnchoredOperation, txnTime, txnNumber uint64) []*operation.AnchoredOperation {
	var selection []*operation.AnchoredOperation

	for _, op := range ops {
		if isOpWithTxnGreaterThanOrUnpublished(op, txnTime, txnNumber) {
			selection = append(selection, op)
		}
	}

	return selection
}

func isOpWithTxnGreaterThanOrUnpublished(op *operation.AnchoredOperation, txnTime, txnNumber uint64) bool {
	if op.CanonicalReference == "" {
		return true
	}

	if op.TransactionTime < txnTime {
		return false
	}

	if op.TransactionTime > txnTime {
		return true
	}

	if op.TransactionNumber > txnNumber {
		return true
	}

	return false
}

func (s *OperationProcessor) applyOperations(ops []*operation.AnchoredOperation, rm *protocol.ResolutionModel,
	commitmentFnc fnc) *protocol.ResolutionModel {
	// suffix for logging
	uniqueSuffix := ops[0].UniqueSuffix

	state := rm

	opMap := s.createOperationHashMap(ops)

	// holds applied commitments
	commitmentMap := make(map[string]bool)

	c := commitmentFnc(state)

	s.logger.Debug("Processing commitment", logfields.WithCommitment(c), logfields.WithSuffix(uniqueSuffix))

	commitmentOps, ok := opMap[c]
	for ok {
		s.logger.Debug("Found operation(s) for commitment", logfields.WithTotal(len(commitmentOps)),
			logfields.WithCommitment(c), logfields.WithSuffix(uniqueSuffix))

		newState := s.applyFirstValidOperation(commitmentOps, state, c, commitmentMap)

		// can't find a valid operation to apply
		if newState == nil {
			s.logger.Info("Unable to apply valid operation for commitment", logfields.WithCommitment(c),
				logfields.WithSuffixes(uniqueSuffix))

			break
		}

		// commitment has been processed successfully
		commitmentMap[c] = true
		state = newState

		s.logger.Debug("Successfully processed commitment", logfields.WithCommitment(c), logfields.WithSuffix(uniqueSuffix))

		// get next commitment to be processed
		c = commitmentFnc(state)

		s.logger.Debug("Next commitment to process", logfields.WithCommitment(c), logfields.WithSuffix(uniqueSuffix))

		// stop if there is no next commitment
		if c == "" {
			return state
		}

		commitmentOps, ok = opMap[c]
	}

	if len(commitmentMap) != len(ops) {
		s.logger.Debug("Number of commitments applied doesn't match number of operations",
			logfields.WithTotalCommitments(len(commitmentMap)), logfields.WithTotalOperations(len(ops)),
			logfields.WithSuffix(uniqueSuffix))
	}

	return state
}

type fnc func(rm *protocol.ResolutionModel) string

func getUpdateCommitment(rm *protocol.ResolutionModel) string {
	return rm.UpdateCommitment
}

func getRecoveryCommitment(rm *protocol.ResolutionModel) string {
	return rm.RecoveryCommitment
}

func (s *OperationProcessor) applyFirstValidCreateOperation(createOps []*operation.AnchoredOperation,
	rm *protocol.ResolutionModel) *protocol.ResolutionModel {
	for _, op := range createOps {
		var state *protocol.ResolutionModel
		var err error

		if state, err = s.applyOperation(op, rm); err != nil {
			s.logger.Info("Skipped bad operation", logfields.WithSuffix(op.UniqueSuffix), logfields.WithOperationType(string(op.Type)),
				logfields.WithTransactionTime(op.TransactionTime), logfields.WithTransactionNumber(op.TransactionNumber),
				log.WithError(err))

			continue
		}

		s.logger.Debug("Applied create operation, recover commitment, update commitment which results in new document",
			logfields.WithOperation(op), logfields.WithRecoveryCommitment(state.RecoveryCommitment),
			logfields.WithUpdateCommitment(state.UpdateCommitment), logfields.WithDocument(state.Doc))

		return state
	}

	return nil
}

// this function should be used for update, recover and deactivate operations (create is handled differently).
func (s *OperationProcessor) applyFirstValidOperation(ops []*operation.AnchoredOperation, rm *protocol.ResolutionModel,
	currCommitment string, processedCommitments map[string]bool) *protocol.ResolutionModel {
	for _, op := range ops {
		var state *protocol.ResolutionModel
		var err error

		nextCommitment, err := s.getCommitment(op)
		if err != nil {
			s.logger.Info("Skipped bad operation", logfields.WithSuffix(op.UniqueSuffix), logfields.WithOperationType(string(op.Type)),
				logfields.WithTransactionTime(op.TransactionTime), logfields.WithTransactionNumber(op.TransactionNumber), log.WithError(err))

			continue
		}

		if currCommitment == nextCommitment {
			s.logger.Info("Skipped bad operatio. Reason: operation commitment(key) equals next operation commitment(key)",
				logfields.WithSuffix(op.UniqueSuffix), logfields.WithOperationType(string(op.Type)),
				logfields.WithTransactionTime(op.TransactionTime), logfields.WithTransactionNumber(op.TransactionNumber))

			continue
		}

		if nextCommitment != "" {
			// for recovery and update operations check if next commitment has been used already; if so skip to next operation
			_, processed := processedCommitments[nextCommitment]
			if processed {
				s.logger.Info("Skipped bad operation. Reason: next operation commitment(key) has already been used",
					logfields.WithSuffix(op.UniqueSuffix), logfields.WithOperationType(string(op.Type)),
					logfields.WithTransactionTime(op.TransactionTime), logfields.WithTransactionNumber(op.TransactionNumber))

				continue
			}
		}

		if state, err = s.applyOperation(op, rm); err != nil {
			s.logger.Info("Skipped bad operation", logfields.WithSuffix(op.UniqueSuffix), logfields.WithOperationType(string(op.Type)),
				logfields.WithTransactionTime(op.TransactionTime), logfields.WithTransactionNumber(op.TransactionNumber),
				log.WithError(err))

			continue
		}

		s.logger.Debug("Applyied operation.", logfields.WithOperation(op), logfields.WithRecoveryCommitment(state.RecoveryCommitment),
			logfields.WithUpdateCommitment(state.UpdateCommitment), logfields.WithDeactivated(state.Deactivated), logfields.WithDocument(state.Doc))

		return state
	}

	return nil
}

func (s *OperationProcessor) applyOperation(op *operation.AnchoredOperation,
	rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) {
	p, err := s.pc.Get(op.ProtocolVersion)
	if err != nil {
		return nil, fmt.Errorf("apply '%s' operation: %s", op.Type, err.Error())
	}

	return p.OperationApplier().Apply(op, rm)
}

func sortOperations(ops []*operation.AnchoredOperation) {
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].TransactionTime < ops[j].TransactionTime {
			return true
		}

		return ops[i].TransactionNumber < ops[j].TransactionNumber
	})
}

func (s *OperationProcessor) getRevealValue(op *operation.AnchoredOperation) (string, error) {
	if op.Type == operation.TypeCreate {
		return "", errors.New("create operation doesn't have reveal value")
	}

	p, err := s.pc.Get(op.ProtocolVersion)
	if err != nil {
		return "", fmt.Errorf("get operation reveal value - retrieve protocol: %s", err.Error())
	}

	rv, err := p.OperationParser().GetRevealValue(op.OperationRequest)
	if err != nil {
		return "", fmt.Errorf("get operation reveal value from operation parser: %s", err.Error())
	}

	return rv, nil
}

func (s *OperationProcessor) getCommitment(op *operation.AnchoredOperation) (string, error) {
	p, err := s.pc.Get(op.ProtocolVersion)
	if err != nil {
		return "", fmt.Errorf("get next operation commitment: %s", err.Error())
	}

	nextCommitment, err := p.OperationParser().GetCommitment(op.OperationRequest)
	if err != nil {
		return "", fmt.Errorf("get commitment from operation parser: %s", err.Error())
	}

	return nextCommitment, nil
}

type noopUnpublishedOpsStore struct{}

func (noop *noopUnpublishedOpsStore) Get(_ string) ([]*operation.AnchoredOperation, error) {
	return nil, fmt.Errorf("not found")
}
