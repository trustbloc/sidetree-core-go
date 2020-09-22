/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package processor

import (
	"crypto"
	"errors"
	"fmt"
	"sort"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

var logger = log.New("sidetree-core-processor")

// OperationProcessor will process document operations in chronological order and create final document during resolution.
// It uses operation store client to retrieve all operations that are related to requested document.
type OperationProcessor struct {
	name  string
	store OperationStoreClient
	pc    protocol.Client
}

// OperationStoreClient defines interface for retrieving all operations related to document
type OperationStoreClient interface {
	// Get retrieves all operations related to document
	Get(uniqueSuffix string) ([]*batch.AnchoredOperation, error)
}

// New returns new operation processor with the given name. (Note that name is only used for logging.)
func New(name string, store OperationStoreClient, pc protocol.Client) *OperationProcessor {
	return &OperationProcessor{name: name, store: store, pc: pc}
}

// Resolve document based on the given unique suffix
// Parameters:
// uniqueSuffix - unique portion of ID to resolve. for example "abc123" in "did:sidetree:abc123"
func (s *OperationProcessor) Resolve(uniqueSuffix string) (*document.ResolutionResult, error) {
	ops, err := s.store.Get(uniqueSuffix)
	if err != nil {
		return nil, err
	}

	sortOperations(ops)

	logger.Debugf("[%s] Found %d operations for unique suffix [%s]: %+v", s.name, len(ops), uniqueSuffix, ops)

	rm := &protocol.ResolutionModel{}

	// split operations into 'create', 'update' and 'full' operations
	createOps, updateOps, fullOps := splitOperations(ops)
	if len(createOps) == 0 {
		return nil, errors.New("missing create operation")
	}

	// apply 'create' operations first
	rm = s.applyFirstValidCreateOperation(createOps, rm)
	if rm == nil {
		return nil, errors.New("valid create operation not found")
	}

	// apply 'full' operations first
	if len(fullOps) > 0 {
		logger.Debugf("[%s] Applying %d full operations for unique suffix [%s]", s.name, len(fullOps), uniqueSuffix)

		rm = s.applyOperations(fullOps, rm, getRecoveryCommitment)
		if rm.Doc == nil {
			return nil, errors.New("document was deactivated")
		}
	}

	// next apply update ops since last 'full' transaction
	filteredUpdateOps := getOpsWithTxnGreaterThan(updateOps, rm.LastOperationTransactionTime, rm.LastOperationTransactionNumber)
	if len(filteredUpdateOps) > 0 {
		logger.Debugf("[%s] Applying %d update operations after last full operation for unique suffix [%s]", s.name, len(filteredUpdateOps), uniqueSuffix)
		rm = s.applyOperations(filteredUpdateOps, rm, getUpdateCommitment)
	}

	return &document.ResolutionResult{
		Document: rm.Doc,
		MethodMetadata: document.MethodMetadata{
			RecoveryCommitment: rm.RecoveryCommitment,
			UpdateCommitment:   rm.UpdateCommitment,
		},
	}, nil
}

func (s *OperationProcessor) createOperationHashMap(ops []*batch.AnchoredOperation) map[string][]*batch.AnchoredOperation {
	opMap := make(map[string][]*batch.AnchoredOperation)

	for _, op := range ops {
		commitmentValue, err := s.getOperationCommitment(op)
		if err != nil {
			logger.Infof("[%s] Skipped bad operation while creating operation hash map {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", s.name, op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber, err)
		}

		opMap[commitmentValue] = append(opMap[commitmentValue], op)
	}

	return opMap
}

func splitOperations(ops []*batch.AnchoredOperation) (createOps, updateOps, fullOps []*batch.AnchoredOperation) {
	for _, op := range ops {
		switch op.Type {
		case batch.OperationTypeCreate:
			createOps = append(createOps, op)
		case batch.OperationTypeUpdate:
			updateOps = append(updateOps, op)
		case batch.OperationTypeRecover:
			fullOps = append(fullOps, op)
		case batch.OperationTypeDeactivate:
			fullOps = append(fullOps, op)
		}
	}

	return createOps, updateOps, fullOps
}

// pre-condition: operations have to be sorted
func getOpsWithTxnGreaterThan(ops []*batch.AnchoredOperation, txnTime, txnNumber uint64) []*batch.AnchoredOperation {
	for index, op := range ops {
		if op.TransactionTime < txnTime {
			continue
		}

		if op.TransactionTime > txnTime {
			return ops[index:]
		}

		if op.TransactionNumber > txnNumber {
			return ops[index:]
		}
	}

	return nil
}
func (s *OperationProcessor) applyOperations(ops []*batch.AnchoredOperation, rm *protocol.ResolutionModel, commitmentFnc fnc) *protocol.ResolutionModel {
	if len(ops) == 0 {
		// nothing to do; shouldn't be called without operations
		return rm
	}

	// suffix for logging
	uniqueSuffix := ops[0].UniqueSuffix

	opMap := s.createOperationHashMap(ops)

	// holds applied commitments
	commitmentMap := make(map[string]bool)

	var state = rm

	c := commitmentFnc(state)
	logger.Debugf("[%s] Processing commitment '%s' {UniqueSuffix: %s}", s.name, c, uniqueSuffix)

	commitmentOps, ok := opMap[c]
	for ok {
		logger.Debugf("[%s] Found %d operation(s) for commitment '%s' {UniqueSuffix: %s}", s.name, len(commitmentOps), c, uniqueSuffix)

		newState := s.applyFirstValidOperation(commitmentOps, state, c, commitmentMap)

		// can't find a valid operation to apply
		if newState == nil {
			logger.Infof("[%s] Unable to apply valid operation for commitment '%s' {UniqueSuffix: %s}", s.name, c, uniqueSuffix)
			break
		}

		// commitment has been processed successfully
		commitmentMap[c] = true
		state = newState

		logger.Debugf("[%s] Successfully processed commitment '%s' {UniqueSuffix: %s}", s.name, c, uniqueSuffix)

		// get next commitment to be processed
		c = commitmentFnc(state)

		logger.Debugf("[%s] Next commitment to process is '%s' {UniqueSuffix: %s}", s.name, c, uniqueSuffix)

		// stop if there is no next commitment
		if c == "" {
			return state
		}

		commitmentOps, ok = opMap[c]
	}

	if len(commitmentMap) != len(ops) {
		logger.Infof("[%s] Number of commitments applied '%d' doesn't match number of operations '%d' {UniqueSuffix: %s}", s.name, len(commitmentMap), len(ops), uniqueSuffix)
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

func (s *OperationProcessor) applyFirstValidCreateOperation(createOps []*batch.AnchoredOperation, rm *protocol.ResolutionModel) *protocol.ResolutionModel {
	for _, op := range createOps {
		var state *protocol.ResolutionModel
		var err error

		if state, err = s.applyOperation(op, rm); err != nil {
			logger.Infof("[%s] Skipped bad operation {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", s.name, op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber, err)
			continue
		}

		logger.Debugf("[%s] After applying create op %+v, recover commitment[%s], update commitment[%s], New doc: %s", s.name, op, state.RecoveryCommitment, state.UpdateCommitment, state.Doc)
		return state
	}

	return nil
}

// this function should be used for update, recover and deactivate operations (create is handled differently)
func (s *OperationProcessor) applyFirstValidOperation(ops []*batch.AnchoredOperation, rm *protocol.ResolutionModel, currCommitment string, processedCommitments map[string]bool) *protocol.ResolutionModel {
	for _, op := range ops {
		var state *protocol.ResolutionModel
		var err error

		nextCommitment, err := s.getNextOperationCommitment(op)
		if err != nil {
			logger.Infof("[%s] Skipped bad operation {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", s.name, op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber, err)
			continue
		}

		if currCommitment == nextCommitment {
			logger.Infof("[%s] Skipped bad operation {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: operation commitment equals next operation commitment", s.name, op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber)
			continue
		}

		if nextCommitment != "" {
			// for recovery and update operations check if next commitment has been used already; if so skip to next operation
			_, processed := processedCommitments[nextCommitment]
			if processed {
				logger.Infof("[%s] Skipped bad operation {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: next operation commitment has already been used", s.name, op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber)
				continue
			}
		}

		if state, err = s.applyOperation(op, rm); err != nil {
			logger.Infof("[%s] Skipped bad operation {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", s.name, op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber, err)
			continue
		}

		logger.Debugf("[%s] After applying op %+v, recover commitment[%s], update commitment[%s], New doc: %s", s.name, op, state.RecoveryCommitment, state.UpdateCommitment, state.Doc)
		return state
	}

	return nil
}

func (s *OperationProcessor) applyOperation(operation *batch.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) {
	p, err := s.pc.Get(operation.ProtocolGenesisTime)
	if err != nil {
		return nil, fmt.Errorf("apply '%s' operation: %s", operation.Type, err.Error())
	}

	return p.OperationApplier().Apply(operation, rm)
}

func sortOperations(ops []*batch.AnchoredOperation) {
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].TransactionTime < ops[j].TransactionTime {
			return true
		}

		return ops[i].TransactionNumber < ops[j].TransactionNumber
	})
}

func (s *OperationProcessor) getOperationCommitment(op *batch.AnchoredOperation) (string, error) { // nolint: gocyclo
	if op.Type == batch.OperationTypeCreate {
		return "", errors.New("create operation doesn't have reveal value")
	}

	p, err := s.pc.Get(op.ProtocolGenesisTime)
	if err != nil {
		return "", fmt.Errorf("get operation commitment: %s", err.Error())
	}

	var commitmentKey *jws.JWK

	switch op.Type {
	case batch.OperationTypeUpdate:
		signedDataModel, innerErr := p.OperationParser().ParseSignedDataForUpdate(op.SignedData)
		if innerErr != nil {
			return "", fmt.Errorf("failed to parse signed data model for update: %s", innerErr.Error())
		}

		commitmentKey = signedDataModel.UpdateKey

	case batch.OperationTypeDeactivate:
		signedDataModel, innerErr := p.OperationParser().ParseSignedDataForDeactivate(op.SignedData)
		if innerErr != nil {
			return "", fmt.Errorf("failed to parse signed data model for deactivate: %s", innerErr.Error())
		}

		commitmentKey = signedDataModel.RecoveryKey

	case batch.OperationTypeRecover:
		signedDataModel, innerErr := p.OperationParser().ParseSignedDataForRecover(op.SignedData)
		if innerErr != nil {
			return "", fmt.Errorf("failed to parse signed data model for recover: %s", innerErr.Error())
		}

		commitmentKey = signedDataModel.RecoveryKey

	default:
		return "", errors.New("operation type not supported for getting operation commitment")
	}

	currentCommitment, err := commitment.Calculate(commitmentKey, p.Protocol().HashAlgorithmInMultiHashCode, crypto.Hash(p.Protocol().HashAlgorithm))
	if err != nil {
		return "", fmt.Errorf("failed to calculate operation commitment for key: %s", err.Error())
	}

	return currentCommitment, nil
}

func (s *OperationProcessor) getNextOperationCommitment(op *batch.AnchoredOperation) (string, error) { // nolint: gocyclo
	p, err := s.pc.Get(op.ProtocolGenesisTime)
	if err != nil {
		return "", fmt.Errorf("get next operation commitment: %s", err.Error())
	}

	var nextCommitment string

	switch op.Type {
	case batch.OperationTypeUpdate:
		delta, innerErr := p.OperationParser().ParseDelta(op.Delta)
		if innerErr != nil {
			return "", fmt.Errorf("failed to parse delta for %s: %s", op.Type, innerErr.Error())
		}

		nextCommitment = delta.UpdateCommitment

	case batch.OperationTypeDeactivate:
		nextCommitment = ""

	case batch.OperationTypeRecover:
		signedDataModel, innerErr := p.OperationParser().ParseSignedDataForRecover(op.SignedData)
		if innerErr != nil {
			return "", fmt.Errorf("failed to parse signed data model for recover: %s", innerErr.Error())
		}

		nextCommitment = signedDataModel.RecoveryCommitment

	default:
		return "", errors.New("operation type not supported for getting next operation commitment")
	}

	return nextCommitment, nil
}
