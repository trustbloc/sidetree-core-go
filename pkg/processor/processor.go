/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package processor

import (
	"errors"
	"fmt"
	"sort"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
)

var logger = log.New("sidetree-core-processor")

// OperationProcessor will process document operations in chronological order and create final document during resolution.
// It uses operation store client to retrieve all operations that are related to requested document.
type OperationProcessor struct {
	name  string
	store OperationStoreClient
	pc    protocol.Client
}

// OperationStoreClient defines interface for retrieving all operations related to document.
type OperationStoreClient interface {
	// Get retrieves all operations related to document
	Get(uniqueSuffix string) ([]*operation.AnchoredOperation, error)
}

// New returns new operation processor with the given name. (Note that name is only used for logging.)
func New(name string, store OperationStoreClient, pc protocol.Client) *OperationProcessor {
	return &OperationProcessor{name: name, store: store, pc: pc}
}

// Resolve document based on the given unique suffix.
// Parameters:
// uniqueSuffix - unique portion of ID to resolve. for example "abc123" in "did:sidetree:abc123".
func (s *OperationProcessor) Resolve(uniqueSuffix string) (*protocol.ResolutionModel, error) {
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

	return rm, nil
}

func (s *OperationProcessor) createOperationHashMap(ops []*operation.AnchoredOperation) map[string][]*operation.AnchoredOperation {
	opMap := make(map[string][]*operation.AnchoredOperation)

	for _, op := range ops {
		rv, err := s.getRevealValue(op)
		if err != nil {
			logger.Infof("[%s] Skipped bad operation while creating operation hash map {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", s.name, op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber, err)

			continue
		}

		c, err := commitment.GetCommitmentFromRevealValue(rv)
		if err != nil {
			logger.Infof("[%s] Skipped calculating commitment while creating operation hash map {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", s.name, op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber, err)

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

// pre-condition: operations have to be sorted.
func getOpsWithTxnGreaterThan(ops []*operation.AnchoredOperation, txnTime, txnNumber uint64) []*operation.AnchoredOperation {
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

func (s *OperationProcessor) applyOperations(ops []*operation.AnchoredOperation, rm *protocol.ResolutionModel, commitmentFnc fnc) *protocol.ResolutionModel {
	// suffix for logging
	uniqueSuffix := ops[0].UniqueSuffix

	state := rm

	opMap := s.createOperationHashMap(ops)

	// holds applied commitments
	commitmentMap := make(map[string]bool)

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

func (s *OperationProcessor) applyFirstValidCreateOperation(createOps []*operation.AnchoredOperation, rm *protocol.ResolutionModel) *protocol.ResolutionModel {
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

// this function should be used for update, recover and deactivate operations (create is handled differently).
func (s *OperationProcessor) applyFirstValidOperation(ops []*operation.AnchoredOperation, rm *protocol.ResolutionModel, currCommitment string, processedCommitments map[string]bool) *protocol.ResolutionModel {
	for _, op := range ops {
		var state *protocol.ResolutionModel
		var err error

		nextCommitment, err := s.getCommitment(op)
		if err != nil {
			logger.Infof("[%s] Skipped bad operation {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", s.name, op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber, err)

			continue
		}

		if currCommitment == nextCommitment {
			logger.Infof("[%s] Skipped bad operation {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: operation commitment(key) equals next operation commitment(key)", s.name, op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber)

			continue
		}

		if nextCommitment != "" {
			// for recovery and update operations check if next commitment has been used already; if so skip to next operation
			_, processed := processedCommitments[nextCommitment]
			if processed {
				logger.Infof("[%s] Skipped bad operation {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: next operation commitment(key) has already been used", s.name, op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber)

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

func (s *OperationProcessor) applyOperation(op *operation.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) {
	p, err := s.pc.Get(op.ProtocolGenesisTime)
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

	p, err := s.pc.Get(op.ProtocolGenesisTime)
	if err != nil {
		return "", fmt.Errorf("get operation reveal value - retrieve protocol: %s", err.Error())
	}

	rv, err := p.OperationParser().GetRevealValue(op.OperationBuffer)
	if err != nil {
		return "", fmt.Errorf("get operation reveal value from operation parser: %s", err.Error())
	}

	return rv, nil
}

func (s *OperationProcessor) getCommitment(op *operation.AnchoredOperation) (string, error) {
	p, err := s.pc.Get(op.ProtocolGenesisTime)
	if err != nil {
		return "", fmt.Errorf("get next operation commitment: %s", err.Error())
	}

	nextCommitment, err := p.OperationParser().GetCommitment(op.OperationBuffer)
	if err != nil {
		return "", fmt.Errorf("get commitment from operation parser: %s", err.Error())
	}

	return nextCommitment, nil
}
