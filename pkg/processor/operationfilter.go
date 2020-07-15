/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package processor

import (
	"strings"

	"github.com/pkg/errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
)

// OperationValidationFilter filters out invalid operations.
type OperationValidationFilter struct {
	*OperationProcessor
}

// NewOperationFilter returns new operation filter with the given name. (Note that name is only used for logging.)
func NewOperationFilter(name string, store OperationStoreClient, pc protocol.Client) *OperationValidationFilter {
	return &OperationValidationFilter{
		OperationProcessor: New(name, store, pc),
	}
}

// Filter filters out the invalid operations and returns only the valid ones
func (s *OperationValidationFilter) Filter(uniqueSuffix string, newOps []*batch.Operation) ([]*batch.Operation, error) {
	logger.Debugf("[%s] Validating operations for unique suffix [%s]...", s.name, uniqueSuffix)

	newOps = s.filterInvalidSuffix(uniqueSuffix, newOps)

	ops, err := s.store.Get(uniqueSuffix)
	if err != nil {
		if !strings.Contains(err.Error(), "not found") {
			return nil, err
		}

		logger.Debugf("[%s] Unique suffix not found in the store [%s]", s.name, uniqueSuffix)
	}

	// Combine the existing (persistet) operations with the new operations
	ops = append(ops, newOps...)

	// Sort the operations by transaction time/number
	sortOperations(ops)

	logger.Debugf("[%s] Found %d operations for unique suffix [%s]: %+v", s.name, len(ops), uniqueSuffix, ops)

	// split operations info 'full' and 'update' operations
	createOps, updateOps, fullOps := splitOperations(ops)
	if len(createOps) == 0 {
		return nil, errors.New("missing create operation")
	}

	// apply 'full' operations first
	validFullOps, rm := s.getValidOperations(append(createOps, fullOps...), &resolutionModel{})

	var validUpdateOps []*batch.Operation
	if rm.Doc == nil {
		logger.Debugf("[%s] Document was deactivated [%s]", s.name, uniqueSuffix)
	} else {
		// next apply update ops since last 'full' transaction
		validUpdateOps, _ = s.getValidOperations(getOpsWithTxnGreaterThan(updateOps, rm.LastOperationTransactionTime, rm.LastOperationTransactionNumber), rm)
	}

	var validNewOps []*batch.Operation
	for _, op := range append(validFullOps, validUpdateOps...) {
		if contains(newOps, op) {
			validNewOps = append(validNewOps, op)
		}
	}

	return validNewOps, nil
}

func (s *OperationValidationFilter) getValidOperations(ops []*batch.Operation, rm *resolutionModel) ([]*batch.Operation, *resolutionModel) {
	var validOps []*batch.Operation
	for _, op := range ops {
		m, err := s.applyOperation(op, rm)
		if err != nil {
			logger.Infof("[%s] Rejecting invalid operation {ID: %s, UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", s.name, op.ID, op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber, err)
			continue
		}

		validOps = append(validOps, op)
		rm = m

		logger.Debugf("[%s] After applying op %+v, New doc: %s", s.name, op, rm.Doc)
	}

	return validOps, rm
}

func (s *OperationValidationFilter) filterInvalidSuffix(uniqueSuffix string, ops []*batch.Operation) []*batch.Operation {
	var filtered []*batch.Operation
	for _, op := range ops {
		if op.UniqueSuffix != uniqueSuffix {
			logger.Infof("[%s] Rejecting invalid operation {ID: %s, UniqueSuffix: %s Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: operation's unique suffix is not set to [%s]", s.name, op.ID, op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber, uniqueSuffix)
			continue
		}

		filtered = append(filtered, op)
	}

	return filtered
}

func contains(ops []*batch.Operation, op *batch.Operation) bool {
	for _, o := range ops {
		if o == op {
			return true
		}
	}

	return false
}
