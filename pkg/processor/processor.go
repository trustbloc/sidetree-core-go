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

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/composer"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"

	internal "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
)

var logger = log.New("sidetree-core-processor")

// OperationProcessor will process document operations in chronological order and create final document during resolution.
// It uses operation store client to retrieve all operations that are related to requested document.
type OperationProcessor struct {
	name  string
	store OperationStoreClient
	pc    protocol.Client
	dc    docComposer
}

// OperationStoreClient defines interface for retrieving all operations related to document
type OperationStoreClient interface {
	// Get retrieves all operations related to document
	Get(uniqueSuffix string) ([]*batch.AnchoredOperation, error)
}

type docComposer interface {
	ApplyPatches(doc document.Document, patches []patch.Patch) (document.Document, error)
}

// New returns new operation processor with the given name. (Note that name is only used for logging.)
func New(name string, store OperationStoreClient, pc protocol.Client) *OperationProcessor {
	return &OperationProcessor{name: name, store: store, pc: pc, dc: composer.New()}
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

	rm := &resolutionModel{}

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
	rm = s.applyOperations(fullOps, rm, getRecoveryCommitment)
	if rm.Doc == nil {
		return nil, errors.New("document was deactivated")
	}

	// next apply update ops since last 'full' transaction
	rm = s.applyOperations(getOpsWithTxnGreaterThan(updateOps, rm.LastOperationTransactionTime, rm.LastOperationTransactionNumber), rm, getUpdateCommitment)

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

func (s *OperationProcessor) applyOperations(ops []*batch.AnchoredOperation, rm *resolutionModel, commitmentFnc fnc) *resolutionModel {
	opMap := s.createOperationHashMap(ops)

	commitmentMap := make(map[string]bool)

	var state = rm

	c := commitmentFnc(state)

	commitmentOps, ok := opMap[c]
	for ok {
		newState := s.applyFirstValidOperation(commitmentOps, state, c, commitmentMap)

		// can't find a valid operation to apply
		if newState == nil {
			break
		}

		// commitment has been processed successfully
		commitmentMap[c] = true
		state = newState

		// get next commitment to be processed
		c = commitmentFnc(state)

		// stop if we just applied deactivate
		if c == "" {
			return state
		}

		commitmentOps, ok = opMap[c]
	}

	return state
}

type fnc func(rm *resolutionModel) string

func getUpdateCommitment(rm *resolutionModel) string {
	return rm.UpdateCommitment
}

func getRecoveryCommitment(rm *resolutionModel) string {
	return rm.RecoveryCommitment
}

func (s *OperationProcessor) applyFirstValidCreateOperation(createOps []*batch.AnchoredOperation, rm *resolutionModel) *resolutionModel {
	for _, op := range createOps {
		var state *resolutionModel
		var err error

		if state, err = s.applyOperation(op, rm); err != nil {
			logger.Infof("[%s] Skipped bad operation {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", s.name, op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber, err)
			continue
		}

		logger.Debugf("[%s] After applying op %+v, New doc: %s", s.name, op, rm.Doc)
		return state
	}

	return nil
}

// this function should be used for update, recover and deactivate operations (create is handled differently)
func (s *OperationProcessor) applyFirstValidOperation(ops []*batch.AnchoredOperation, rm *resolutionModel, currCommitment string, processedCommitments map[string]bool) *resolutionModel {
	for _, op := range ops {
		var state *resolutionModel
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

		logger.Debugf("[%s] After applying op %+v, New doc: %s", s.name, op, rm.Doc)
		return state
	}

	return nil
}

type resolutionModel struct {
	Doc                            document.Document
	LastOperationTransactionTime   uint64
	LastOperationTransactionNumber uint64
	UpdateCommitment               string
	RecoveryCommitment             string
}

func (s *OperationProcessor) applyOperation(operation *batch.AnchoredOperation, rm *resolutionModel) (*resolutionModel, error) {
	p, err := s.pc.Get(operation.TransactionTime)
	if err != nil {
		return nil, fmt.Errorf("apply '%s' operation: %s", operation.Type, err.Error())
	}

	switch operation.Type {
	case batch.OperationTypeCreate:
		return s.applyCreateOperation(operation, p, rm)
	case batch.OperationTypeUpdate:
		return s.applyUpdateOperation(operation, p, rm)
	case batch.OperationTypeDeactivate:
		return s.applyDeactivateOperation(operation, p, rm)
	case batch.OperationTypeRecover:
		return s.applyRecoverOperation(operation, p, rm)
	default:
		return nil, errors.New("operation type not supported for process operation")
	}
}

func (s *OperationProcessor) applyCreateOperation(op *batch.AnchoredOperation, p protocol.Protocol, rm *resolutionModel) (*resolutionModel, error) {
	logger.Debugf("[%s] Applying create operation: %+v", s.name, op)

	if rm.Doc != nil {
		return nil, errors.New("create has to be the first operation")
	}

	suffixData, err := operation.ParseSuffixData(op.SuffixData, p)
	if err != nil {
		return nil, fmt.Errorf("failed to parse suffix data: %s", err.Error())
	}

	// verify actual delta hash matches expected delta hash
	err = docutil.IsValidHash(op.Delta, suffixData.DeltaHash)
	if err != nil {
		return nil, fmt.Errorf("create delta doesn't match suffix data delta hash: %s", err.Error())
	}

	delta, err := operation.ParseDelta(op.Delta, p)
	if err != nil {
		return nil, fmt.Errorf("failed to parse delta: %s", err.Error())
	}

	doc, err := s.dc.ApplyPatches(make(document.Document), delta.Patches)
	if err != nil {
		return nil, err
	}

	return &resolutionModel{
		Doc:                            doc,
		LastOperationTransactionTime:   op.TransactionTime,
		LastOperationTransactionNumber: op.TransactionNumber,
		UpdateCommitment:               delta.UpdateCommitment,
		RecoveryCommitment:             suffixData.RecoveryCommitment,
	}, nil
}

func (s *OperationProcessor) applyUpdateOperation(op *batch.AnchoredOperation, p protocol.Protocol, rm *resolutionModel) (*resolutionModel, error) { //nolint:dupl
	logger.Debugf("[%s] Applying update operation: %+v", s.name, op)

	if rm.Doc == nil {
		return nil, errors.New("update cannot be first operation")
	}

	signedDataModel, err := operation.ParseSignedDataForUpdate(op.SignedData, p)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed data model while applying update: %s", err.Error())
	}

	updateCommitment, err := commitment.Calculate(signedDataModel.UpdateKey, p.HashAlgorithmInMultiHashCode)
	if err != nil {
		return nil, err
	}

	// verify that update commitments match
	if updateCommitment != rm.UpdateCommitment {
		return nil, fmt.Errorf("commitment generated from update key doesn't match update commitment: [%s][%s]", updateCommitment, rm.UpdateCommitment)
	}

	// verify the delta against the signed delta hash
	err = docutil.IsValidHash(op.Delta, signedDataModel.DeltaHash)
	if err != nil {
		return nil, fmt.Errorf("update delta doesn't match delta hash: %s", err.Error())
	}

	// verify signature
	_, err = internal.VerifyJWS(op.SignedData, signedDataModel.UpdateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check signature: %s", err.Error())
	}

	delta, err := operation.ParseDelta(op.Delta, p)
	if err != nil {
		return nil, fmt.Errorf("failed to parse delta: %s", err.Error())
	}

	doc, err := s.dc.ApplyPatches(rm.Doc, delta.Patches)
	if err != nil {
		return nil, err
	}

	return &resolutionModel{
		Doc:                            doc,
		LastOperationTransactionTime:   op.TransactionTime,
		LastOperationTransactionNumber: op.TransactionNumber,
		UpdateCommitment:               delta.UpdateCommitment,
		RecoveryCommitment:             rm.RecoveryCommitment}, nil
}

func (s *OperationProcessor) applyDeactivateOperation(op *batch.AnchoredOperation, p protocol.Protocol, rm *resolutionModel) (*resolutionModel, error) {
	logger.Debugf("[%s] Applying deactivate operation: %+v", s.name, op)

	if rm.Doc == nil {
		return nil, errors.New("deactivate can only be applied to an existing document")
	}

	signedDataModel, err := operation.ParseSignedDataForDeactivate(op.SignedData, p)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed data model while applying deactivate: %s", err.Error())
	}

	// verify signed did suffix against actual did suffix
	if op.UniqueSuffix != signedDataModel.DidSuffix {
		return nil, errors.New("did suffix doesn't match signed value")
	}

	recoveryCommitment, err := commitment.Calculate(signedDataModel.RecoveryKey, p.HashAlgorithmInMultiHashCode)
	if err != nil {
		return nil, err
	}

	// verify that recovery commitments match
	if recoveryCommitment != rm.RecoveryCommitment {
		return nil, fmt.Errorf("commitment generated from recovery key doesn't match recovery commitment: [%s][%s]", recoveryCommitment, rm.RecoveryCommitment)
	}

	// verify signature
	_, err = internal.VerifyJWS(op.SignedData, signedDataModel.RecoveryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check signature: %s", err.Error())
	}

	return &resolutionModel{
		Doc:                            nil,
		LastOperationTransactionTime:   op.TransactionTime,
		LastOperationTransactionNumber: op.TransactionNumber,
		UpdateCommitment:               "",
		RecoveryCommitment:             ""}, nil
}

func (s *OperationProcessor) applyRecoverOperation(op *batch.AnchoredOperation, p protocol.Protocol, rm *resolutionModel) (*resolutionModel, error) { //nolint:dupl
	logger.Debugf("[%s] Applying recover operation: %+v", s.name, op)

	if rm.Doc == nil {
		return nil, errors.New("recover can only be applied to an existing document")
	}

	signedDataModel, err := operation.ParseSignedDataForRecover(op.SignedData, p)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed data model while applying recover: %s", err.Error())
	}

	recoveryCommitment, err := commitment.Calculate(signedDataModel.RecoveryKey, p.HashAlgorithmInMultiHashCode)
	if err != nil {
		return nil, err
	}

	// verify that recovery commitments match
	if recoveryCommitment != rm.RecoveryCommitment {
		return nil, fmt.Errorf("commitment generated from recovery key doesn't match recovery commitment: [%s][%s]", recoveryCommitment, rm.RecoveryCommitment)
	}

	// verify the delta against the signed delta hash
	err = docutil.IsValidHash(op.Delta, signedDataModel.DeltaHash)
	if err != nil {
		return nil, fmt.Errorf("recover delta doesn't match delta hash: %s", err.Error())
	}

	// verify signature
	_, err = internal.VerifyJWS(op.SignedData, signedDataModel.RecoveryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check signature: %s", err.Error())
	}

	delta, err := operation.ParseDelta(op.Delta, p)
	if err != nil {
		return nil, fmt.Errorf("failed to parse delta: %s", err.Error())
	}

	doc, err := s.dc.ApplyPatches(make(document.Document), delta.Patches)
	if err != nil {
		return nil, err
	}

	return &resolutionModel{
		Doc:                            doc,
		LastOperationTransactionTime:   op.TransactionTime,
		LastOperationTransactionNumber: op.TransactionNumber,
		UpdateCommitment:               delta.UpdateCommitment,
		RecoveryCommitment:             signedDataModel.RecoveryCommitment}, nil
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

	p, err := s.pc.Get(op.TransactionTime)
	if err != nil {
		return "", fmt.Errorf("get operation commitment: %s", err.Error())
	}

	var commitmentKey *jws.JWK

	switch op.Type {
	case batch.OperationTypeUpdate:
		signedDataModel, innerErr := operation.ParseSignedDataForUpdate(op.SignedData, p)
		if innerErr != nil {
			return "", fmt.Errorf("failed to parse signed data model for update: %s", innerErr.Error())
		}

		commitmentKey = signedDataModel.UpdateKey

	case batch.OperationTypeDeactivate:
		signedDataModel, innerErr := operation.ParseSignedDataForDeactivate(op.SignedData, p)
		if innerErr != nil {
			return "", fmt.Errorf("failed to parse signed data model for deactivate: %s", innerErr.Error())
		}

		commitmentKey = signedDataModel.RecoveryKey

	case batch.OperationTypeRecover:
		signedDataModel, innerErr := operation.ParseSignedDataForRecover(op.SignedData, p)
		if innerErr != nil {
			return "", fmt.Errorf("failed to parse signed data model for recover: %s", innerErr.Error())
		}

		commitmentKey = signedDataModel.RecoveryKey

	default:
		return "", errors.New("operation type not supported for getting operation commitment")
	}

	currentCommitment, err := commitment.Calculate(commitmentKey, p.HashAlgorithmInMultiHashCode)
	if err != nil {
		return "", fmt.Errorf("failed to calculate operation commitment for key: %s", err.Error())
	}

	return currentCommitment, nil
}

func (s *OperationProcessor) getNextOperationCommitment(op *batch.AnchoredOperation) (string, error) { // nolint: gocyclo
	p, err := s.pc.Get(op.TransactionTime)
	if err != nil {
		return "", fmt.Errorf("get next operation commitment: %s", err.Error())
	}

	var nextCommitment string

	switch op.Type {
	case batch.OperationTypeUpdate:
		delta, innerErr := operation.ParseDelta(op.Delta, p)
		if innerErr != nil {
			return "", fmt.Errorf("failed to parse delta for %s: %s", op.Type, innerErr.Error())
		}

		nextCommitment = delta.UpdateCommitment

	case batch.OperationTypeDeactivate:
		nextCommitment = ""

	case batch.OperationTypeRecover:
		signedDataModel, innerErr := operation.ParseSignedDataForRecover(op.SignedData, p)
		if innerErr != nil {
			return "", fmt.Errorf("failed to parse signed data model for recover: %s", innerErr.Error())
		}

		nextCommitment = signedDataModel.RecoveryCommitment

	default:
		return "", errors.New("operation type not supported for getting next operation commitment")
	}

	return nextCommitment, nil
}
