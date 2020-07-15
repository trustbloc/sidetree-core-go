/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package processor

import (
	"encoding/json"
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
	internal "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
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
	Get(uniqueSuffix string) ([]*batch.Operation, error)
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

	rm := &resolutionModel{}

	// split operations info 'full' and 'update' operations
	fullOps, updateOps := splitOperations(ops)
	if len(fullOps) == 0 {
		return nil, errors.New("missing create operation")
	}

	// apply 'full' operations first
	rm, err = s.applyOperations(fullOps, rm)
	if err != nil {
		return nil, err
	}

	if rm.Doc == nil {
		return nil, errors.New("document was deactivated")
	}

	// next apply update ops since last 'full' transaction
	rm, err = s.applyOperations(getOpsWithTxnGreaterThan(updateOps, rm.LastOperationTransactionTime, rm.LastOperationTransactionNumber), rm)
	if err != nil {
		return nil, err
	}

	return &document.ResolutionResult{
		Document: rm.Doc,
		MethodMetadata: document.MethodMetadata{
			RecoveryCommitment: rm.RecoveryCommitment,
			UpdateCommitment:   rm.UpdateCommitment,
		},
	}, nil
}

func splitOperations(ops []*batch.Operation) (fullOps, updateOps []*batch.Operation) {
	for _, op := range ops {
		if op.Type == batch.OperationTypeUpdate {
			updateOps = append(updateOps, op)
		} else { // Create, Recover, deactivate
			fullOps = append(fullOps, op)
		}
	}

	return fullOps, updateOps
}

// pre-condition: operations have to be sorted
func getOpsWithTxnGreaterThan(ops []*batch.Operation, txnTime, txnNumber uint64) []*batch.Operation {
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

func (s *OperationProcessor) applyOperations(ops []*batch.Operation, rm *resolutionModel) (*resolutionModel, error) {
	var err error

	for _, op := range ops {
		if rm, err = s.applyOperation(op, rm); err != nil {
			return nil, err
		}

		logger.Debugf("[%s] After applying op %+v, New doc: %s", s.name, op, rm.Doc)
	}

	return rm, nil
}

type resolutionModel struct {
	Doc                            document.Document
	LastOperationTransactionTime   uint64
	LastOperationTransactionNumber uint64
	UpdateCommitment               string
	RecoveryCommitment             string
}

func (s *OperationProcessor) applyOperation(operation *batch.Operation, rm *resolutionModel) (*resolutionModel, error) {
	switch operation.Type {
	case batch.OperationTypeCreate:
		return s.applyCreateOperation(operation, rm)
	case batch.OperationTypeUpdate:
		return s.applyUpdateOperation(operation, rm)
	case batch.OperationTypeDeactivate:
		return s.applyDeactivateOperation(operation, rm)
	case batch.OperationTypeRecover:
		return s.applyRecoverOperation(operation, rm)
	default:
		return nil, errors.New("operation type not supported for process operation")
	}
}

func (s *OperationProcessor) applyCreateOperation(operation *batch.Operation, rm *resolutionModel) (*resolutionModel, error) {
	logger.Debugf("[%s] Applying create operation: %+v", s.name, operation)

	if rm.Doc != nil {
		return nil, errors.New("create has to be the first operation")
	}

	// verify actual delta hash matches expected delta hash
	err := docutil.IsValidHash(operation.EncodedDelta, operation.SuffixData.DeltaHash)
	if err != nil {
		return nil, fmt.Errorf("create delta doesn't match suffix data delta hash: %s", err.Error())
	}

	doc, err := composer.ApplyPatches(make(document.Document), operation.Delta.Patches)
	if err != nil {
		return nil, err
	}

	return &resolutionModel{
		Doc:                            doc,
		LastOperationTransactionTime:   operation.TransactionTime,
		LastOperationTransactionNumber: operation.TransactionNumber,
		UpdateCommitment:               operation.Delta.UpdateCommitment,
		RecoveryCommitment:             operation.SuffixData.RecoveryCommitment,
	}, nil
}

func (s *OperationProcessor) applyUpdateOperation(operation *batch.Operation, rm *resolutionModel) (*resolutionModel, error) { //nolint:dupl
	logger.Debugf("[%s] Applying update operation: %+v", s.name, operation)

	if rm.Doc == nil {
		return nil, errors.New("update cannot be first operation")
	}

	jwsParts, err := parseSignedData(operation.SignedData)
	if err != nil {
		return nil, err
	}

	var signedDataModel model.UpdateSignedDataModel
	err = json.Unmarshal(jwsParts.Payload, &signedDataModel)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed data model while applying update: %s", err.Error())
	}

	// TODO: protocol should be calculated based on transaction number
	p := s.pc.Current()

	updateCommitment, err := commitment.Calculate(signedDataModel.UpdateKey, p.HashAlgorithmInMultiHashCode)
	if err != nil {
		return nil, err
	}

	// verify that update commitments match
	if updateCommitment != rm.UpdateCommitment {
		return nil, fmt.Errorf("commitment generated from update key doesn't match update commitment: [%s][%s]", updateCommitment, rm.UpdateCommitment)
	}

	// verify the delta against the signed delta hash
	err = docutil.IsValidHash(operation.EncodedDelta, signedDataModel.DeltaHash)
	if err != nil {
		return nil, fmt.Errorf("update delta doesn't match delta hash: %s", err.Error())
	}

	// verify signature
	_, err = internal.VerifyJWS(operation.SignedData, signedDataModel.UpdateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check signature: %s", err.Error())
	}

	doc, err := composer.ApplyPatches(rm.Doc, operation.Delta.Patches)
	if err != nil {
		return nil, err
	}

	return &resolutionModel{
		Doc:                            doc,
		LastOperationTransactionTime:   operation.TransactionTime,
		LastOperationTransactionNumber: operation.TransactionNumber,
		UpdateCommitment:               operation.Delta.UpdateCommitment,
		RecoveryCommitment:             rm.RecoveryCommitment}, nil
}

func parseSignedData(compactJWS string) (*internal.JSONWebSignature, error) {
	if compactJWS == "" {
		return nil, errors.New("missing signed data")
	}

	return internal.ParseJWS(compactJWS)
}

func (s *OperationProcessor) applyDeactivateOperation(operation *batch.Operation, rm *resolutionModel) (*resolutionModel, error) {
	logger.Debugf("[%s] Applying deactivate operation: %+v", s.name, operation)

	if rm.Doc == nil {
		return nil, errors.New("deactivate can only be applied to an existing document")
	}

	jwsParts, err := parseSignedData(operation.SignedData)
	if err != nil {
		return nil, err
	}

	var signedDataModel model.DeactivateSignedDataModel
	err = json.Unmarshal(jwsParts.Payload, &signedDataModel)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed data model while applying deactivate: %s", err.Error())
	}

	// verify signed did suffix against actual did suffix
	if operation.UniqueSuffix != signedDataModel.DidSuffix {
		return nil, errors.New("did suffix doesn't match signed value")
	}

	// TODO: protocol should be calculated based on transaction number
	p := s.pc.Current()

	recoveryCommitment, err := commitment.Calculate(signedDataModel.RecoveryKey, p.HashAlgorithmInMultiHashCode)
	if err != nil {
		return nil, err
	}

	// verify that recovery commitments match
	if recoveryCommitment != rm.RecoveryCommitment {
		return nil, fmt.Errorf("commitment generated from recovery key doesn't match recovery commitment: [%s][%s]", recoveryCommitment, rm.RecoveryCommitment)
	}

	// verify signature
	_, err = internal.VerifyJWS(operation.SignedData, signedDataModel.RecoveryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check signature: %s", err.Error())
	}

	return &resolutionModel{
		Doc:                            nil,
		LastOperationTransactionTime:   operation.TransactionTime,
		LastOperationTransactionNumber: operation.TransactionNumber,
		UpdateCommitment:               "",
		RecoveryCommitment:             ""}, nil
}

func (s *OperationProcessor) applyRecoverOperation(operation *batch.Operation, rm *resolutionModel) (*resolutionModel, error) { //nolint:dupl
	logger.Debugf("[%s] Applying recover operation: %+v", s.name, operation)

	if rm.Doc == nil {
		return nil, errors.New("recover can only be applied to an existing document")
	}

	jwsParts, err := parseSignedData(operation.SignedData)
	if err != nil {
		return nil, err
	}

	var signedDataModel model.RecoverSignedDataModel
	err = json.Unmarshal(jwsParts.Payload, &signedDataModel)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed data model while applying recover: %s", err.Error())
	}

	// TODO: protocol should be calculated based on transaction number
	p := s.pc.Current()

	recoveryCommitment, err := commitment.Calculate(signedDataModel.RecoveryKey, p.HashAlgorithmInMultiHashCode)
	if err != nil {
		return nil, err
	}

	// verify that recovery commitments match
	if recoveryCommitment != rm.RecoveryCommitment {
		return nil, fmt.Errorf("commitment generated from recovery key doesn't match recovery commitment: [%s][%s]", recoveryCommitment, rm.RecoveryCommitment)
	}

	// verify the delta against the signed delta hash
	err = docutil.IsValidHash(operation.EncodedDelta, signedDataModel.DeltaHash)
	if err != nil {
		return nil, fmt.Errorf("recover delta doesn't match delta hash: %s", err.Error())
	}

	// verify signature
	_, err = internal.VerifyJWS(operation.SignedData, signedDataModel.RecoveryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check signature: %s", err.Error())
	}

	doc, err := composer.ApplyPatches(make(document.Document), operation.Delta.Patches)
	if err != nil {
		return nil, err
	}

	return &resolutionModel{
		Doc:                            doc,
		LastOperationTransactionTime:   operation.TransactionTime,
		LastOperationTransactionNumber: operation.TransactionNumber,
		UpdateCommitment:               operation.Delta.UpdateCommitment,
		RecoveryCommitment:             signedDataModel.RecoveryCommitment}, nil
}

func sortOperations(ops []*batch.Operation) {
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].TransactionTime < ops[j].TransactionTime {
			return true
		}

		return ops[i].TransactionNumber < ops[j].TransactionNumber
	})
}
