/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationapplier

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	internal "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
)

var logger = log.New("sidetree-core-applier")

// Applier is an operation applier.
type Applier struct {
	protocol.Protocol
	protocol.OperationParser
	protocol.DocumentComposer
}

// New returns a new operation applier for the given protocol.
func New(p protocol.Protocol, parser protocol.OperationParser, dc protocol.DocumentComposer) *Applier {
	return &Applier{
		Protocol:         p,
		OperationParser:  parser,
		DocumentComposer: dc,
	}
}

// Apply applies the given anchored operation.
func (s *Applier) Apply(operation *batch.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) {
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
		return nil, fmt.Errorf("operation type not supported for process operation")
	}
}

func (s *Applier) applyCreateOperation(op *batch.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) {
	logger.Debugf("Applying create operation: %+v", op)

	if rm.Doc != nil {
		return nil, errors.New("create has to be the first operation")
	}

	suffixData, err := s.ParseSuffixData(op.SuffixData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse suffix data: %s", err.Error())
	}

	// from this point any error should advance recovery commitment
	result := &protocol.ResolutionModel{
		Doc:                              make(document.Document),
		LastOperationTransactionTime:     op.TransactionTime,
		LastOperationTransactionNumber:   op.TransactionNumber,
		LastOperationProtocolGenesisTime: op.ProtocolGenesisTime,
		RecoveryCommitment:               suffixData.RecoveryCommitment,
	}

	// verify actual delta hash matches expected delta hash
	err = docutil.IsValidHash(op.Delta, suffixData.DeltaHash)
	if err != nil {
		logger.Infof("Delta doesn't match delta hash; set update commitment to nil and advance recovery commitment {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber, err)

		return result, nil
	}

	delta, err := s.ParseDelta(op.Delta)
	if err != nil {
		logger.Infof("Parse delta failed; set update commitment to nil and advance recovery commitment {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber, err)

		return result, nil
	}

	result.UpdateCommitment = delta.UpdateCommitment

	doc, err := s.ApplyPatches(make(document.Document), delta.Patches)
	if err != nil {
		logger.Infof("Apply patches failed; advance commitments {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber, err)

		return result, nil
	}

	result.Doc = doc

	return result, nil
}

func (s *Applier) applyUpdateOperation(op *batch.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) { //nolint:dupl
	logger.Debugf("Applying update operation: %+v", op)

	if rm.Doc == nil {
		return nil, errors.New("update cannot be first operation")
	}

	signedDataModel, err := s.ParseSignedDataForUpdate(op.SignedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed data model while applying update: %s", err.Error())
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

	delta, err := s.ParseDelta(op.Delta)
	if err != nil {
		return nil, fmt.Errorf("failed to parse delta: %s", err.Error())
	}

	doc, err := s.ApplyPatches(rm.Doc, delta.Patches)
	if err != nil {
		return nil, err
	}

	return &protocol.ResolutionModel{
		Doc:                              doc,
		LastOperationTransactionTime:     op.TransactionTime,
		LastOperationTransactionNumber:   op.TransactionNumber,
		LastOperationProtocolGenesisTime: op.ProtocolGenesisTime,
		UpdateCommitment:                 delta.UpdateCommitment,
		RecoveryCommitment:               rm.RecoveryCommitment,
	}, nil
}

func (s *Applier) applyDeactivateOperation(op *batch.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) {
	logger.Debugf("[%s] Applying deactivate operation: %+v", op)

	if rm.Doc == nil {
		return nil, errors.New("deactivate can only be applied to an existing document")
	}

	signedDataModel, err := s.ParseSignedDataForDeactivate(op.SignedData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed data model while applying deactivate: %s", err.Error())
	}

	// verify signed did suffix against actual did suffix
	if op.UniqueSuffix != signedDataModel.DidSuffix {
		return nil, errors.New("did suffix doesn't match signed value")
	}

	// verify signature
	_, err = internal.VerifyJWS(op.SignedData, signedDataModel.RecoveryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check signature: %s", err.Error())
	}

	return &protocol.ResolutionModel{
		Doc:                              nil,
		LastOperationTransactionTime:     op.TransactionTime,
		LastOperationTransactionNumber:   op.TransactionNumber,
		LastOperationProtocolGenesisTime: op.ProtocolGenesisTime,
		UpdateCommitment:                 "",
		RecoveryCommitment:               "",
	}, nil
}

func (s *Applier) applyRecoverOperation(op *batch.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) { //nolint:dupl
	logger.Debugf("Applying recover operation: %+v", op)

	if rm.Doc == nil {
		return nil, errors.New("recover can only be applied to an existing document")
	}

	signedDataModel, err := s.ParseSignedDataForRecover(op.SignedData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed data model while applying recover: %s", err.Error())
	}

	// verify signature
	_, err = internal.VerifyJWS(op.SignedData, signedDataModel.RecoveryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check signature: %s", err.Error())
	}

	// from this point any error should advance recovery commitment
	result := &protocol.ResolutionModel{
		Doc:                              make(document.Document),
		LastOperationTransactionTime:     op.TransactionTime,
		LastOperationTransactionNumber:   op.TransactionNumber,
		LastOperationProtocolGenesisTime: op.ProtocolGenesisTime,
		RecoveryCommitment:               signedDataModel.RecoveryCommitment,
	}

	// verify the delta against the signed delta hash
	err = docutil.IsValidHash(op.Delta, signedDataModel.DeltaHash)
	if err != nil {
		logger.Infof("Recover delta doesn't match delta hash; set update commitment to nil and advance recovery commitment {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber, err)

		return result, nil
	}

	delta, err := s.ParseDelta(op.Delta)
	if err != nil {
		logger.Infof("Parse delta failed; set update commitment to nil and advance recovery commitment {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber, err)

		return result, nil
	}

	result.UpdateCommitment = delta.UpdateCommitment

	doc, err := s.ApplyPatches(make(document.Document), delta.Patches)
	if err != nil {
		logger.Infof("Apply patches failed; advance commitments {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", op.UniqueSuffix, op.Type, op.TransactionTime, op.TransactionNumber, err)

		return result, nil
	}

	result.Doc = doc

	return result, nil
}
