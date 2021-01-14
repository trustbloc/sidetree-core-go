/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationapplier

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	internal "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
)

//go:generate counterfeiter -o operationparser.gen.go --fake-name MockOperationParser . OperationParser

var logger = log.New("sidetree-core-applier")

// Applier is an operation applier.
type Applier struct {
	protocol.Protocol
	OperationParser
	protocol.DocumentComposer
}

// OperationParser defines the functions for parsing operations.
type OperationParser interface {
	ValidateSuffixData(suffixData *model.SuffixDataModel) error
	ValidateDelta(delta *model.DeltaModel) error
	ParseCreateOperation(request []byte, anchor bool) (*model.Operation, error)
	ParseUpdateOperation(request []byte, anchor bool) (*model.Operation, error)
	ParseRecoverOperation(request []byte, anchor bool) (*model.Operation, error)
	ParseDeactivateOperation(request []byte, anchor bool) (*model.Operation, error)
	ParseSignedDataForUpdate(compactJWS string) (*model.UpdateSignedDataModel, error)
	ParseSignedDataForDeactivate(compactJWS string) (*model.DeactivateSignedDataModel, error)
	ParseSignedDataForRecover(compactJWS string) (*model.RecoverSignedDataModel, error)
}

// New returns a new operation applier for the given protocol.
func New(p protocol.Protocol, parser OperationParser, dc protocol.DocumentComposer) *Applier {
	return &Applier{
		Protocol:         p,
		OperationParser:  parser,
		DocumentComposer: dc,
	}
}

// Apply applies the given anchored operation.
func (s *Applier) Apply(op *operation.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) {
	switch op.Type {
	case operation.TypeCreate:
		return s.applyCreateOperation(op, rm)
	case operation.TypeUpdate:
		return s.applyUpdateOperation(op, rm)
	case operation.TypeDeactivate:
		return s.applyDeactivateOperation(op, rm)
	case operation.TypeRecover:
		return s.applyRecoverOperation(op, rm)
	default:
		return nil, fmt.Errorf("operation type not supported for process operation")
	}
}

func (s *Applier) applyCreateOperation(anchoredOp *operation.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) {
	logger.Debugf("Applying create operation: %+v", anchoredOp)

	if rm.Doc != nil {
		return nil, errors.New("create has to be the first operation")
	}

	op, err := s.OperationParser.ParseCreateOperation(anchoredOp.OperationBuffer, true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse create operation in batch mode: %s", err.Error())
	}

	// from this point any error should advance recovery commitment
	result := &protocol.ResolutionModel{
		Doc:                              make(document.Document),
		LastOperationTransactionTime:     anchoredOp.TransactionTime,
		LastOperationTransactionNumber:   anchoredOp.TransactionTime,
		LastOperationProtocolGenesisTime: anchoredOp.ProtocolGenesisTime,
		RecoveryCommitment:               op.SuffixData.RecoveryCommitment,
	}

	// verify actual delta hash matches expected delta hash
	err = hashing.IsValidModelMultihash(op.Delta, op.SuffixData.DeltaHash)
	if err != nil {
		logger.Infof("Delta doesn't match delta hash; set update commitment to nil and advance recovery commitment {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", anchoredOp.UniqueSuffix, anchoredOp.Type, anchoredOp.TransactionTime, anchoredOp.TransactionTime, err)

		return result, nil
	}

	err = s.OperationParser.ValidateDelta(op.Delta)
	if err != nil {
		logger.Infof("Parse delta failed; set update commitment to nil and advance recovery commitment {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", op.UniqueSuffix, op.Type, anchoredOp.TransactionTime, anchoredOp.TransactionTime, err)

		return result, nil
	}

	result.UpdateCommitment = op.Delta.UpdateCommitment

	doc, err := s.ApplyPatches(make(document.Document), op.Delta.Patches)
	if err != nil {
		logger.Infof("Apply patches failed; advance commitments {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", anchoredOp.UniqueSuffix, anchoredOp.Type, anchoredOp.TransactionTime, anchoredOp.TransactionTime, err)

		return result, nil
	}

	result.Doc = doc

	return result, nil
}

func (s *Applier) applyUpdateOperation(anchoredOp *operation.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) { //nolint:dupl
	logger.Debugf("Applying update operation: %+v", anchoredOp)

	if rm.Doc == nil {
		return nil, errors.New("update cannot be first operation")
	}

	op, err := s.OperationParser.ParseUpdateOperation(anchoredOp.OperationBuffer, true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse update operation in batch mode: %s", err.Error())
	}

	signedDataModel, err := s.ParseSignedDataForUpdate(op.SignedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed data model while applying update: %s", err.Error())
	}

	// verify the delta against the signed delta hash
	err = hashing.IsValidModelMultihash(op.Delta, signedDataModel.DeltaHash)
	if err != nil {
		return nil, fmt.Errorf("update delta doesn't match delta hash: %s", err.Error())
	}

	// verify signature
	_, err = internal.VerifyJWS(op.SignedData, signedDataModel.UpdateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check signature: %s", err.Error())
	}

	err = s.OperationParser.ValidateDelta(op.Delta)
	if err != nil {
		return nil, fmt.Errorf("failed to validate delta: %s", err.Error())
	}

	// delta is valid so advance update commitment
	result := &protocol.ResolutionModel{
		Doc:                              rm.Doc,
		LastOperationTransactionTime:     anchoredOp.TransactionTime,
		LastOperationTransactionNumber:   anchoredOp.TransactionTime,
		LastOperationProtocolGenesisTime: anchoredOp.ProtocolGenesisTime,
		UpdateCommitment:                 op.Delta.UpdateCommitment,
		RecoveryCommitment:               rm.RecoveryCommitment,
	}

	doc, err := s.ApplyPatches(rm.Doc, op.Delta.Patches)
	if err != nil {
		logger.Infof("Apply patches failed; advance update commitment {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", op.UniqueSuffix, op.Type, anchoredOp.TransactionTime, anchoredOp.TransactionTime, err)

		return result, nil
	}

	// applying patches succeeded so update document
	result.Doc = doc

	return result, nil
}

func (s *Applier) applyDeactivateOperation(anchoredOp *operation.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) {
	logger.Debugf("[%s] Applying deactivate operation: %+v", anchoredOp)

	if rm.Doc == nil {
		return nil, errors.New("deactivate can only be applied to an existing document")
	}

	op, err := s.OperationParser.ParseDeactivateOperation(anchoredOp.OperationBuffer, true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse deactive operation in batch mode: %s", err.Error())
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
		Doc:                              make(document.Document),
		LastOperationTransactionTime:     anchoredOp.TransactionTime,
		LastOperationTransactionNumber:   anchoredOp.TransactionTime,
		LastOperationProtocolGenesisTime: anchoredOp.ProtocolGenesisTime,
		UpdateCommitment:                 "",
		RecoveryCommitment:               "",
		Deactivated:                      true,
	}, nil
}

func (s *Applier) applyRecoverOperation(anchoredOp *operation.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) { //nolint:dupl
	logger.Debugf("Applying recover operation: %+v", anchoredOp)

	if rm.Doc == nil {
		return nil, errors.New("recover can only be applied to an existing document")
	}

	op, err := s.OperationParser.ParseRecoverOperation(anchoredOp.OperationBuffer, true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse recover operation in batch mode: %s", err.Error())
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
		LastOperationTransactionTime:     anchoredOp.TransactionTime,
		LastOperationTransactionNumber:   anchoredOp.TransactionTime,
		LastOperationProtocolGenesisTime: anchoredOp.ProtocolGenesisTime,
		RecoveryCommitment:               signedDataModel.RecoveryCommitment,
	}

	// verify the delta against the signed delta hash
	err = hashing.IsValidModelMultihash(op.Delta, signedDataModel.DeltaHash)
	if err != nil {
		logger.Infof("Recover delta doesn't match delta hash; set update commitment to nil and advance recovery commitment {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", op.UniqueSuffix, op.Type, anchoredOp.TransactionTime, anchoredOp.TransactionTime, err)

		return result, nil
	}

	err = s.OperationParser.ValidateDelta(op.Delta)
	if err != nil {
		logger.Infof("Parse delta failed; set update commitment to nil and advance recovery commitment {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", op.UniqueSuffix, op.Type, anchoredOp.TransactionTime, anchoredOp.TransactionTime, err)

		return result, nil
	}

	result.UpdateCommitment = op.Delta.UpdateCommitment

	doc, err := s.ApplyPatches(make(document.Document), op.Delta.Patches)
	if err != nil {
		logger.Infof("Apply patches failed; advance commitments {UniqueSuffix: %s, Type: %s, TransactionTime: %d, TransactionNumber: %d}. Reason: %s", op.UniqueSuffix, op.Type, anchoredOp.TransactionTime, anchoredOp.TransactionTime, err)

		return result, nil
	}

	result.Doc = doc

	return result, nil
}
