/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationapplier

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	internal "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/log"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/model"
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
	logger.Debug("Applying create operation", log.WithOperation(anchoredOp))

	if rm.Doc != nil {
		return nil, errors.New("create has to be the first operation")
	}

	op, err := s.OperationParser.ParseCreateOperation(anchoredOp.OperationRequest, true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse create operation in batch mode: %s", err.Error())
	}

	// from this point any error should advance recovery commitment
	result := &protocol.ResolutionModel{
		Doc:                            make(document.Document),
		CreatedTime:                    anchoredOp.TransactionTime,
		LastOperationTransactionTime:   anchoredOp.TransactionTime,
		LastOperationTransactionNumber: anchoredOp.TransactionNumber,
		LastOperationProtocolVersion:   anchoredOp.ProtocolVersion,
		VersionID:                      anchoredOp.CanonicalReference,
		CanonicalReference:             anchoredOp.CanonicalReference,
		EquivalentReferences:           anchoredOp.EquivalentReferences,
		RecoveryCommitment:             op.SuffixData.RecoveryCommitment,
		AnchorOrigin:                   op.SuffixData.AnchorOrigin,
		PublishedOperations:            rm.PublishedOperations,
		UnpublishedOperations:          rm.UnpublishedOperations,
	}

	// verify actual delta hash matches expected delta hash
	err = hashing.IsValidModelMultihash(op.Delta, op.SuffixData.DeltaHash)
	if err != nil {
		logger.Info("Delta doesn't match delta hash; set update commitment to nil and advance recovery commitment",
			log.WithError(err), log.WithSuffix(anchoredOp.UniqueSuffix), log.WithOperationType(string(anchoredOp.Type)),
			log.WithTransactionTime(anchoredOp.TransactionTime), log.WithTransactionNumber(anchoredOp.TransactionNumber))

		return result, nil
	}

	err = s.OperationParser.ValidateDelta(op.Delta)
	if err != nil {
		logger.Info("Parse delta failed; set update commitment to nil and advance recovery commitment",
			log.WithError(err), log.WithSuffix(op.UniqueSuffix), log.WithOperationType(string(op.Type)),
			log.WithTransactionTime(anchoredOp.TransactionTime), log.WithTransactionNumber(anchoredOp.TransactionNumber))

		return result, nil
	}

	result.UpdateCommitment = op.Delta.UpdateCommitment

	doc, err := s.ApplyPatches(make(document.Document), op.Delta.Patches)
	if err != nil {
		logger.Info("Apply patches failed; advance commitments",
			log.WithError(err), log.WithSuffix(anchoredOp.UniqueSuffix), log.WithOperationType(string(anchoredOp.Type)),
			log.WithTransactionTime(anchoredOp.TransactionTime), log.WithTransactionNumber(anchoredOp.TransactionNumber))

		return result, nil
	}

	result.Doc = doc

	return result, nil
}

func (s *Applier) applyUpdateOperation(anchoredOp *operation.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) { //nolint:dupl,funlen
	logger.Debug("Applying update operation", log.WithOperation(anchoredOp))

	if rm.Doc == nil {
		return nil, errors.New("update cannot be first operation")
	}

	op, err := s.OperationParser.ParseUpdateOperation(anchoredOp.OperationRequest, true)
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
		Doc:                            rm.Doc,
		CreatedTime:                    rm.CreatedTime,
		UpdatedTime:                    anchoredOp.TransactionTime,
		LastOperationTransactionTime:   anchoredOp.TransactionTime,
		LastOperationTransactionNumber: anchoredOp.TransactionNumber,
		LastOperationProtocolVersion:   anchoredOp.ProtocolVersion,
		VersionID:                      anchoredOp.CanonicalReference,
		CanonicalReference:             rm.CanonicalReference,
		EquivalentReferences:           rm.EquivalentReferences,
		UpdateCommitment:               op.Delta.UpdateCommitment,
		RecoveryCommitment:             rm.RecoveryCommitment,
		AnchorOrigin:                   rm.AnchorOrigin,
		PublishedOperations:            rm.PublishedOperations,
		UnpublishedOperations:          rm.UnpublishedOperations,
	}

	// verify anchor from and until time against anchoring time
	err = s.verifyAnchoringTimeRange(signedDataModel.AnchorFrom, signedDataModel.AnchorUntil, anchoredOp.TransactionTime)
	if err != nil {
		logger.Info("invalid anchoring time range; advance commitments",
			log.WithSuffix(op.UniqueSuffix), log.WithOperationType(string(op.Type)),
			log.WithTransactionTime(anchoredOp.TransactionTime), log.WithTransactionNumber(anchoredOp.TransactionNumber),
			log.WithError(err))

		return result, nil
	}

	doc, err := s.ApplyPatches(rm.Doc, op.Delta.Patches)
	if err != nil {
		logger.Info("Apply patches failed; advance update commitment",
			log.WithSuffixes(op.UniqueSuffix), log.WithOperationType(string(op.Type)),
			log.WithTransactionTime(anchoredOp.TransactionTime), log.WithTransactionNumber(anchoredOp.TransactionNumber),
			log.WithError(err))

		return result, nil
	}

	// applying patches succeeded so update document
	result.Doc = doc

	return result, nil
}

func (s *Applier) applyDeactivateOperation(anchoredOp *operation.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) {
	logger.Debug("Applying deactivate operation", log.WithOperation(anchoredOp))

	if rm.Doc == nil {
		return nil, errors.New("deactivate can only be applied to an existing document")
	}

	op, err := s.OperationParser.ParseDeactivateOperation(anchoredOp.OperationRequest, true)
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

	// verify anchor from and until time against anchoring time
	err = s.verifyAnchoringTimeRange(signedDataModel.AnchorFrom, signedDataModel.AnchorUntil, anchoredOp.TransactionTime)
	if err != nil {
		return nil, fmt.Errorf("invalid anchoring time range: %s", err.Error())
	}

	return &protocol.ResolutionModel{
		Doc:                            make(document.Document),
		CreatedTime:                    rm.CreatedTime,
		UpdatedTime:                    anchoredOp.TransactionTime,
		LastOperationTransactionTime:   anchoredOp.TransactionTime,
		LastOperationTransactionNumber: anchoredOp.TransactionNumber,
		LastOperationProtocolVersion:   anchoredOp.ProtocolVersion,
		VersionID:                      anchoredOp.CanonicalReference,
		CanonicalReference:             rm.CanonicalReference,
		EquivalentReferences:           rm.EquivalentReferences,
		UpdateCommitment:               "",
		RecoveryCommitment:             "",
		Deactivated:                    true,
		AnchorOrigin:                   rm.AnchorOrigin,
		PublishedOperations:            rm.PublishedOperations,
		UnpublishedOperations:          rm.UnpublishedOperations,
	}, nil
}

func (s *Applier) applyRecoverOperation(anchoredOp *operation.AnchoredOperation, rm *protocol.ResolutionModel) (*protocol.ResolutionModel, error) { //nolint:dupl,funlen
	logger.Debug("Applying recover operation", log.WithOperation(anchoredOp))

	if rm.Doc == nil {
		return nil, errors.New("recover can only be applied to an existing document")
	}

	op, err := s.OperationParser.ParseRecoverOperation(anchoredOp.OperationRequest, true)
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
		Doc:                            make(document.Document),
		CreatedTime:                    rm.CreatedTime,
		UpdatedTime:                    anchoredOp.TransactionTime,
		LastOperationTransactionTime:   anchoredOp.TransactionTime,
		LastOperationTransactionNumber: anchoredOp.TransactionNumber,
		LastOperationProtocolVersion:   anchoredOp.ProtocolVersion,
		VersionID:                      anchoredOp.CanonicalReference,
		CanonicalReference:             anchoredOp.CanonicalReference,
		EquivalentReferences:           anchoredOp.EquivalentReferences,
		RecoveryCommitment:             signedDataModel.RecoveryCommitment,
		AnchorOrigin:                   signedDataModel.AnchorOrigin,
		PublishedOperations:            rm.PublishedOperations,
		UnpublishedOperations:          rm.UnpublishedOperations,
	}

	// verify the delta against the signed delta hash
	err = hashing.IsValidModelMultihash(op.Delta, signedDataModel.DeltaHash)
	if err != nil {
		logger.Info("Recover delta doesn't match delta hash; set update commitment to nil and advance recovery commitment",
			log.WithSuffixes(op.UniqueSuffix), log.WithOperationType(string(op.Type)),
			log.WithTransactionTime(anchoredOp.TransactionTime), log.WithTransactionNumber(anchoredOp.TransactionNumber),
			log.WithError(err))

		return result, nil
	}

	err = s.OperationParser.ValidateDelta(op.Delta)
	if err != nil {
		logger.Info("Parse delta failed; set update commitment to nil and advance recovery commitment",
			log.WithSuffixes(op.UniqueSuffix), log.WithOperationType(string(op.Type)),
			log.WithTransactionTime(anchoredOp.TransactionTime), log.WithTransactionNumber(anchoredOp.TransactionNumber),
			log.WithError(err))

		return result, nil
	}

	result.UpdateCommitment = op.Delta.UpdateCommitment

	// verify anchor from and until time against anchoring time
	err = s.verifyAnchoringTimeRange(signedDataModel.AnchorFrom, signedDataModel.AnchorUntil, anchoredOp.TransactionTime)
	if err != nil {
		logger.Info("Invalid anchoring time range; advance commitments",
			log.WithSuffixes(op.UniqueSuffix), log.WithOperationType(string(op.Type)),
			log.WithTransactionTime(anchoredOp.TransactionTime), log.WithTransactionNumber(anchoredOp.TransactionNumber),
			log.WithError(err))

		return result, nil
	}

	doc, err := s.ApplyPatches(make(document.Document), op.Delta.Patches)
	if err != nil {
		logger.Info("Apply patches failed; advance commitments",
			log.WithSuffixes(op.UniqueSuffix), log.WithOperationType(string(op.Type)),
			log.WithTransactionTime(anchoredOp.TransactionTime), log.WithTransactionNumber(anchoredOp.TransactionNumber),
			log.WithError(err))

		return result, nil
	}

	result.Doc = doc

	return result, nil
}

func (s *Applier) verifyAnchoringTimeRange(from, until int64, anchor uint64) error {
	if from == 0 && until == 0 {
		// from and until are not specified - nothing to check
		return nil
	}

	if from > int64(anchor) {
		return fmt.Errorf("anchor from time is greater then anchoring time")
	}

	if s.getAnchorUntil(from, until) < int64(anchor) {
		return fmt.Errorf("anchor until time is less then anchoring time")
	}

	return nil
}

func (s *Applier) getAnchorUntil(from, until int64) int64 {
	if from != 0 && until == 0 {
		return from + int64(s.MaxDeltaSize)
	}

	return until
}
