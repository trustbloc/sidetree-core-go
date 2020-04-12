/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package processor

import (
	"encoding/json"
	"errors"
	"sort"

	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/composer"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	internal "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// recovery key ID
const (
	recoveryKID       = "recovery"
	operationsKeyType = "ops"
)

// OperationProcessor will process document operations in chronological order and create final document during resolution.
// It uses operation store client to retrieve all operations that are related to requested document.
type OperationProcessor struct {
	name  string
	store OperationStoreClient
}

// OperationStoreClient defines interface for retrieving all operations related to document
type OperationStoreClient interface {
	// Get retrieves all operations related to document
	Get(uniqueSuffix string) ([]*batch.Operation, error)
}

// New returns new operation processor with the given name. (Note that name is only used for logging.)
func New(name string, store OperationStoreClient) *OperationProcessor {
	return &OperationProcessor{name: name, store: store}
}

// Resolve document based on the given unique suffix
// Parameters:
// uniqueSuffix - unique portion of ID to resolve. for example "abc123" in "did:sidetree:abc123"
func (s *OperationProcessor) Resolve(uniqueSuffix string) (document.Document, error) {
	ops, err := s.store.Get(uniqueSuffix)
	if err != nil {
		return nil, err
	}

	sortOperations(ops)

	log.Debugf("[%s] Found %d operations for unique suffix [%s]: %+v", s.name, len(ops), uniqueSuffix, ops)

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
		return nil, errors.New("document was revoked")
	}

	// next apply update ops since last 'full' transaction
	rm, err = s.applyOperations(getOpsWithTxnGreaterThan(updateOps, rm.LastOperationTransactionTime, rm.LastOperationTransactionNumber), rm)
	if err != nil {
		return nil, err
	}

	return rm.Doc, nil
}

func splitOperations(ops []*batch.Operation) (fullOps, updateOps []*batch.Operation) {
	for _, op := range ops {
		if op.Type == batch.OperationTypeUpdate {
			updateOps = append(updateOps, op)
		} else { // Create, Recover, Revoke
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

		log.Debugf("[%s] After applying op %+v, New doc: %s", s.name, op, rm.Doc)
	}

	return rm, nil
}

type resolutionModel struct {
	Doc                            document.Document
	LastOperationTransactionTime   uint64
	LastOperationTransactionNumber uint64
	NextUpdateCommitmentHash       string
	NextRecoveryCommitmentHash     string
	RecoveryKey                    *jws.JWK
}

func (s *OperationProcessor) applyOperation(operation *batch.Operation, rm *resolutionModel) (*resolutionModel, error) {
	switch operation.Type {
	case batch.OperationTypeCreate:
		return s.applyCreateOperation(operation, rm)
	case batch.OperationTypeUpdate:
		return s.applyUpdateOperation(operation, rm)
	case batch.OperationTypeRevoke:
		return s.applyRevokeOperation(operation, rm)
	case batch.OperationTypeRecover:
		return s.applyRecoverOperation(operation, rm)
	default:
		return nil, errors.New("operation type not supported for process operation")
	}
}

func (s *OperationProcessor) applyCreateOperation(operation *batch.Operation, rm *resolutionModel) (*resolutionModel, error) {
	log.Debugf("[%s] Applying create operation: %+v", s.name, operation)

	if rm.Doc != nil {
		return nil, errors.New("create has to be the first operation")
	}

	doc, err := composer.ApplyPatches(nil, operation.PatchData.Patches)
	if err != nil {
		return nil, err
	}

	return &resolutionModel{
		Doc:                            doc,
		LastOperationTransactionTime:   operation.TransactionTime,
		LastOperationTransactionNumber: operation.TransactionNumber,
		NextUpdateCommitmentHash:       operation.NextUpdateCommitmentHash,
		NextRecoveryCommitmentHash:     operation.NextRecoveryCommitmentHash,
		RecoveryKey:                    operation.SuffixData.RecoveryKey,
	}, nil
}

func (s *OperationProcessor) applyUpdateOperation(operation *batch.Operation, rm *resolutionModel) (*resolutionModel, error) { //nolint:dupl
	log.Debugf("[%s] Applying update operation: %+v", s.name, operation)

	if rm.Doc == nil {
		return nil, errors.New("update cannot be first operation")
	}

	err := isValidHash(operation.UpdateRevealValue, rm.NextUpdateCommitmentHash)
	if err != nil {
		return nil, err
	}

	signingKID := operation.SignedData.Protected.Kid

	var signingPublicKey *jws.JWK
	if signingKID == recoveryKID {
		signingPublicKey = rm.RecoveryKey
	} else {
		signingPublicKey, err = getSigningPublicKeyFromDoc(rm.Doc, signingKID)
		if err != nil {
			return nil, err
		}
	}

	_, err = internal.ParseJWS(operation.SignedData.Signature, signingPublicKey)
	if err != nil {
		return nil, err
	}

	doc, err := composer.ApplyPatches(rm.Doc, operation.PatchData.Patches)
	if err != nil {
		return nil, err
	}

	return &resolutionModel{
		Doc:                            doc,
		LastOperationTransactionTime:   operation.TransactionTime,
		LastOperationTransactionNumber: operation.TransactionNumber,
		NextUpdateCommitmentHash:       operation.NextUpdateCommitmentHash,
		NextRecoveryCommitmentHash:     rm.NextRecoveryCommitmentHash,
		RecoveryKey:                    rm.RecoveryKey}, nil
}

func getSigningPublicKeyFromDoc(doc document.Document, kid string) (*jws.JWK, error) {
	pk, err := findPublicKey(doc, kid)
	if err != nil {
		return nil, err
	}

	if err := validateSigningKey(pk); err != nil {
		return nil, err
	}

	jwk := pk.PublicKeyJWK()

	return &jws.JWK{
		Kty: jwk.Kty(),
		Crv: jwk.Crv(),
		X:   jwk.X(),
		Y:   jwk.Y(),
	}, nil
}

func validateSigningKey(pk document.PublicKey) error {
	if !containsString(pk.Usage(), operationsKeyType) {
		return errors.New("signing public key is not an operations key")
	}

	jwk := pk.PublicKeyJWK()
	if jwk == nil {
		return errors.New("signing public key has to be in JWK format")
	}

	return nil
}

func findPublicKey(doc document.Document, kid string) (document.PublicKey, error) {
	didDoc := document.DidDocumentFromJSONLDObject(doc.JSONLdObject())
	for _, pk := range didDoc.PublicKeys() {
		if pk.ID() == kid {
			return pk, nil
		}
	}

	return nil, errors.New("signing public key not found in the document")
}

func (s *OperationProcessor) applyRevokeOperation(operation *batch.Operation, rm *resolutionModel) (*resolutionModel, error) {
	log.Debugf("[%s] Applying revoke operation: %+v", s.name, operation)

	if rm.Doc == nil {
		return nil, errors.New("revoke can only be applied to an existing document")
	}

	err := isValidHash(operation.RecoveryRevealValue, rm.NextRecoveryCommitmentHash)
	if err != nil {
		return nil, err
	}

	_, err = internal.ParseJWS(operation.SignedData.Signature, rm.RecoveryKey)
	if err != nil {
		return nil, err
	}

	return &resolutionModel{
		Doc:                            nil,
		LastOperationTransactionTime:   operation.TransactionTime,
		LastOperationTransactionNumber: operation.TransactionNumber,
		NextUpdateCommitmentHash:       "",
		NextRecoveryCommitmentHash:     ""}, nil
}

func (s *OperationProcessor) applyRecoverOperation(operation *batch.Operation, rm *resolutionModel) (*resolutionModel, error) { //nolint:dupl
	log.Debugf("[%s] Applying recover operation: %+v", s.name, operation)

	if rm.Doc == nil {
		return nil, errors.New("recover can only be applied to an existing document")
	}

	err := isValidHash(operation.RecoveryRevealValue, rm.NextRecoveryCommitmentHash)
	if err != nil {
		return nil, err
	}

	jwsParts, err := internal.ParseJWS(operation.SignedData.Signature, rm.RecoveryKey)
	if err != nil {
		return nil, err
	}

	decoded, err := docutil.DecodeString(string(jwsParts.Payload))
	if err != nil {
		return nil, err
	}

	var signedDataModel model.RecoverSignedDataModel
	err = json.Unmarshal(decoded, &signedDataModel)
	if err != nil {
		return nil, err
	}

	doc, err := composer.ApplyPatches(rm.Doc, operation.PatchData.Patches)
	if err != nil {
		return nil, err
	}

	return &resolutionModel{
		Doc:                            doc,
		LastOperationTransactionTime:   operation.TransactionTime,
		LastOperationTransactionNumber: operation.TransactionNumber,
		NextUpdateCommitmentHash:       operation.NextUpdateCommitmentHash,
		NextRecoveryCommitmentHash:     operation.NextRecoveryCommitmentHash,
		RecoveryKey:                    signedDataModel.RecoveryKey}, nil
}

func isValidHash(encodedContent, encodedMultihash string) error {
	content, err := docutil.DecodeString(encodedContent)
	if err != nil {
		return err
	}

	code, err := docutil.GetMultihashCode(encodedMultihash)
	if err != nil {
		return err
	}

	computedMultihash, err := docutil.ComputeMultihash(uint(code), content)
	if err != nil {
		return err
	}

	encodedComputedMultihash := docutil.EncodeToString(computedMultihash)

	if encodedComputedMultihash != encodedMultihash {
		return errors.New("supplied hash doesn't match original content")
	}

	return nil
}

func sortOperations(ops []*batch.Operation) {
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].TransactionTime < ops[j].TransactionTime {
			return true
		}

		return ops[i].TransactionNumber < ops[j].TransactionNumber
	})
}
