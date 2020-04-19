/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package processor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	internal "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/helper"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
)

const (
	sha2_256          = 18
	dummyUniqueSuffix = "dummy"

	updateReveal   = "updateReveal"
	recoveryReveal = "recoveryReveal"
)

func TestResolve(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store, uniqueSuffix := getDefaultStore(privateKey)

	op := New("test", store)

	doc, err := op.Resolve(uniqueSuffix)

	require.Nil(t, err)
	require.NotNil(t, doc)
}

func TestDocumentNotFoundError(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store, _ := getDefaultStore(privateKey)

	op := New("test", store)
	doc, err := op.Resolve(dummyUniqueSuffix)
	require.Nil(t, doc)
	require.Error(t, err)
	require.Equal(t, "uniqueSuffix not found in the store", err.Error())
}

func TestResolveMockStoreError(t *testing.T) {
	testErr := errors.New("test store error")
	store := mocks.NewMockOperationStore(testErr)
	p := New("test", store)

	doc, err := p.Resolve("suffix")
	require.Nil(t, doc)
	require.Error(t, err)
	require.Equal(t, testErr, err)
}

func TestResolveError(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store := mocks.NewMockOperationStore(nil)

	jsonPatch, err := patch.NewJSONPatch("[]")
	require.NoError(t, err)
	jsonPatch["patches"] = "invalid"

	createOp, err := getCreateOperation(privateKey)
	require.NoError(t, err)
	createOp.Delta = &model.DeltaModel{
		Patches: []patch.Patch{jsonPatch},
	}

	err = store.Put(createOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(createOp.UniqueSuffix)
	require.Nil(t, doc)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected array")
}

func TestUpdateDocument(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(privateKey)

		updateOp, err := getUpdateOperation(privateKey, uniqueSuffix, 1)
		require.Nil(t, err)
		err = store.Put(updateOp)
		require.Nil(t, err)

		p := New("test", store) //Storing operation in the test store
		result, err := p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		didDoc := document.FromJSONLDObject(result.Document)

		//updated instance value inside public key via json patch
		require.Equal(t, "special1", didDoc.PublicKeys()[0].JWK().Kty())
	})

	t.Run("Missing signed data -> error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(privateKey)

		updateOp, err := getUpdateOperation(privateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		updateOp.SignedData = nil

		err = store.Put(updateOp)
		require.NoError(t, err)

		p := New("test", store) //Storing operation in the test store
		_, err = p.Resolve(uniqueSuffix)
		require.Error(t, err, "missing protected section of signedData")
	})

	t.Run("Missing protected section of signed data -> error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(privateKey)

		updateOp, err := getUpdateOperation(privateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		updateOp.SignedData.Protected = nil

		err = store.Put(updateOp)
		require.NoError(t, err)

		p := New("test", store) //Storing operation in the test store
		_, err = p.Resolve(uniqueSuffix)
		require.Error(t, err, "missing protected section of signedData")
	})
}

func TestUpdateDocument_InvalidRevealValue(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store, uniqueSuffix := getDefaultStore(privateKey)

	updateOp, err := getUpdateOperation(privateKey, uniqueSuffix, 77)
	require.Nil(t, err)
	err = store.Put(updateOp)
	require.Nil(t, err)

	p := New("test", store) //Storing operation in the test store
	doc, err := p.Resolve(uniqueSuffix)
	require.Error(t, err)
	require.Contains(t, err.Error(), "supplied hash doesn't match original content")
	require.Nil(t, doc)
}

func TestConsecutiveUpdates(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store, uniqueSuffix := getDefaultStore(privateKey)

	updateOp, err := getUpdateOperation(privateKey, uniqueSuffix, 1)
	require.Nil(t, err)
	err = store.Put(updateOp)
	require.Nil(t, err)

	updateOp, err = getUpdateOperation(privateKey, uniqueSuffix, 2)
	require.Nil(t, err)
	err = store.Put(updateOp)
	require.Nil(t, err)

	p := New("test", store)
	result, err := p.Resolve(uniqueSuffix)
	require.Nil(t, err)

	didDoc := document.FromJSONLDObject(result.Document)

	// double updated instance value inside public key via json patch
	require.Equal(t, "special2", didDoc.PublicKeys()[0].JWK().Kty())
}

func TestUpdate_InvalidSignature(t *testing.T) {
	recoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store, uniqueSuffix := getDefaultStore(recoveryKey)

	// sign recover operation with different recovery key (than one used in create)
	differentRecoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	updateOp, err := getUpdateOperation(differentRecoveryKey, uniqueSuffix, 1)
	require.NoError(t, err)

	err = store.Put(updateOp)
	require.NoError(t, err)

	p := New("test", store)
	doc, err := p.Resolve(uniqueSuffix)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ecdsa: invalid signature")
	require.Nil(t, doc)
}

func TestUpdate_PublicKeyInDocument(t *testing.T) {
	recoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store := mocks.NewMockOperationStore(nil)

	updateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	publicKey, err := pubkey.GetPublicKeyJWK(&updateKey.PublicKey)
	require.NoError(t, err)

	publicKeyBytes, err := json.Marshal(publicKey)
	require.NoError(t, err)

	const keyID = "public-key"
	opaque := fmt.Sprintf(docTemplate, keyID, string(publicKeyBytes))

	// get and store create operation
	createOp, err := getCreateOperationWithDoc(recoveryKey, opaque)
	require.NoError(t, err)
	err = store.Put(createOp)
	require.Nil(t, err)

	s := ecsigner.New(updateKey, "ES256", keyID)
	updateOp, err := getUpdateOperationWithSigner(s, createOp.UniqueSuffix, 1)
	require.NoError(t, err)

	err = store.Put(updateOp)
	require.NoError(t, err)

	p := New("test", store)
	doc, err := p.Resolve(createOp.UniqueSuffix)
	require.NoError(t, err)
	require.NotNil(t, doc)
}

func TestUpdateDocument_SigningKeyNotInDocument(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store, uniqueSuffix := getDefaultStore(privateKey)

	s := ecsigner.New(privateKey, "ES256", "some-key")
	updateOp, err := getUpdateOperationWithSigner(s, uniqueSuffix, 1)
	require.NoError(t, err)

	err = store.Put(updateOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(uniqueSuffix)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "signing public key not found in the document")
}

func TestProcessOperation_UpdateIsFirstOperation(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store := mocks.NewMockOperationStore(nil)

	uniqueSuffix := "uniqueSuffix"

	updateOp, err := getUpdateOperation(privateKey, uniqueSuffix, 1)
	require.Nil(t, err)
	err = store.Put(updateOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(uniqueSuffix)
	require.Error(t, err)
	require.Nil(t, doc)
	require.Equal(t, "missing create operation", err.Error())
}

func TestProcessOperation_CreateIsSecondOperation(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store := mocks.NewMockOperationStore(nil)
	store.Validate = false

	createOp, err := getCreateOperation(privateKey)
	require.NoError(t, err)

	// store create operation
	err = store.Put(createOp)
	require.Nil(t, err)

	// store create operation again
	err = store.Put(createOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(createOp.UniqueSuffix)
	require.Error(t, err)
	require.Nil(t, doc)
	require.Equal(t, "create has to be the first operation", err.Error())
}

func TestProcessOperation_InvalidOperationType(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store := mocks.NewMockOperationStore(nil)

	createOp, err := getCreateOperation(privateKey)
	require.NoError(t, err)

	createOp.Type = "invalid"

	// store create operation
	err = store.Put(createOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(createOp.UniqueSuffix)
	require.Error(t, err)
	require.Nil(t, doc)
	require.Equal(t, "operation type not supported for process operation", err.Error())
}

func TestIsValidHashErrors(t *testing.T) {
	multihash, err := docutil.ComputeMultihash(sha2_256, []byte("test"))
	require.NoError(t, err)

	encodedMultihash := docutil.EncodeToString(multihash)

	err = isValidHash("hello", encodedMultihash)
	require.Error(t, err)
	require.Contains(t, err.Error(), "illegal base64 data at input byte 4")

	err = isValidHash(docutil.EncodeToString([]byte("content")), string(multihash))
	require.Error(t, err)
	require.Contains(t, err.Error(), "illegal base64 data at input byte 0")

	err = isValidHash(docutil.EncodeToString([]byte("content")), encodedMultihash)
	require.Error(t, err)
	require.Contains(t, err.Error(), "supplied hash doesn't match original content")
}

func TestDeactivate(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store, uniqueSuffix := getDefaultStore(privateKey)

	deactivateOp, err := getDeactivateOperation(privateKey, uniqueSuffix, 1)
	require.NoError(t, err)

	err = store.Put(deactivateOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(uniqueSuffix)
	require.Error(t, err)
	require.Contains(t, err.Error(), "document was deactivated")
	require.Nil(t, doc)
}

func TestConsecutiveDeactivate(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store, uniqueSuffix := getDefaultStore(privateKey)

	deactivateOp, err := getDeactivateOperation(privateKey, uniqueSuffix, 1)
	require.NoError(t, err)
	err = store.Put(deactivateOp)
	require.Nil(t, err)

	deactivateOp, err = getDeactivateOperation(privateKey, uniqueSuffix, 2)
	require.NoError(t, err)
	err = store.Put(deactivateOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(uniqueSuffix)
	require.Error(t, err)
	require.Contains(t, err.Error(), "deactivate can only be applied to an existing document")
	require.Nil(t, doc)
}

func TestDeactivate_DocumentNotFound(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store, _ := getDefaultStore(privateKey)

	deactivateOp, err := getDeactivateOperation(privateKey, dummyUniqueSuffix, 0)
	require.NoError(t, err)
	err = store.Put(deactivateOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(dummyUniqueSuffix)
	require.Error(t, err)
	require.Contains(t, err.Error(), "deactivate can only be applied to an existing document")
	require.Nil(t, doc)
}

func TestDeactivate_InvalidRecoveryRevealValue(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store, uniqueSuffix := getDefaultStore(privateKey)

	deactivateOp, err := getDeactivateOperation(privateKey, uniqueSuffix, 1)
	require.NoError(t, err)
	deactivateOp.RecoveryRevealValue = docutil.EncodeToString([]byte("invalid"))
	err = store.Put(deactivateOp)
	require.NoError(t, err)

	p := New("test", store)
	doc, err := p.Resolve(uniqueSuffix)
	require.Error(t, err)
	require.Contains(t, err.Error(), "supplied hash doesn't match original content")
	require.Nil(t, doc)
}

func TestDeactivate_InvalidSignature(t *testing.T) {
	recoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store, uniqueSuffix := getDefaultStore(recoveryKey)

	// sign recover operation with different recovery key (than one used in create)
	differentRecoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	deactivateOp, err := getDeactivateOperation(differentRecoveryKey, uniqueSuffix, 1)
	require.NoError(t, err)
	err = store.Put(deactivateOp)
	require.NoError(t, err)

	p := New("test", store)
	doc, err := p.Resolve(uniqueSuffix)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ecdsa: invalid signature")
	require.Nil(t, doc)
}

func TestRecover(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store, uniqueSuffix := getDefaultStore(privateKey)

	recoverOp, err := getRecoverOperation(privateKey, uniqueSuffix, 1)
	require.NoError(t, err)
	err = store.Put(recoverOp)
	require.Nil(t, err)

	p := New("test", store)
	result, err := p.Resolve(uniqueSuffix)
	require.NoError(t, err)

	// test for recovered key
	docBytes, err := result.Document.Bytes()
	require.NoError(t, err)
	require.Contains(t, string(docBytes), "recovered")
}

func TestConsecutiveRecover(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store, uniqueSuffix := getDefaultStore(privateKey)

	recoverOp, err := getRecoverOperation(privateKey, uniqueSuffix, 1)
	require.NoError(t, err)
	err = store.Put(recoverOp)
	require.Nil(t, err)

	recoverOp, err = getRecoverOperation(privateKey, uniqueSuffix, 2)
	require.NoError(t, err)
	err = store.Put(recoverOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(uniqueSuffix)
	require.NoError(t, err)
	require.NotNil(t, doc)
}

func TestRecover_InvalidSignature(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store, uniqueSuffix := getDefaultStore(privateKey)

	// sign recover operation with different recovery key (than one used in create)
	differentRecoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	recoverOp, err := getRecoverOperation(differentRecoveryKey, uniqueSuffix, 1)
	require.NoError(t, err)
	err = store.Put(recoverOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(uniqueSuffix)
	require.Error(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "ecdsa: invalid signature")
}

func TestRecoverAfterDeactivate(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	store, uniqueSuffix := getDefaultStore(privateKey)

	deactivateOp, err := getDeactivateOperation(privateKey, uniqueSuffix, 1)
	require.NoError(t, err)
	err = store.Put(deactivateOp)
	require.Nil(t, err)

	recoverOp, err := getRecoverOperation(privateKey, uniqueSuffix, 2)
	require.NoError(t, err)
	err = store.Put(recoverOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(uniqueSuffix)
	require.Error(t, err)
	require.Contains(t, err.Error(), "recover can only be applied to an existing document")
	require.Nil(t, doc)
}

func TestRecover_InvalidRecoveryRevealValue(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	store, uniqueSuffix := getDefaultStore(privateKey)

	op, err := getRecoverOperation(privateKey, uniqueSuffix, 1)
	require.NoError(t, err)
	op.RecoveryRevealValue = docutil.EncodeToString([]byte("invalid"))
	err = store.Put(op)
	require.NoError(t, err)

	p := New("test", store)
	doc, err := p.Resolve(uniqueSuffix)
	require.Error(t, err)
	require.Contains(t, err.Error(), "supplied hash doesn't match original content")
	require.Nil(t, doc)
}

func TestOpsWithTxnGreaterThan(t *testing.T) {
	op1 := &batch.Operation{
		TransactionTime:   1,
		TransactionNumber: 1,
	}

	op2 := &batch.Operation{
		TransactionTime:   1,
		TransactionNumber: 2,
	}

	ops := []*batch.Operation{op1, op2}

	txns := getOpsWithTxnGreaterThan(ops, 0, 0)
	require.Equal(t, 2, len(txns))

	txns = getOpsWithTxnGreaterThan(ops, 2, 1)
	require.Equal(t, 0, len(txns))

	txns = getOpsWithTxnGreaterThan(ops, 1, 1)
	require.Equal(t, 1, len(txns))
}

func getUpdateOperationWithSigner(s helper.Signer, uniqueSuffix string, operationNumber uint) (*batch.Operation, error) {
	p := map[string]interface{}{
		"op":    "replace",
		"path":  "/publicKey/0/jwk/kty",
		"value": "special" + strconv.Itoa(int(operationNumber)),
	}

	patchBytes, err := docutil.MarshalCanonical([]map[string]interface{}{p})
	if err != nil {
		return nil, err
	}

	jsonPatch, err := patch.NewJSONPatch(string(patchBytes))
	if err != nil {
		return nil, err
	}

	updateRevealValue := docutil.EncodeToString([]byte(updateReveal + strconv.Itoa(int(operationNumber))))

	nextUpdateCommitmentHash := getEncodedMultihash([]byte(updateReveal + strconv.Itoa(int(operationNumber+1))))

	delta := &model.DeltaModel{
		UpdateCommitment: nextUpdateCommitmentHash,
		Patches:          []patch.Patch{jsonPatch},
	}

	deltaBytes, err := docutil.MarshalCanonical(delta)
	if err != nil {
		return nil, err
	}

	jws, err := signPayload(getEncodedMultihash(deltaBytes), s)
	if err != nil {
		return nil, err
	}

	operation := &batch.Operation{
		ID:                           "did:sidetree:" + uniqueSuffix,
		UniqueSuffix:                 uniqueSuffix,
		HashAlgorithmInMultiHashCode: sha2_256,
		Delta:                        delta,
		Type:                         batch.OperationTypeUpdate,
		TransactionNumber:            uint64(operationNumber),
		UpdateRevealValue:            updateRevealValue,
		UpdateCommitment:             nextUpdateCommitmentHash,
		SignedData:                   jws,
	}

	return operation, nil
}

func getUpdateOperation(privateKey *ecdsa.PrivateKey, uniqueSuffix string, operationNumber uint) (*batch.Operation, error) {
	s := ecsigner.New(privateKey, "ES256", "recovery")

	return getUpdateOperationWithSigner(s, uniqueSuffix, operationNumber)
}

func getDeactivateOperation(privateKey *ecdsa.PrivateKey, uniqueSuffix string, operationNumber uint) (*batch.Operation, error) {
	signedDataModel := model.DeactivateSignedDataModel{
		DidSuffix:           uniqueSuffix,
		RecoveryRevealValue: docutil.EncodeToString([]byte("recovery")),
	}

	s := ecsigner.New(privateKey, "ES256", "recovery")

	jws, err := signModel(signedDataModel, s)
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		ID:                  "did:sidetree:" + uniqueSuffix,
		UniqueSuffix:        uniqueSuffix,
		Type:                batch.OperationTypeDeactivate,
		TransactionTime:     0,
		TransactionNumber:   uint64(operationNumber),
		RecoveryRevealValue: docutil.EncodeToString([]byte(recoveryReveal)),
		SignedData:          jws,
	}, nil
}

func getRecoverOperation(privateKey *ecdsa.PrivateKey, uniqueSuffix string, operationNumber uint) (*batch.Operation, error) {
	recoverRequest, err := getDefaultRecoverRequest(privateKey)
	if err != nil {
		return nil, err
	}

	operationBuffer, err := json.Marshal(recoverRequest)
	if err != nil {
		return nil, err
	}

	nextUpdateCommitmentHash := getEncodedMultihash([]byte(updateReveal + "1"))

	nextRecoveryCommitmentHash := getEncodedMultihash([]byte(recoveryReveal))

	delta, err := getReplaceDelta(recoveredDoc)
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		UniqueSuffix:        uniqueSuffix,
		Type:                batch.OperationTypeRecover,
		OperationBuffer:     operationBuffer,
		Delta:               delta,
		EncodedDelta:        recoverRequest.Delta,
		SignedData:          recoverRequest.SignedData,
		RecoveryRevealValue: docutil.EncodeToString([]byte(recoveryReveal)),
		UpdateCommitment:    nextUpdateCommitmentHash,
		RecoveryCommitment:  nextRecoveryCommitmentHash,
		TransactionTime:     0,
		TransactionNumber:   uint64(operationNumber),
	}, nil
}

func getRecoverRequest(privateKey *ecdsa.PrivateKey, deltaModel *model.DeltaModel, signedDataModel *model.RecoverSignedDataModel) (*model.RecoverRequest, error) {
	deltaBytes, err := docutil.MarshalCanonical(deltaModel)
	if err != nil {
		return nil, err
	}

	jws, err := signModel(signedDataModel, ecsigner.New(privateKey, "ES256", "recovery"))
	if err != nil {
		return nil, err
	}

	return &model.RecoverRequest{
		Operation:  model.OperationTypeRecover,
		DidSuffix:  "suffix",
		Delta:      docutil.EncodeToString(deltaBytes),
		SignedData: jws,
	}, nil
}

func getDefaultRecoverRequest(privateKey *ecdsa.PrivateKey) (*model.RecoverRequest, error) {
	delta, err := getReplaceDelta(recoveredDoc)
	if err != nil {
		return nil, err
	}

	recoverSignedData, err := getRecoverSignedData(privateKey)
	if err != nil {
		return nil, err
	}

	return getRecoverRequest(privateKey, delta, recoverSignedData)
}

func getRecoverSignedData(privateKey *ecdsa.PrivateKey) (*model.RecoverSignedDataModel, error) {
	jwk, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &model.RecoverSignedDataModel{
		RecoveryKey:        jwk,
		RecoveryCommitment: getEncodedMultihash([]byte("recoveryReveal")),
		DeltaHash:          getEncodedMultihash([]byte("operation")),
	}, nil
}

func getDefaultStore(privateKey *ecdsa.PrivateKey) (*mocks.MockOperationStore, string) {
	store := mocks.NewMockOperationStore(nil)

	createOp, err := getCreateOperation(privateKey)
	if err != nil {
		panic(err)
	}

	// store default create operation
	err = store.Put(createOp)
	if err != nil {
		panic(err)
	}

	return store, createOp.UniqueSuffix
}

func getCreateOperationWithDoc(privateKey *ecdsa.PrivateKey, doc string) (*batch.Operation, error) {
	nextUpdateCommitmentHash := getEncodedMultihash([]byte(updateReveal + "1"))

	nextRecoveryCommitmentHash := getEncodedMultihash([]byte(recoveryReveal))

	createRequest, err := getCreateRequest(privateKey)
	if err != nil {
		return nil, err
	}

	operationBuffer, err := json.Marshal(createRequest)
	if err != nil {
		return nil, err
	}

	uniqueSuffix, err := docutil.CalculateUniqueSuffix(createRequest.SuffixData, sha2_256)
	if err != nil {
		return nil, err
	}

	delta, err := getReplaceDelta(doc)
	if err != nil {
		return nil, err
	}

	suffixData, err := getSuffixData(privateKey)
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		HashAlgorithmInMultiHashCode: sha2_256,
		ID:                           "did:sidetree:" + uniqueSuffix,
		UniqueSuffix:                 uniqueSuffix,
		Type:                         batch.OperationTypeCreate,
		OperationBuffer:              operationBuffer,
		Delta:                        delta,
		EncodedDelta:                 createRequest.Delta,
		SuffixData:                   suffixData,
		TransactionNumber:            0,
		UpdateCommitment:             nextUpdateCommitmentHash,
		RecoveryCommitment:           nextRecoveryCommitmentHash,
	}, nil
}

func getCreateOperation(privateKey *ecdsa.PrivateKey) (*batch.Operation, error) {
	return getCreateOperationWithDoc(privateKey, validDoc)
}

func getCreateRequest(privateKey *ecdsa.PrivateKey) (*model.CreateRequest, error) {
	delta, err := getReplaceDelta(validDoc)
	if err != nil {
		return nil, err
	}

	deltaBytes, err := docutil.MarshalCanonical(delta)
	if err != nil {
		return nil, err
	}

	suffixData, err := getSuffixData(privateKey)
	if err != nil {
		return nil, err
	}

	suffixDataBytes, err := docutil.MarshalCanonical(suffixData)
	if err != nil {
		return nil, err
	}

	return &model.CreateRequest{
		Operation:  model.OperationTypeCreate,
		Delta:      docutil.EncodeToString(deltaBytes),
		SuffixData: docutil.EncodeToString(suffixDataBytes),
	}, nil
}

func getReplaceDelta(doc string) (*model.DeltaModel, error) {
	replace, err := patch.NewReplacePatch(doc)
	if err != nil {
		return nil, err
	}

	return &model.DeltaModel{
		Patches:          []patch.Patch{replace},
		UpdateCommitment: getEncodedMultihash([]byte("updateReveal")),
	}, nil
}

func getSuffixData(privateKey *ecdsa.PrivateKey) (*model.SuffixDataModel, error) {
	jwk, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &model.SuffixDataModel{
		DeltaHash:          getEncodedMultihash([]byte(validDoc)),
		RecoveryKey:        jwk,
		RecoveryCommitment: getEncodedMultihash([]byte("recoveryReveal")),
	}, nil
}

func getEncodedMultihash(data []byte) string {
	mh, err := docutil.ComputeMultihash(sha2_256, data)
	if err != nil {
		panic(err)
	}
	return docutil.EncodeToString(mh)
}

func signModel(data interface{}, signer helper.Signer) (*model.JWS, error) {
	signedDataBytes, err := docutil.MarshalCanonical(data)
	if err != nil {
		return nil, err
	}

	payload := docutil.EncodeToString(signedDataBytes)

	return signPayload(payload, signer)
}

func signPayload(payload string, signer helper.Signer) (*model.JWS, error) {
	alg, ok := signer.Headers().Algorithm()
	if !ok || alg == "" {
		return nil, errors.New("signing algorithm is required")
	}

	kid, ok := signer.Headers().KeyID()
	if !ok || kid == "" {
		return nil, errors.New("signing kid is required")
	}

	jwsSignature, err := internal.NewJWS(signer.Headers(), nil, []byte(payload), signer)
	if err != nil {
		return nil, err
	}

	signature, err := jwsSignature.SerializeCompact(false)
	if err != nil {
		return nil, err
	}

	protected := &model.Header{
		Alg: alg,
		Kid: kid,
	}
	return &model.JWS{
		Protected: protected,
		Signature: signature,
		Payload:   payload,
	}, nil
}

const validDoc = `{
	"publicKey": [{
		  "id": "key1",
		  "type": "JwsVerificationKey2020",
		  "usage": ["ops", "general"],
		  "jwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		  }
	}]
}`

const recoveredDoc = `{
	"publicKey": [{
		  "id": "recovered",
		  "type": "JwsVerificationKey2020",
		  "usage": ["ops", "general"],
		  "jwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		  }
	}]
}`

const docTemplate = `{
  "publicKey": [
	{
  		"id": "%s",
  		"type": "JwsVerificationKey2020",
		"usage": ["ops"],
  		"jwk": %s
	}
  ]
}`
