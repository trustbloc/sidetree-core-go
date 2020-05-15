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
	"github.com/trustbloc/sidetree-core-go/pkg/internal/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/signutil"
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

	updateKey = "update-key"
)

func TestResolve(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(privateKey)
		op := New("test", store)

		doc, err := op.Resolve(uniqueSuffix)
		require.Nil(t, err)
		require.NotNil(t, doc)
	})

	t.Run("document not found error", func(t *testing.T) {
		store, _ := getDefaultStore(privateKey)

		op := New("test", store)
		doc, err := op.Resolve(dummyUniqueSuffix)
		require.Nil(t, doc)
		require.Error(t, err)
		require.Equal(t, "uniqueSuffix not found in the store", err.Error())
	})

	t.Run("store error", func(t *testing.T) {
		testErr := errors.New("test store error")
		store := mocks.NewMockOperationStore(testErr)
		p := New("test", store)

		doc, err := p.Resolve("suffix")
		require.Nil(t, doc)
		require.Error(t, err)
		require.Equal(t, testErr, err)
	})

	t.Run("resolution error", func(t *testing.T) {
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
	})
}

func TestUpdateDocument(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(privateKey)

		updateOp, err := getUpdateOperation(privateKey, uniqueSuffix, 1)
		require.Nil(t, err)
		err = store.Put(updateOp)
		require.Nil(t, err)

		p := New("test", store)
		result, err := p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		// check if service type value is updated (done via json patch)
		didDoc := document.DidDocumentFromJSONLDObject(result.Document)
		require.Equal(t, "special1", didDoc["test"])

		// test consecutive update
		updateOp, err = getUpdateOperation(privateKey, uniqueSuffix, 2)
		require.Nil(t, err)
		err = store.Put(updateOp)
		require.Nil(t, err)

		result, err = p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		// check if service type value is updated again (done via json patch)
		didDoc = document.DidDocumentFromJSONLDObject(result.Document)
		require.Equal(t, "special2", didDoc["test"])
	})

	t.Run("missing signed data error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(privateKey)

		updateOp, err := getUpdateOperation(privateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		updateOp.SignedData = ""

		err = store.Put(updateOp)
		require.NoError(t, err)

		p := New("test", store)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "missing signed data")
	})

	t.Run("invalid reveal value error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(privateKey)

		updateOp, err := getUpdateOperation(privateKey, uniqueSuffix, 77)
		require.Nil(t, err)
		err = store.Put(updateOp)
		require.Nil(t, err)

		p := New("test", store)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Contains(t, err.Error(), "supplied hash doesn't match original content")
		require.Nil(t, doc)
	})

	t.Run("invalid signature error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(privateKey)

		// sign update operation with different  key (than one used in create)
		differentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		updateOp, err := getUpdateOperation(differentKey, uniqueSuffix, 1)
		require.NoError(t, err)

		err = store.Put(updateOp)
		require.NoError(t, err)

		p := New("test", store)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Contains(t, err.Error(), "ecdsa: invalid signature")
		require.Nil(t, doc)
	})

	t.Run("signing key not in document error", func(t *testing.T) {
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
	})

	t.Run("delta hash doesn't match delta error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(privateKey)

		updateOp, err := getUpdateOperation(privateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		updateOp.EncodedDelta = docutil.EncodeToString([]byte("other value"))

		err = store.Put(updateOp)
		require.NoError(t, err)

		p := New("test", store)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "update delta doesn't match delta hash")
	})
}

func TestProcessOperation(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("update is first operation error", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)

		const uniqueSuffix = "uniqueSuffix"
		updateOp, err := getUpdateOperation(privateKey, uniqueSuffix, 1)
		require.Nil(t, err)
		err = store.Put(updateOp)
		require.Nil(t, err)

		p := New("test", store)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Equal(t, "missing create operation", err.Error())
	})

	t.Run("create is second operation error", func(t *testing.T) {
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
	})

	t.Run("recover after deactivate error", func(t *testing.T) {
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
	})

	t.Run("invalid operation type error", func(t *testing.T) {
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
	})
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

	t.Run("success", func(t *testing.T) {
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

		// deactivate same document again - error
		deactivateOp, err = getDeactivateOperation(privateKey, uniqueSuffix, 2)
		require.NoError(t, err)
		err = store.Put(deactivateOp)
		require.NoError(t, err)

		doc, err = p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Contains(t, err.Error(), "deactivate can only be applied to an existing document")
		require.Nil(t, doc)
	})

	t.Run("document not found error", func(t *testing.T) {
		store, _ := getDefaultStore(privateKey)

		deactivateOp, err := getDeactivateOperation(privateKey, dummyUniqueSuffix, 0)
		require.NoError(t, err)
		err = store.Put(deactivateOp)
		require.NoError(t, err)

		p := New("test", store)
		doc, err := p.Resolve(dummyUniqueSuffix)
		require.Error(t, err)
		require.Contains(t, err.Error(), "deactivate can only be applied to an existing document")
		require.Nil(t, doc)
	})

	t.Run("invalid recovery reveal value error", func(t *testing.T) {
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
	})

	t.Run("missing signed data error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(privateKey)

		deactivateOp, err := getDeactivateOperation(privateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		deactivateOp.SignedData = ""

		err = store.Put(deactivateOp)
		require.NoError(t, err)

		p := New("test", store)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "missing signed data")
	})

	t.Run("invalid signature error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(privateKey)

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
	})

	t.Run("did suffix doesn't match signed value error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(privateKey)

		deactivateOp, err := getDeactivateOperation(privateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		s := ecsigner.New(privateKey, "ES256", "")

		jws, err := signutil.SignModel(&model.DeactivateSignedDataModel{
			DidSuffix:           "other",
			RecoveryRevealValue: docutil.EncodeToString([]byte(recoveryReveal)),
		}, s)
		require.NoError(t, err)

		deactivateOp.SignedData = jws

		err = store.Put(deactivateOp)
		require.NoError(t, err)

		p := New("test", store)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "did suffix doesn't match signed value")
	})

	t.Run("recovery reveal value doesn't match signed value", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(privateKey)

		deactivateOp, err := getDeactivateOperation(privateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		s := ecsigner.New(privateKey, "ES256", "")

		jws, err := signutil.SignModel(&model.DeactivateSignedDataModel{
			DidSuffix:           uniqueSuffix,
			RecoveryRevealValue: docutil.EncodeToString([]byte("other")),
		}, s)
		require.NoError(t, err)

		deactivateOp.SignedData = jws

		err = store.Put(deactivateOp)
		require.NoError(t, err)

		p := New("test", store)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "recovery reveal value doesn't match signed value")
	})
}

func TestRecover(t *testing.T) {
	recoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey)

		recoverOp, err := getRecoverOperation(recoveryKey, uniqueSuffix, 1)
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

		// apply recover again - consecutive recoveries are valid
		recoverOp, err = getRecoverOperation(recoveryKey, uniqueSuffix, 2)
		require.NoError(t, err)
		err = store.Put(recoverOp)
		require.Nil(t, err)

		doc, err := p.Resolve(uniqueSuffix)
		require.NoError(t, err)
		require.NotNil(t, doc)
	})

	t.Run("missing signed data error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey)

		recoverOp, err := getRecoverOperation(recoveryKey, uniqueSuffix, 1)
		require.NoError(t, err)

		recoverOp.SignedData = ""

		err = store.Put(recoverOp)
		require.Nil(t, err)

		p := New("test", store)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "missing signed data")
	})

	t.Run("invalid signature error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey)

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
	})

	t.Run("invalid reveal value error", func(t *testing.T) {
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
	})
	t.Run("delta hash doesn't match delta error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey)

		recoverOp, err := getRecoverOperation(recoveryKey, uniqueSuffix, 1)
		require.NoError(t, err)

		recoverOp.EncodedDelta = docutil.EncodeToString([]byte("other value"))

		err = store.Put(recoverOp)
		require.Nil(t, err)

		p := New("test", store)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "recover delta doesn't match delta hash")
	})
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
		"path":  "/test",
		"value": "special" + strconv.Itoa(int(operationNumber)),
	}

	patchBytes, err := canonicalizer.MarshalCanonical([]map[string]interface{}{p})
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

	deltaBytes, err := canonicalizer.MarshalCanonical(delta)
	if err != nil {
		return nil, err
	}

	signedData := &model.UpdateSignedDataModel{
		DeltaHash: getEncodedMultihash(deltaBytes),
	}

	jws, err := signutil.SignModel(signedData, s)
	if err != nil {
		return nil, err
	}

	operation := &batch.Operation{
		ID:                "did:sidetree:" + uniqueSuffix,
		UniqueSuffix:      uniqueSuffix,
		EncodedDelta:      docutil.EncodeToString(deltaBytes),
		Delta:             delta,
		Type:              batch.OperationTypeUpdate,
		TransactionNumber: uint64(operationNumber),
		UpdateRevealValue: updateRevealValue,
		SignedData:        jws,
	}

	return operation, nil
}

func getUpdateOperation(privateKey *ecdsa.PrivateKey, uniqueSuffix string, operationNumber uint) (*batch.Operation, error) {
	s := ecsigner.New(privateKey, "ES256", updateKey)

	return getUpdateOperationWithSigner(s, uniqueSuffix, operationNumber)
}

func getDeactivateOperation(privateKey *ecdsa.PrivateKey, uniqueSuffix string, operationNumber uint) (*batch.Operation, error) {
	signedDataModel := model.DeactivateSignedDataModel{
		DidSuffix:           uniqueSuffix,
		RecoveryRevealValue: docutil.EncodeToString([]byte(recoveryReveal)),
	}

	s := ecsigner.New(privateKey, "ES256", "")

	jws, err := signutil.SignModel(signedDataModel, s)
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

	delta, err := getReplaceDelta(recoveredDoc, nextUpdateCommitmentHash)
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
		TransactionTime:     0,
		TransactionNumber:   uint64(operationNumber),
	}, nil
}

func getRecoverRequest(privateKey *ecdsa.PrivateKey, deltaModel *model.DeltaModel, signedDataModel *model.RecoverSignedDataModel) (*model.RecoverRequest, error) {
	deltaBytes, err := canonicalizer.MarshalCanonical(deltaModel)
	if err != nil {
		return nil, err
	}

	signedDataModel.DeltaHash = getEncodedMultihash(deltaBytes)

	jws, err := signutil.SignModel(signedDataModel, ecsigner.New(privateKey, "ES256", ""))
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
	delta, err := getReplaceDelta(recoveredDoc, getEncodedMultihash([]byte("updateReveal")))
	if err != nil {
		return nil, err
	}

	deltaBytes, err := canonicalizer.MarshalCanonical(delta)
	if err != nil {
		return nil, err
	}

	jwk, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	recoverSignedData := &model.RecoverSignedDataModel{
		RecoveryKey:        jwk,
		RecoveryCommitment: getEncodedMultihash([]byte("recoveryReveal")),
		DeltaHash:          getEncodedMultihash(deltaBytes),
	}

	return getRecoverRequest(privateKey, delta, recoverSignedData)
}

func getDefaultStore(recoveryKey *ecdsa.PrivateKey) (*mocks.MockOperationStore, string) {
	store := mocks.NewMockOperationStore(nil)

	createOp, err := getCreateOperation(recoveryKey)
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

	delta, err := getReplaceDelta(doc, nextUpdateCommitmentHash)
	if err != nil {
		return nil, err
	}

	suffixData, err := getSuffixData(privateKey)
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		ID:                "did:sidetree:" + uniqueSuffix,
		UniqueSuffix:      uniqueSuffix,
		Type:              batch.OperationTypeCreate,
		OperationBuffer:   operationBuffer,
		Delta:             delta,
		EncodedDelta:      createRequest.Delta,
		SuffixData:        suffixData,
		TransactionNumber: 0,
	}, nil
}

func getCreateOperation(recoveryKey *ecdsa.PrivateKey) (*batch.Operation, error) {
	// for test purposes use recovery key as update key
	publicKey, err := pubkey.GetPublicKeyJWK(&recoveryKey.PublicKey)
	if err != nil {
		return nil, err
	}

	publicKeyBytes, err := json.Marshal(publicKey)
	if err != nil {
		return nil, err
	}

	opaque := fmt.Sprintf(docTemplate, updateKey, string(publicKeyBytes))

	return getCreateOperationWithDoc(recoveryKey, opaque)
}

func getCreateRequest(privateKey *ecdsa.PrivateKey) (*model.CreateRequest, error) {
	delta, err := getReplaceDelta(validDoc, getEncodedMultihash([]byte("updateReveal")))
	if err != nil {
		return nil, err
	}

	deltaBytes, err := canonicalizer.MarshalCanonical(delta)
	if err != nil {
		return nil, err
	}

	suffixData, err := getSuffixData(privateKey)
	if err != nil {
		return nil, err
	}

	suffixDataBytes, err := canonicalizer.MarshalCanonical(suffixData)
	if err != nil {
		return nil, err
	}

	return &model.CreateRequest{
		Operation:  model.OperationTypeCreate,
		Delta:      docutil.EncodeToString(deltaBytes),
		SuffixData: docutil.EncodeToString(suffixDataBytes),
	}, nil
}

func getReplaceDelta(doc, updateCommitment string) (*model.DeltaModel, error) {
	patches, err := patch.PatchesFromDocument(doc)
	if err != nil {
		return nil, err
	}

	return &model.DeltaModel{
		Patches:          patches,
		UpdateCommitment: updateCommitment,
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
  ],
  "service": [
	{
	   "id": "oidc",
	   "type": "OpenIdConnectVersion1.0Service",
	   "serviceEndpoint": "https://openid.example.com/"
	}
  ]
}`
