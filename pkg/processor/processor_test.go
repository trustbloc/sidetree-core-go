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
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
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

	updateKeyID = "update-key"
)

func TestResolve(t *testing.T) {
	recoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	updateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pc := mocks.NewMockProtocolClient()

	t.Run("success", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
		op := New("test", store, pc)

		doc, err := op.Resolve(uniqueSuffix)
		require.Nil(t, err)
		require.NotNil(t, doc)
	})

	t.Run("document not found error", func(t *testing.T) {
		store, _ := getDefaultStore(recoveryKey, updateKey)

		op := New("test", store, pc)
		doc, err := op.Resolve(dummyUniqueSuffix)
		require.Nil(t, doc)
		require.Error(t, err)
		require.Equal(t, "uniqueSuffix not found in the store", err.Error())
	})

	t.Run("store error", func(t *testing.T) {
		testErr := errors.New("test store error")
		store := mocks.NewMockOperationStore(testErr)
		p := New("test", store, pc)

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

		createOp, err := getCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)
		createOp.Delta = &model.DeltaModel{
			Patches: []patch.Patch{jsonPatch},
		}

		err = store.Put(createOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(createOp.UniqueSuffix)
		require.Nil(t, doc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "valid create operation not found")
	})
	t.Run("create delta hash doesn't match delta error", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)

		createOp, err := getCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		delta, err := getDeltaModel(validDoc, "different")
		require.NoError(t, err)

		deltaBytes, err := canonicalizer.MarshalCanonical(delta)
		require.NoError(t, err)

		createOp.EncodedDelta = docutil.EncodeToString(deltaBytes)

		err = store.Put(createOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		doc, err := p.applyCreateOperation(createOp, &resolutionModel{})
		require.Nil(t, doc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "create delta doesn't match suffix data delta hash")
	})
}

func TestUpdateDocument(t *testing.T) {
	recoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	updateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pc := mocks.NewMockProtocolClient()

	var updateOp *batch.Operation

	t.Run("success", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		updateOp, updateKey, err = getUpdateOperation(updateKey, uniqueSuffix, 1)
		require.Nil(t, err)
		err = store.Put(updateOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		result, err := p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		// check if service type value is updated (done via json patch)
		didDoc := document.DidDocumentFromJSONLDObject(result.Document)
		require.Equal(t, "special1", didDoc["test"])

		// test consecutive update
		updateOp, updateKey, err = getUpdateOperation(updateKey, uniqueSuffix, 2)
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
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		updateOp, _, err := getUpdateOperation(updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		updateOp.SignedData = ""

		err = store.Put(updateOp)
		require.NoError(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "missing signed data")
	})

	t.Run("unmarshal signed data model error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		updateOp, _, err := getUpdateOperation(updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		signer := ecsigner.New(updateKey, "ES256", "update-kid")

		compactJWS, err := signutil.SignPayload([]byte("payload"), signer)
		require.NoError(t, err)

		updateOp.SignedData = compactJWS

		err = store.Put(updateOp)
		require.NoError(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "failed to unmarshal signed data model while applying update")
	})

	t.Run("invalid update commitment error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		updateOp, _, err := getUpdateOperation(recoveryKey, uniqueSuffix, 77)
		require.Nil(t, err)
		err = store.Put(updateOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Contains(t, err.Error(), "commitment generated from update key doesn't match update commitment")
		require.Nil(t, doc)
	})

	t.Run("invalid signature error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		// sign update operation with different  key (than one used in create)
		differentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		s := ecsigner.New(differentKey, "ES256", updateKeyID)
		updateOp, _, err := getUpdateOperationWithSigner(s, updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		err = store.Put(updateOp)
		require.NoError(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Contains(t, err.Error(), "ecdsa: invalid signature")
		require.Nil(t, doc)
	})

	t.Run("delta hash doesn't match delta error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		updateOp, _, err := getUpdateOperation(updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		updateOp.EncodedDelta = docutil.EncodeToString([]byte("other value"))

		err = store.Put(updateOp)
		require.NoError(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "update delta doesn't match delta hash")
	})
}

func TestProcessOperation(t *testing.T) {
	recoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	updateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pc := mocks.NewMockProtocolClient()

	t.Run("update is first operation error", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)

		const uniqueSuffix = "uniqueSuffix"
		updateOp, _, err := getUpdateOperation(updateKey, uniqueSuffix, 1)
		require.Nil(t, err)
		err = store.Put(updateOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Equal(t, "missing create operation", err.Error())
	})

	t.Run("create is second operation error", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)
		store.Validate = false

		createOp, err := getCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		p := New("test", store, pc)
		doc, err := p.applyCreateOperation(createOp, &resolutionModel{
			Doc: make(document.Document),
		})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Equal(t, "create has to be the first operation", err.Error())
	})

	t.Run("recover after deactivate error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		deactivateOp, err := getDeactivateOperation(recoveryKey, uniqueSuffix, 1)
		require.NoError(t, err)
		err = store.Put(deactivateOp)
		require.Nil(t, err)

		recoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix, 2)
		require.NoError(t, err)
		err = store.Put(recoverOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Contains(t, err.Error(), "recover can only be applied to an existing document")
		require.Nil(t, doc)
	})

	t.Run("invalid operation type error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		deactivateOp, err := getDeactivateOperation(recoveryKey, uniqueSuffix, 1)
		require.NoError(t, err)

		deactivateOp.Type = "invalid"

		err = store.Put(deactivateOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		doc, err := p.applyOperation(deactivateOp, &resolutionModel{Doc: make(document.Document)})
		require.Error(t, err)
		require.Equal(t, "operation type not supported for process operation", err.Error())
		require.Nil(t, doc)
	})
}

func TestDeactivate(t *testing.T) {
	recoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	recoveryPubKey, err := pubkey.GetPublicKeyJWK(&recoveryKey.PublicKey)
	require.NoError(t, err)

	updateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	updatePubKey, err := pubkey.GetPublicKeyJWK(&updateKey.PublicKey)
	require.NoError(t, err)

	pc := mocks.NewMockProtocolClient()

	t.Run("success", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		deactivateOp, err := getDeactivateOperation(recoveryKey, uniqueSuffix, 1)
		require.NoError(t, err)

		err = store.Put(deactivateOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Contains(t, err.Error(), "document was deactivated")
		require.Nil(t, doc)

		// deactivate same document again - error
		deactivateOp, err = getDeactivateOperation(recoveryKey, uniqueSuffix, 2)
		require.NoError(t, err)
		err = store.Put(deactivateOp)
		require.NoError(t, err)

		doc, err = p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Contains(t, err.Error(), "deactivate can only be applied to an existing document")
		require.Nil(t, doc)
	})

	t.Run("document not found error", func(t *testing.T) {
		store, _ := getDefaultStore(recoveryKey, updateKey)

		deactivateOp, err := getDeactivateOperation(recoveryKey, dummyUniqueSuffix, 0)
		require.NoError(t, err)
		err = store.Put(deactivateOp)
		require.NoError(t, err)

		p := New("test", store, pc)
		doc, err := p.applyDeactivateOperation(deactivateOp, &resolutionModel{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "deactivate can only be applied to an existing document")
		require.Nil(t, doc)
	})

	t.Run("missing signed data error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		deactivateOp, err := getDeactivateOperation(recoveryKey, uniqueSuffix, 1)
		require.NoError(t, err)

		deactivateOp.SignedData = ""

		err = store.Put(deactivateOp)
		require.NoError(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "missing signed data")
	})

	t.Run("unmarshal signed data model error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		deactivateOp, err := getDeactivateOperation(recoveryKey, uniqueSuffix, 1)
		require.NoError(t, err)

		signer := ecsigner.New(recoveryKey, "ES256", "")

		compactJWS, err := signutil.SignPayload([]byte("payload"), signer)
		require.NoError(t, err)

		deactivateOp.SignedData = compactJWS

		err = store.Put(deactivateOp)
		require.NoError(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "failed to unmarshal signed data model while applying deactivate")
	})

	t.Run("invalid signature error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		// sign recover operation with different recovery key (than one used in create)
		differentRecoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer := ecsigner.New(differentRecoveryKey, "ES256", "")
		deactivateOp, err := getDeactivateOperationWithSigner(signer, recoveryKey, uniqueSuffix, 1)
		require.NoError(t, err)
		err = store.Put(deactivateOp)
		require.NoError(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Contains(t, err.Error(), "ecdsa: invalid signature")
		require.Nil(t, doc)
	})

	t.Run("did suffix doesn't match signed value error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		deactivateOp, err := getDeactivateOperation(recoveryKey, uniqueSuffix, 1)
		require.NoError(t, err)

		s := ecsigner.New(recoveryKey, "ES256", "")

		jws, err := signutil.SignModel(&model.DeactivateSignedDataModel{
			DidSuffix:   "other",
			RecoveryKey: recoveryPubKey,
		}, s)
		require.NoError(t, err)

		deactivateOp.SignedData = jws

		err = store.Put(deactivateOp)
		require.NoError(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "did suffix doesn't match signed value")
	})

	t.Run("deactivate recovery reveal value doesn't match recovery commitment", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		deactivateOp, err := getDeactivateOperation(recoveryKey, uniqueSuffix, 1)
		require.NoError(t, err)

		s := ecsigner.New(recoveryKey, "ES256", "")

		jws, err := signutil.SignModel(&model.DeactivateSignedDataModel{
			DidSuffix:   uniqueSuffix,
			RecoveryKey: updatePubKey,
		}, s)
		require.NoError(t, err)

		deactivateOp.SignedData = jws

		err = store.Put(deactivateOp)
		require.NoError(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "commitment generated from recovery key doesn't match recovery commitment")
	})
}

func TestRecover(t *testing.T) {
	recoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	updateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pc := mocks.NewMockProtocolClient()

	var recoverOp *batch.Operation

	t.Run("success", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		recoverOp, recoveryKey, err = getRecoverOperation(recoveryKey, updateKey, uniqueSuffix, 1)
		require.NoError(t, err)
		err = store.Put(recoverOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		result, err := p.Resolve(uniqueSuffix)
		require.NoError(t, err)

		// test for recovered key
		docBytes, err := result.Document.Bytes()
		require.NoError(t, err)
		require.Contains(t, string(docBytes), "recovered")

		// apply recover again - consecutive recoveries are valid
		recoverOp, _, err = getRecoverOperation(recoveryKey, updateKey, uniqueSuffix, 2)
		require.NoError(t, err)
		err = store.Put(recoverOp)
		require.Nil(t, err)

		doc, err := p.Resolve(uniqueSuffix)
		require.NoError(t, err)
		require.NotNil(t, doc)
	})

	t.Run("missing signed data error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		recoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		recoverOp.SignedData = ""

		err = store.Put(recoverOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "missing signed data")
	})

	t.Run("unmarshal signed data model error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		recoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		signer := ecsigner.New(recoveryKey, "ES256", "")

		compactJWS, err := signutil.SignPayload([]byte("payload"), signer)
		require.NoError(t, err)

		recoverOp.SignedData = compactJWS

		err = store.Put(recoverOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "failed to unmarshal signed data model while applying recover")
	})

	t.Run("invalid signature error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		// sign recover operation with different recovery key (than one used in create)
		differentRecoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer := ecsigner.New(differentRecoveryKey, "ES256", "")
		recoverOp, _, err := getRecoverOperationWithSigner(signer, recoveryKey, updateKey, uniqueSuffix, 1)
		require.NoError(t, err)
		err = store.Put(recoverOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "ecdsa: invalid signature")
	})

	t.Run("invalid recovery commitment error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		privatePubKey, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
		require.NoError(t, err)

		store, uniqueSuffix := getDefaultStore(recoveryKey, privateKey)

		op, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix, 1)
		require.NoError(t, err)
		signedModel := model.RecoverSignedDataModel{
			RecoveryKey: privatePubKey,
		}
		op.SignedData, err = signutil.SignModel(signedModel, ecsigner.New(privateKey, "P-256", ""))

		err = store.Put(op)
		require.NoError(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Contains(t, err.Error(), "commitment generated from recovery key doesn't match recovery commitment")
		require.Nil(t, doc)
	})
	t.Run("delta hash doesn't match delta error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		recoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		recoverOp.EncodedDelta = docutil.EncodeToString([]byte("other value"))

		err = store.Put(recoverOp)
		require.Nil(t, err)

		p := New("test", store, pc)
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

func getUpdateOperation(privateKey *ecdsa.PrivateKey, uniqueSuffix string, operationNumber uint) (*batch.Operation, *ecdsa.PrivateKey, error) {
	s := ecsigner.New(privateKey, "ES256", updateKeyID)

	return getUpdateOperationWithSigner(s, privateKey, uniqueSuffix, operationNumber)
}

func getUpdateOperationWithSigner(s helper.Signer, privateKey *ecdsa.PrivateKey, uniqueSuffix string, operationNumber uint) (*batch.Operation, *ecdsa.PrivateKey, error) {
	p := map[string]interface{}{
		"op":    "replace",
		"path":  "/test",
		"value": "special" + strconv.Itoa(int(operationNumber)),
	}

	patchBytes, err := canonicalizer.MarshalCanonical([]map[string]interface{}{p})
	if err != nil {
		return nil, nil, err
	}

	jsonPatch, err := patch.NewJSONPatch(string(patchBytes))
	if err != nil {
		return nil, nil, err
	}

	nextUpdateKey, updateCommitment, err := generateKeyAndCommitment()
	if err != nil {
		return nil, nil, err
	}

	delta := &model.DeltaModel{
		UpdateCommitment: updateCommitment,
		Patches:          []patch.Patch{jsonPatch},
	}

	deltaBytes, err := canonicalizer.MarshalCanonical(delta)
	if err != nil {
		return nil, nil, err
	}

	updatePubKey, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	signedData := &model.UpdateSignedDataModel{
		DeltaHash: getEncodedMultihash(deltaBytes),
		UpdateKey: updatePubKey,
	}

	jws, err := signutil.SignModel(signedData, s)
	if err != nil {
		return nil, nil, err
	}

	operation := &batch.Operation{
		Namespace:         mocks.DefaultNS,
		ID:                "did:sidetree:" + uniqueSuffix,
		UniqueSuffix:      uniqueSuffix,
		EncodedDelta:      docutil.EncodeToString(deltaBytes),
		Delta:             delta,
		Type:              batch.OperationTypeUpdate,
		TransactionNumber: uint64(operationNumber),
		SignedData:        jws,
	}

	return operation, nextUpdateKey, nil
}

func generateKeyAndCommitment() (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}

	pubKey, err := pubkey.GetPublicKeyJWK(&key.PublicKey)
	if err != nil {
		return nil, "", err
	}

	c, err := commitment.Calculate(pubKey, sha2_256)
	if err != nil {
		return nil, "", err
	}

	return key, c, nil
}

func getDeactivateOperation(privateKey *ecdsa.PrivateKey, uniqueSuffix string, operationNumber uint) (*batch.Operation, error) {
	signer := ecsigner.New(privateKey, "ES256", "")

	return getDeactivateOperationWithSigner(signer, privateKey, uniqueSuffix, operationNumber)
}

func getDeactivateOperationWithSigner(singer helper.Signer, privateKey *ecdsa.PrivateKey, uniqueSuffix string, operationNumber uint) (*batch.Operation, error) {
	recoverPubKey, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	signedDataModel := model.DeactivateSignedDataModel{
		DidSuffix:   uniqueSuffix,
		RecoveryKey: recoverPubKey,
	}

	jws, err := signutil.SignModel(signedDataModel, singer)
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		Namespace:         mocks.DefaultNS,
		ID:                "did:sidetree:" + uniqueSuffix,
		UniqueSuffix:      uniqueSuffix,
		Type:              batch.OperationTypeDeactivate,
		TransactionTime:   0,
		TransactionNumber: uint64(operationNumber),
		SignedData:        jws,
	}, nil
}

func getRecoverOperation(recoveryKey, updateKey *ecdsa.PrivateKey, uniqueSuffix string, operationNumber uint) (*batch.Operation, *ecdsa.PrivateKey, error) {
	signer := ecsigner.New(recoveryKey, "ES256", "")

	return getRecoverOperationWithSigner(signer, recoveryKey, updateKey, uniqueSuffix, operationNumber)
}

func getRecoverOperationWithSigner(signer helper.Signer, recoveryKey, updateKey *ecdsa.PrivateKey, uniqueSuffix string, operationNumber uint) (*batch.Operation, *ecdsa.PrivateKey, error) {
	recoverRequest, nextRecoveryKey, err := getDefaultRecoverRequest(signer, recoveryKey, updateKey)
	if err != nil {
		return nil, nil, err
	}

	operationBuffer, err := json.Marshal(recoverRequest)
	if err != nil {
		return nil, nil, err
	}

	_, updateCommitment, err := generateKeyAndCommitment()
	if err != nil {
		return nil, nil, err
	}

	delta, err := getDeltaModel(recoveredDoc, updateCommitment)
	if err != nil {
		return nil, nil, err
	}

	return &batch.Operation{
		Namespace:         mocks.DefaultNS,
		UniqueSuffix:      uniqueSuffix,
		Type:              batch.OperationTypeRecover,
		OperationBuffer:   operationBuffer,
		Delta:             delta,
		EncodedDelta:      recoverRequest.Delta,
		SignedData:        recoverRequest.SignedData,
		TransactionTime:   0,
		TransactionNumber: uint64(operationNumber),
	}, nextRecoveryKey, nil
}

func getRecoverRequest(signer helper.Signer, deltaModel *model.DeltaModel, signedDataModel *model.RecoverSignedDataModel) (*model.RecoverRequest, error) {
	deltaBytes, err := canonicalizer.MarshalCanonical(deltaModel)
	if err != nil {
		return nil, err
	}

	signedDataModel.DeltaHash = getEncodedMultihash(deltaBytes)

	jws, err := signutil.SignModel(signedDataModel, signer)
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

func getDefaultRecoverRequest(signer helper.Signer, recoveryKey, updateKey *ecdsa.PrivateKey) (*model.RecoverRequest, *ecdsa.PrivateKey, error) {
	updateCommitment, err := getCommitment(updateKey)
	if err != nil {
		return nil, nil, err
	}

	delta, err := getDeltaModel(recoveredDoc, updateCommitment)
	if err != nil {
		return nil, nil, err
	}

	deltaBytes, err := canonicalizer.MarshalCanonical(delta)
	if err != nil {
		return nil, nil, err
	}

	recoveryPubKey, err := pubkey.GetPublicKeyJWK(&recoveryKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	nextRecoveryKey, recoveryCommitment, err := generateKeyAndCommitment()
	if err != nil {
		return nil, nil, err
	}

	recoverSignedData := &model.RecoverSignedDataModel{
		RecoveryKey:        recoveryPubKey,
		RecoveryCommitment: recoveryCommitment,
		DeltaHash:          getEncodedMultihash(deltaBytes),
	}

	req, err := getRecoverRequest(signer, delta, recoverSignedData)
	if err != nil {
		return nil, nil, err
	}

	return req, nextRecoveryKey, nil
}

func getDefaultStore(recoveryKey, updateKey *ecdsa.PrivateKey) (*mocks.MockOperationStore, string) {
	store := mocks.NewMockOperationStore(nil)

	createOp, err := getCreateOperation(recoveryKey, updateKey)
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

func getCreateOperationWithDoc(recoveryKey, updateKey *ecdsa.PrivateKey, doc string) (*batch.Operation, error) {
	createRequest, err := getCreateRequest(recoveryKey, updateKey)
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

	updateCommitment, err := getCommitment(updateKey)
	if err != nil {
		return nil, err
	}

	delta, err := getDeltaModel(doc, updateCommitment)
	if err != nil {
		return nil, err
	}

	deltaBytes, err := canonicalizer.MarshalCanonical(delta)
	if err != nil {
		return nil, err
	}

	suffixData, err := getSuffixData(recoveryKey, deltaBytes)
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		Namespace:         mocks.DefaultNS,
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

func getCreateOperation(recoveryKey, updateKey *ecdsa.PrivateKey) (*batch.Operation, error) {
	return getCreateOperationWithDoc(recoveryKey, updateKey, validDoc)
}

func getCreateRequest(recoveryKey, updateKey *ecdsa.PrivateKey) (*model.CreateRequest, error) {
	updateCommitment, err := getCommitment(updateKey)
	if err != nil {
		return nil, err
	}

	delta, err := getDeltaModel(validDoc, updateCommitment)
	if err != nil {
		return nil, err
	}

	deltaBytes, err := canonicalizer.MarshalCanonical(delta)
	if err != nil {
		return nil, err
	}

	suffixData, err := getSuffixData(recoveryKey, deltaBytes)
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

func getDeltaModel(doc string, updateCommitment string) (*model.DeltaModel, error) {
	patches, err := patch.PatchesFromDocument(doc)
	if err != nil {
		return nil, err
	}

	return &model.DeltaModel{
		Patches:          patches,
		UpdateCommitment: updateCommitment,
	}, nil
}

func getCommitment(key *ecdsa.PrivateKey) (string, error) {
	pubKey, err := pubkey.GetPublicKeyJWK(&key.PublicKey)
	if err != nil {
		return "", err
	}

	c, err := commitment.Calculate(pubKey, sha2_256)
	if err != nil {
		return "", err
	}

	return c, nil
}

func getSuffixData(privateKey *ecdsa.PrivateKey, delta []byte) (*model.SuffixDataModel, error) {
	recoveryCommitment, err := getCommitment(privateKey)
	if err != nil {
		return nil, err
	}

	return &model.SuffixDataModel{
		DeltaHash:          getEncodedMultihash(delta),
		RecoveryCommitment: recoveryCommitment,
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
		  "purpose": ["ops", "general"],
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
		  "purpose": ["ops", "general"],
		  "jwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		  }
	}]
}`
