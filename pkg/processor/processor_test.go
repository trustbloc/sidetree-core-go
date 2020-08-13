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
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/signutil"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/operation"
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

	t.Run("protocol error", func(t *testing.T) {
		pcWithErr := mocks.NewMockProtocolClient()
		pcWithErr.Versions = []protocol.Protocol{}

		store, _ := getDefaultStore(recoveryKey, updateKey)
		op := New("test", store, pcWithErr)

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		doc, err := op.applyOperation(createOp, &resolutionModel{})
		require.Nil(t, doc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "apply 'create' operation: protocol parameters are not defined for blockchain time")
	})

	t.Run("resolution error", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)

		jsonPatch, err := patch.NewJSONPatch("[]")
		require.NoError(t, err)
		jsonPatch["patches"] = "invalid"

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		deltaBytes, err := json.Marshal(&model.DeltaModel{
			Patches: []patch.Patch{jsonPatch},
		})

		createOp.Delta = docutil.EncodeToString(deltaBytes)

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

		createOp.Delta = docutil.EncodeToString(deltaBytes)

		anchoredOp := getAnchoredOperation(createOp)
		err = store.Put(anchoredOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		doc, err := p.applyCreateOperation(anchoredOp, pc.Protocol, &resolutionModel{})
		require.Nil(t, doc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "create delta doesn't match suffix data delta hash")
	})
}

func TestUpdateDocument(t *testing.T) {
	recoveryKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, e)

	updateKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, e)

	pc := mocks.NewMockProtocolClient()

	t.Run("success", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		updateOp, nextUpdateKey, err := getAnchoredUpdateOperation(updateKey, uniqueSuffix, 1)
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
		updateOp, nextUpdateKey, err = getAnchoredUpdateOperation(nextUpdateKey, uniqueSuffix, 2)
		require.Nil(t, err)
		err = store.Put(updateOp)
		require.Nil(t, err)

		result, err = p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		// check if service type value is updated again (done via json patch)
		didDoc = document.DidDocumentFromJSONLDObject(result.Document)
		require.Equal(t, "special2", didDoc["test"])
	})

	t.Run("success -  operation with reused next commitment ignored", func(t *testing.T) {
		// scenario: update 1 followed by update 2 followed by update 3 with reused commitment from 1

		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		updateOp, nextUpdateKey, err := getAnchoredUpdateOperation(updateKey, uniqueSuffix, 1)
		require.Nil(t, err)

		delta1, err := operation.ParseDelta(updateOp.Delta, pc.Protocol)
		require.NoError(t, err)

		err = store.Put(updateOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		result, err := p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		// check if service type value is updated (done via json patch)
		didDoc := document.DidDocumentFromJSONLDObject(result.Document)
		require.Equal(t, "special1", didDoc["test"])

		// test consecutive update
		updateOp, nextUpdateKey, err = getAnchoredUpdateOperation(nextUpdateKey, uniqueSuffix, 2)
		require.Nil(t, err)

		err = store.Put(updateOp)
		require.Nil(t, err)

		result, err = p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		// service type value is updated since operation is valid
		didDoc = document.DidDocumentFromJSONLDObject(result.Document)
		require.Equal(t, "special2", didDoc["test"])

		// two successful update operations - next update with reused commitment from op 1
		updateOp, nextUpdateKey, err = getAnchoredUpdateOperation(nextUpdateKey, uniqueSuffix, 1)
		require.Nil(t, err)

		delta3, err := operation.ParseDelta(updateOp.Delta, pc.Protocol)
		require.NoError(t, err)
		delta3.UpdateCommitment = delta1.UpdateCommitment

		delta3Bytes, err := canonicalizer.MarshalCanonical(delta3)
		require.NoError(t, err)

		updateOp.Delta = docutil.EncodeToString(delta3Bytes)

		err = store.Put(updateOp)
		require.Nil(t, err)

		result, err = p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		// service type value is not updated since commitment value was reused
		didDoc = document.DidDocumentFromJSONLDObject(result.Document)
		require.Equal(t, "special2", didDoc["test"])
	})

	t.Run("success - operation with same commitment as next operation commitment is ignored", func(t *testing.T) {
		// scenario: update 1 followed by update 2 with same operation commitment as next operation commitment

		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		updateOp, nextUpdateKey, err := getAnchoredUpdateOperation(updateKey, uniqueSuffix, 1)
		require.Nil(t, err)

		delta1, err := operation.ParseDelta(updateOp.Delta, pc.Protocol)
		require.NoError(t, err)

		err = store.Put(updateOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		result, err := p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		// check if service type value is updated (done via json patch)
		didDoc := document.DidDocumentFromJSONLDObject(result.Document)
		require.Equal(t, "special1", didDoc["test"])

		// update operation commitment is the same as next operation commitment
		updateOp, nextUpdateKey, err = getAnchoredUpdateOperation(nextUpdateKey, uniqueSuffix, 1)
		require.Nil(t, err)

		delta2, err := operation.ParseDelta(updateOp.Delta, pc.Protocol)
		require.NoError(t, err)
		delta2.UpdateCommitment = delta1.UpdateCommitment

		delta2Bytes, err := canonicalizer.MarshalCanonical(delta2)
		require.NoError(t, err)

		updateOp.Delta = docutil.EncodeToString(delta2Bytes)

		err = store.Put(updateOp)
		require.Nil(t, err)

		result, err = p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		// service type value is not updated since commitment value was reused
		didDoc = document.DidDocumentFromJSONLDObject(result.Document)
		require.Equal(t, "special1", didDoc["test"])
	})

	t.Run("missing signed data error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
		p := New("test", store, pc)

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		rm, err := p.applyOperation(createOp, &resolutionModel{})
		require.NoError(t, err)

		updateOp, _, err := getAnchoredUpdateOperation(updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		updateOp.SignedData = ""

		rm, err = p.applyOperation(updateOp, rm)
		require.Error(t, err)
		require.Nil(t, rm)
		require.Contains(t, err.Error(), "missing signed data")
	})

	t.Run("unmarshal signed data model error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
		p := New("test", store, pc)

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		rm, err := p.applyOperation(createOp, &resolutionModel{})
		require.NoError(t, err)

		updateOp, _, err := getAnchoredUpdateOperation(updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		signer := ecsigner.New(updateKey, "ES256", "update-kid")

		compactJWS, err := signutil.SignPayload([]byte("payload"), signer)
		require.NoError(t, err)

		updateOp.SignedData = compactJWS

		rm, err = p.applyOperation(updateOp, rm)
		require.Error(t, err)
		require.Nil(t, rm)
		require.Contains(t, err.Error(), "failed to unmarshal signed data model while applying update")
	})

	t.Run("invalid update commitment error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
		p := New("test", store, pc)

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		rm, err := p.applyOperation(createOp, &resolutionModel{})
		require.NoError(t, err)

		updateOp, _, err := getAnchoredUpdateOperation(recoveryKey, uniqueSuffix, 77)
		require.Nil(t, err)

		rm, err = p.applyOperation(updateOp, rm)
		require.Error(t, err)
		require.Nil(t, rm)
		require.Contains(t, err.Error(), "commitment generated from update key doesn't match update commitment")
	})

	t.Run("invalid signature error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
		p := New("test", store, pc)

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		rm, err := p.applyOperation(createOp, &resolutionModel{})
		require.NoError(t, err)

		// sign update operation with different  key (than one used in create)
		differentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		s := ecsigner.New(differentKey, "ES256", updateKeyID)
		updateOp, _, err := getUpdateOperationWithSigner(s, updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		anchoredOp := getAnchoredOperation(updateOp)

		rm, err = p.applyOperation(anchoredOp, rm)
		require.Error(t, err)
		require.Nil(t, rm)
		require.Contains(t, err.Error(), "ecdsa: invalid signature")
	})

	t.Run("delta hash doesn't match delta error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
		p := New("test", store, pc)

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		rm, err := p.applyOperation(createOp, &resolutionModel{})
		require.NoError(t, err)

		updateOp, _, err := getAnchoredUpdateOperation(updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		updateOp.Delta = docutil.EncodeToString([]byte("other value"))

		rm, err = p.applyOperation(updateOp, rm)
		require.Error(t, err)
		require.Nil(t, rm)
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
		updateOp, _, err := getAnchoredUpdateOperation(updateKey, uniqueSuffix, 1)
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

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		p := New("test", store, pc)
		doc, err := p.applyCreateOperation(createOp, pc.Protocol, &resolutionModel{
			Doc: make(document.Document),
		})
		require.Error(t, err)
		require.Nil(t, doc)
		require.Equal(t, "create has to be the first operation", err.Error())
	})

	t.Run("apply recover to non existing document error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
		recoverOp, _, err := getAnchoredRecoverOperation(recoveryKey, updateKey, uniqueSuffix, 2)
		require.NoError(t, err)
		err = store.Put(recoverOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		doc, err := p.applyOperation(recoverOp, &resolutionModel{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "recover can only be applied to an existing document")
		require.Nil(t, doc)
	})

	t.Run("invalid operation type error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		deactivateOp, err := getDeactivateOperation(recoveryKey, uniqueSuffix)
		require.NoError(t, err)

		deactivateOp.Type = "invalid"

		anchoredOp := getAnchoredOperation(deactivateOp)

		p := New("test", store, pc)
		doc, err := p.applyOperation(anchoredOp, &resolutionModel{Doc: make(document.Document)})
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

		deactivateOp, err := getAnchoredDeactivateOperation(recoveryKey, uniqueSuffix)
		require.NoError(t, err)

		err = store.Put(deactivateOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(uniqueSuffix)
		require.Error(t, err)
		require.Contains(t, err.Error(), "document was deactivated")
		require.Nil(t, doc)
	})

	t.Run("deactivate can only be applied to an existing document", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		deactivateOp, err := getAnchoredDeactivateOperation(recoveryKey, uniqueSuffix)
		require.NoError(t, err)

		p := New("test", store, pc)
		doc, err := p.applyOperation(deactivateOp, &resolutionModel{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "deactivate can only be applied to an existing document")
		require.Nil(t, doc)
	})

	t.Run("document not found error", func(t *testing.T) {
		store, _ := getDefaultStore(recoveryKey, updateKey)

		deactivateOp, err := getAnchoredDeactivateOperation(recoveryKey, dummyUniqueSuffix)
		require.NoError(t, err)
		err = store.Put(deactivateOp)
		require.NoError(t, err)

		p := New("test", store, pc)
		doc, err := p.applyDeactivateOperation(deactivateOp, pc.Protocol, &resolutionModel{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "deactivate can only be applied to an existing document")
		require.Nil(t, doc)
	})

	t.Run("missing signed data error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
		p := New("test", store, pc)

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		rm, err := p.applyOperation(createOp, &resolutionModel{})
		require.NoError(t, err)

		deactivateOp, err := getDeactivateOperation(recoveryKey, uniqueSuffix)
		require.NoError(t, err)

		deactivateOp.SignedData = ""

		anchoredOp := getAnchoredOperation(deactivateOp)

		rm, err = p.applyOperation(anchoredOp, rm)
		require.Error(t, err)
		require.Nil(t, rm)
		require.Contains(t, err.Error(), "missing signed data")
	})

	t.Run("unmarshal signed data model error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
		p := New("test", store, pc)

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		rm, err := p.applyOperation(createOp, &resolutionModel{})
		require.NoError(t, err)

		deactivateOp, err := getDeactivateOperation(recoveryKey, uniqueSuffix)
		require.NoError(t, err)

		signer := ecsigner.New(recoveryKey, "ES256", "")

		compactJWS, err := signutil.SignPayload([]byte("payload"), signer)
		require.NoError(t, err)

		deactivateOp.SignedData = compactJWS

		anchoredOp := getAnchoredOperation(deactivateOp)

		rm, err = p.applyOperation(anchoredOp, rm)
		require.Error(t, err)
		require.Nil(t, rm)
		require.Contains(t, err.Error(), "failed to parse signed data model while applying deactivate")
	})

	t.Run("invalid signature error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
		p := New("test", store, pc)

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		rm, err := p.applyOperation(createOp, &resolutionModel{})
		require.NoError(t, err)

		// sign recover operation with different recovery key (than one used in create)
		differentRecoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer := ecsigner.New(differentRecoveryKey, "ES256", "")
		deactivateOp, err := getDeactivateOperationWithSigner(signer, recoveryKey, uniqueSuffix)
		require.NoError(t, err)

		anchoredOp := getAnchoredOperation(deactivateOp)

		rm, err = p.applyOperation(anchoredOp, rm)
		require.Error(t, err)
		require.Contains(t, err.Error(), "ecdsa: invalid signature")
		require.Nil(t, rm)
	})

	t.Run("did suffix doesn't match signed value error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
		p := New("test", store, pc)

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		rm, err := p.applyOperation(createOp, &resolutionModel{})
		require.NoError(t, err)

		deactivateOp, err := getDeactivateOperation(recoveryKey, uniqueSuffix)
		require.NoError(t, err)

		s := ecsigner.New(recoveryKey, "ES256", "")

		jws, err := signutil.SignModel(&model.DeactivateSignedDataModel{
			DidSuffix:   "other",
			RecoveryKey: recoveryPubKey,
		}, s)
		require.NoError(t, err)

		deactivateOp.SignedData = jws

		anchoredOp := getAnchoredOperation(deactivateOp)

		rm, err = p.applyOperation(anchoredOp, rm)
		require.Error(t, err)
		require.Nil(t, rm)
		require.Contains(t, err.Error(), "did suffix doesn't match signed value")
	})

	t.Run("deactivate recovery reveal value doesn't match recovery commitment", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
		p := New("test", store, pc)

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		rm, err := p.applyOperation(createOp, &resolutionModel{})
		require.NoError(t, err)

		deactivateOp, err := getDeactivateOperation(recoveryKey, uniqueSuffix)
		require.NoError(t, err)

		s := ecsigner.New(recoveryKey, "ES256", "")

		jws, err := signutil.SignModel(&model.DeactivateSignedDataModel{
			DidSuffix:   uniqueSuffix,
			RecoveryKey: updatePubKey,
		}, s)
		require.NoError(t, err)

		deactivateOp.SignedData = jws

		anchoredOp := getAnchoredOperation(deactivateOp)

		rm, err = p.applyOperation(anchoredOp, rm)
		require.Error(t, err)
		require.Nil(t, rm)
		require.Contains(t, err.Error(), "commitment generated from recovery key doesn't match recovery commitment")
	})
}

func TestRecover(t *testing.T) {
	recoveryKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, e)

	updateKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, e)

	pc := mocks.NewMockProtocolClient()

	t.Run("success", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		recoverOp, nextRecoveryKey, err := getAnchoredRecoverOperation(recoveryKey, updateKey, uniqueSuffix, 1)
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
		recoverOp, _, err = getAnchoredRecoverOperation(nextRecoveryKey, updateKey, uniqueSuffix, 2)
		require.NoError(t, err)
		err = store.Put(recoverOp)
		require.Nil(t, err)

		doc, err := p.Resolve(uniqueSuffix)
		require.NoError(t, err)
		require.NotNil(t, doc)
	})

	t.Run("success - invalid recover operation rejected", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		invalidRecoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix)
		require.NoError(t, err)

		invalidRecoverOp.Delta = ""

		invalidAnchoredOp := getAnchoredOperation(invalidRecoverOp)

		err = store.Put(invalidAnchoredOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		result, err := p.Resolve(uniqueSuffix)
		require.NoError(t, err)

		// since recover operation is invalid resolved document should contain create key "key1"
		docBytes, err := result.Document.Bytes()
		require.NoError(t, err)
		require.Contains(t, string(docBytes), "key1")

		// now generate valid recovery operation with same recoveryKey
		recoverOp, _, err := getAnchoredRecoverOperation(recoveryKey, updateKey, uniqueSuffix, 2)
		err = store.Put(recoverOp)
		require.Nil(t, err)

		p = New("test", store, pc)
		result, err = p.Resolve(uniqueSuffix)
		require.NoError(t, err)

		// test for recovered key in resolved document
		docBytes, err = result.Document.Bytes()
		require.NoError(t, err)
		require.Contains(t, string(docBytes), "recovered")
	})

	t.Run("missing signed data error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
		p := New("test", store, pc)

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		rm, err := p.applyOperation(createOp, &resolutionModel{})
		require.NoError(t, err)

		recoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix)
		require.NoError(t, err)

		recoverOp.SignedData = ""

		anchoredOp := getAnchoredOperation(recoverOp)

		rm, err = p.applyOperation(anchoredOp, rm)
		require.Error(t, err)
		require.Nil(t, rm)
		require.Contains(t, err.Error(), "missing signed data")
	})

	t.Run("unmarshal signed data model error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
		p := New("test", store, pc)

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		rm, err := p.applyOperation(createOp, &resolutionModel{})
		require.NoError(t, err)

		recoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix)
		require.NoError(t, err)

		signer := ecsigner.New(recoveryKey, "ES256", "")

		compactJWS, err := signutil.SignPayload([]byte("payload"), signer)
		require.NoError(t, err)

		recoverOp.SignedData = compactJWS

		anchoredOp := getAnchoredOperation(recoverOp)

		rm, err = p.applyOperation(anchoredOp, rm)
		require.Error(t, err)
		require.Nil(t, rm)
		require.Contains(t, err.Error(), "failed to parse signed data model while applying recover")
	})

	t.Run("invalid signature error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
		p := New("test", store, pc)

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		rm, err := p.applyOperation(createOp, &resolutionModel{})
		require.NoError(t, err)

		// sign recover operation with different recovery key (than one used in create)
		differentRecoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signer := ecsigner.New(differentRecoveryKey, "ES256", "")
		recoverOp, _, err := getRecoverOperationWithSigner(signer, recoveryKey, updateKey, uniqueSuffix)
		require.NoError(t, err)

		anchoredOp := getAnchoredOperation(recoverOp)
		err = store.Put(anchoredOp)

		rm, err = p.applyOperation(anchoredOp, rm)
		require.Error(t, err)
		require.Nil(t, rm)
		require.Contains(t, err.Error(), "ecdsa: invalid signature")
	})

	t.Run("invalid recovery commitment error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		privatePubKey, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
		require.NoError(t, err)

		store, uniqueSuffix := getDefaultStore(recoveryKey, privateKey)
		p := New("test", store, pc)

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		rm, err := p.applyOperation(createOp, &resolutionModel{})
		require.NoError(t, err)

		recoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix)
		require.NoError(t, err)
		signedModel := model.RecoverSignedDataModel{
			RecoveryKey:        privatePubKey,
			RecoveryCommitment: getEncodedMultihash([]byte("different")),
			DeltaHash:          getEncodedMultihash([]byte("{}")),
		}
		recoverOp.SignedData, err = signutil.SignModel(signedModel, ecsigner.New(privateKey, "ES256", ""))

		anchoredOp := getAnchoredOperation(recoverOp)

		rm, err = p.applyOperation(anchoredOp, rm)
		require.Error(t, err)
		require.Nil(t, rm)
		require.Contains(t, err.Error(), "commitment generated from recovery key doesn't match recovery commitment")
	})
	t.Run("delta hash doesn't match delta error", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
		p := New("test", store, pc)

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		rm, err := p.applyOperation(createOp, &resolutionModel{})
		require.NoError(t, err)

		recoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix)
		require.NoError(t, err)

		recoverOp.Delta = docutil.EncodeToString([]byte("other value"))

		anchoredOp := getAnchoredOperation(recoverOp)

		rm, err = p.applyOperation(anchoredOp, rm)
		require.Error(t, err)
		require.Nil(t, rm)
		require.Contains(t, err.Error(), "recover delta doesn't match delta hash")
	})
}

func TestGetOperationCommitment(t *testing.T) {
	recoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	updateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pc := mocks.NewMockProtocolClient()

	store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
	p := New("test", store, pc)

	t.Run("success - recover", func(t *testing.T) {
		recoverOp, _, err := getAnchoredRecoverOperation(recoveryKey, updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		value, err := p.getOperationCommitment(recoverOp)
		require.NoError(t, err)
		require.NotEmpty(t, value)

		c, err := getCommitment(recoveryKey)
		require.NoError(t, err)
		require.Equal(t, c, value)
	})

	t.Run("success - update", func(t *testing.T) {
		updateOp, _, err := getAnchoredUpdateOperation(updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		value, err := p.getOperationCommitment(updateOp)
		require.NoError(t, err)
		require.NotEmpty(t, value)

		c, err := getCommitment(updateKey)
		require.NoError(t, err)
		require.Equal(t, c, value)
	})

	t.Run("success - deactivate", func(t *testing.T) {
		deactivateOp, err := getAnchoredDeactivateOperation(recoveryKey, uniqueSuffix)
		require.NoError(t, err)

		value, err := p.getOperationCommitment(deactivateOp)
		require.NoError(t, err)
		require.NotEmpty(t, value)

		c, err := getCommitment(recoveryKey)
		require.NoError(t, err)
		require.Equal(t, c, value)
	})

	t.Run("error - protocol error", func(t *testing.T) {
		pcWithoutProtocols := mocks.NewMockProtocolClient()
		pcWithoutProtocols.Versions = []protocol.Protocol{}
		store, _ := getDefaultStore(recoveryKey, updateKey)

		updateOp, _, err := getAnchoredUpdateOperation(updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		value, err := New("test", store, pcWithoutProtocols).getOperationCommitment(updateOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "protocol parameters are not defined for blockchain time")
	})

	t.Run("error - create operation doesn't have reveal value", func(t *testing.T) {
		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		value, err := p.getOperationCommitment(createOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "create operation doesn't have reveal value")
	})

	t.Run("error - missing signed data", func(t *testing.T) {
		recoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix)
		require.NoError(t, err)

		recoverOp.SignedData = ""

		anchoredOp := getAnchoredOperation(recoverOp)

		value, err := p.getOperationCommitment(anchoredOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "missing signed data")
	})

	t.Run("error - operation type not supported", func(t *testing.T) {
		recoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix)
		require.NoError(t, err)

		recoverOp.Type = "other"

		anchoredOp := getAnchoredOperation(recoverOp)

		value, err := p.getOperationCommitment(anchoredOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "operation type not supported for getting operation commitment")
	})

	t.Run("error - unmarshall signed models", func(t *testing.T) {
		// test recover signed model
		recoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix)
		require.NoError(t, err)

		recoverSigner := ecsigner.New(recoveryKey, "ES256", "")
		recoverCompactJWS, err := signutil.SignPayload([]byte("recover payload"), recoverSigner)
		require.NoError(t, err)

		recoverOp.SignedData = recoverCompactJWS

		anchoredOp := getAnchoredOperation(recoverOp)

		value, err := p.getOperationCommitment(anchoredOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "failed to unmarshal signed data model for recover")

		// test deactivate signed model
		deactivateOp, err := getDeactivateOperation(recoveryKey, uniqueSuffix)
		require.NoError(t, err)

		deactivateOp.SignedData = recoverCompactJWS

		anchoredOp = getAnchoredOperation(deactivateOp)

		value, err = p.getOperationCommitment(anchoredOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "failed to unmarshal signed data model for deactivate")

		// test deactivate signed model
		updateOp, _, err := getUpdateOperation(updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		updateSigner := ecsigner.New(recoveryKey, "ES256", "")
		updateCompactJWS, err := signutil.SignPayload([]byte("update payload"), updateSigner)
		require.NoError(t, err)

		updateOp.SignedData = updateCompactJWS

		anchoredOp = getAnchoredOperation(updateOp)

		value, err = p.getOperationCommitment(anchoredOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "failed to unmarshal signed data model for update")
	})
}

func TestGetNextOperationCommitment(t *testing.T) {
	recoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	updateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pc := mocks.NewMockProtocolClient()

	store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
	p := New("test", store, pc)

	t.Run("success - recover", func(t *testing.T) {
		recoverOp, nextRecoveryKey, err := getAnchoredRecoverOperation(recoveryKey, updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		value, err := p.getNextOperationCommitment(recoverOp)
		require.NoError(t, err)
		require.NotEmpty(t, value)

		c, err := getCommitment(nextRecoveryKey)
		require.NoError(t, err)
		require.Equal(t, c, value)
	})

	t.Run("success - update", func(t *testing.T) {
		updateOp, nextUpdateKey, err := getAnchoredUpdateOperation(updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		value, err := p.getNextOperationCommitment(updateOp)
		require.NoError(t, err)
		require.NotEmpty(t, value)

		c, err := getCommitment(nextUpdateKey)
		require.NoError(t, err)
		require.Equal(t, c, value)
	})

	t.Run("success - deactivate", func(t *testing.T) {
		deactivateOp, err := getAnchoredDeactivateOperation(recoveryKey, uniqueSuffix)
		require.NoError(t, err)

		value, err := p.getNextOperationCommitment(deactivateOp)
		require.NoError(t, err)
		require.Empty(t, value)
	})

	t.Run("error - protocol error", func(t *testing.T) {
		pcWithoutProtocols := mocks.NewMockProtocolClient()
		pcWithoutProtocols.Versions = []protocol.Protocol{}
		store, _ := getDefaultStore(recoveryKey, updateKey)

		updateOp, _, err := getAnchoredUpdateOperation(updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		value, err := New("test", store, pcWithoutProtocols).getNextOperationCommitment(updateOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "protocol parameters are not defined for blockchain time")
	})

	t.Run("error - create operation is currently not supported", func(t *testing.T) {
		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		value, err := p.getNextOperationCommitment(createOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "operation type not supported for getting next operation commitment")
	})

	t.Run("error - missing signed data", func(t *testing.T) {
		recoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix)
		require.NoError(t, err)

		recoverOp.SignedData = ""

		anchoredOp := getAnchoredOperation(recoverOp)

		value, err := p.getNextOperationCommitment(anchoredOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "missing signed data")
	})

	t.Run("error - invalid delta", func(t *testing.T) {
		updateOp, _, err := getAnchoredUpdateOperation(updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		updateOp.Delta = "whatever"

		value, err := p.getNextOperationCommitment(updateOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "failed to parse delta for update")
	})

	t.Run("error - operation type not supported", func(t *testing.T) {
		recoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix)
		require.NoError(t, err)

		recoverOp.Type = "other"

		anchoredOp := getAnchoredOperation(recoverOp)

		value, err := p.getNextOperationCommitment(anchoredOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "operation type not supported for getting next operation commitment")
	})

	t.Run("error - unmarshall signed model for recovery", func(t *testing.T) {
		// test recover signed model
		recoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix)
		require.NoError(t, err)

		recoverSigner := ecsigner.New(recoveryKey, "ES256", "")
		recoverCompactJWS, err := signutil.SignPayload([]byte("recover payload"), recoverSigner)
		require.NoError(t, err)

		recoverOp.SignedData = recoverCompactJWS

		anchoredOp := getAnchoredOperation(recoverOp)

		value, err := p.getNextOperationCommitment(anchoredOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "failed to unmarshal signed data model for recover")
	})
}

func TestOpsWithTxnGreaterThan(t *testing.T) {
	op1 := &batch.AnchoredOperation{
		TransactionTime:   1,
		TransactionNumber: 1,
	}

	op2 := &batch.AnchoredOperation{
		TransactionTime:   1,
		TransactionNumber: 2,
	}

	ops := []*batch.AnchoredOperation{op1, op2}

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

func getAnchoredUpdateOperation(privateKey *ecdsa.PrivateKey, uniqueSuffix string, operationNumber uint) (*batch.AnchoredOperation, *ecdsa.PrivateKey, error) {
	op, nextUpdateKey, err := getUpdateOperation(privateKey, uniqueSuffix, operationNumber)
	if err != nil {
		return nil, nil, err
	}

	return getAnchoredOperationWithBlockNum(op, uint64(operationNumber)), nextUpdateKey, nil
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
		Namespace:    mocks.DefaultNS,
		ID:           "did:sidetree:" + uniqueSuffix,
		UniqueSuffix: uniqueSuffix,
		Delta:        docutil.EncodeToString(deltaBytes),
		DeltaModel:   delta,
		Type:         batch.OperationTypeUpdate,
		SignedData:   jws,
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

func getDeactivateOperation(privateKey *ecdsa.PrivateKey, uniqueSuffix string) (*batch.Operation, error) {
	signer := ecsigner.New(privateKey, "ES256", "")

	return getDeactivateOperationWithSigner(signer, privateKey, uniqueSuffix)
}

func getAnchoredDeactivateOperation(privateKey *ecdsa.PrivateKey, uniqueSuffix string) (*batch.AnchoredOperation, error) {
	op, err := getDeactivateOperation(privateKey, uniqueSuffix)
	if err != nil {
		return nil, err
	}

	return getAnchoredOperation(op), nil
}

func getDeactivateOperationWithSigner(singer helper.Signer, privateKey *ecdsa.PrivateKey, uniqueSuffix string) (*batch.Operation, error) {
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
		Namespace:    mocks.DefaultNS,
		ID:           "did:sidetree:" + uniqueSuffix,
		UniqueSuffix: uniqueSuffix,
		Type:         batch.OperationTypeDeactivate,
		SignedData:   jws,
	}, nil
}

func getRecoverOperation(recoveryKey, updateKey *ecdsa.PrivateKey, uniqueSuffix string) (*batch.Operation, *ecdsa.PrivateKey, error) {
	signer := ecsigner.New(recoveryKey, "ES256", "")

	return getRecoverOperationWithSigner(signer, recoveryKey, updateKey, uniqueSuffix)
}

func getAnchoredRecoverOperation(recoveryKey, updateKey *ecdsa.PrivateKey, uniqueSuffix string, operationNumber uint) (*batch.AnchoredOperation, *ecdsa.PrivateKey, error) {
	op, nextRecoveryKey, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix)
	if err != nil {
		return nil, nil, err
	}

	return getAnchoredOperationWithBlockNum(op, uint64(operationNumber)), nextRecoveryKey, nil
}

func getRecoverOperationWithSigner(signer helper.Signer, recoveryKey, updateKey *ecdsa.PrivateKey, uniqueSuffix string) (*batch.Operation, *ecdsa.PrivateKey, error) {
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
		Namespace:       mocks.DefaultNS,
		UniqueSuffix:    uniqueSuffix,
		Type:            batch.OperationTypeRecover,
		OperationBuffer: operationBuffer,
		DeltaModel:      delta,
		Delta:           recoverRequest.Delta,
		SignedData:      recoverRequest.SignedData,
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

	createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
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
		Namespace:       mocks.DefaultNS,
		ID:              "did:sidetree:" + uniqueSuffix,
		UniqueSuffix:    uniqueSuffix,
		Type:            batch.OperationTypeCreate,
		OperationBuffer: operationBuffer,
		DeltaModel:      delta,
		Delta:           createRequest.Delta,
		SuffixDataModel: suffixData,
		SuffixData:      createRequest.SuffixData,
	}, nil
}

func getCreateOperation(recoveryKey, updateKey *ecdsa.PrivateKey) (*batch.Operation, error) {
	return getCreateOperationWithDoc(recoveryKey, updateKey, validDoc)
}

func getAnchoredCreateOperation(recoveryKey, updateKey *ecdsa.PrivateKey) (*batch.AnchoredOperation, error) {
	op, err := getCreateOperation(recoveryKey, updateKey)
	if err != nil {
		return nil, err
	}

	return getAnchoredOperation(op), nil
}

func getAnchoredOperation(op *batch.Operation) *batch.AnchoredOperation {
	return &batch.AnchoredOperation{
		Type:         op.Type,
		UniqueSuffix: op.UniqueSuffix,
		Delta:        op.Delta,
		SuffixData:   op.SuffixData,
		SignedData:   op.SignedData,
	}
}

func getAnchoredOperationWithBlockNum(op *batch.Operation, blockNum uint64) *batch.AnchoredOperation {
	anchored := getAnchoredOperation(op)
	anchored.TransactionTime = blockNum
	return anchored
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
		  "type": "JsonWebKey2020",
		  "purpose": ["general"],
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
		  "type": "JsonWebKey2020",
		  "purpose": ["general"],
		  "jwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		  }
	}]
}`
