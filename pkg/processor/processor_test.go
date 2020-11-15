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

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/signutil"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/client"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/doccomposer"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/operationapplier"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/operationparser"
)

const (
	sha2_256 = 18
	sha2_512 = 19

	dummyUniqueSuffix = "dummy"

	defaultBlockNumber = 0
)

func TestResolve(t *testing.T) {
	recoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	updateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pc := newMockProtocolClient()

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
		pcWithErr.Versions = nil

		store, _ := getDefaultStore(recoveryKey, updateKey)
		op := New("test", store, pcWithErr)

		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		doc, err := op.applyOperation(createOp, &protocol.ResolutionModel{})
		require.Nil(t, doc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "apply 'create' operation: protocol parameters are not defined for blockchain time")
	})

	t.Run("resolution error", func(t *testing.T) {
		store := mocks.NewMockOperationStore(nil)

		createOp, err := getCreateOperation(recoveryKey, updateKey, defaultBlockNumber)
		require.NoError(t, err)

		createOp.SuffixData = &model.SuffixDataModel{}

		err = store.Put(getAnchoredOperation(createOp, defaultBlockNumber))
		require.Nil(t, err)

		p := New("test", store, pc)
		doc, err := p.Resolve(createOp.UniqueSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "valid create operation not found")
	})
}

func TestUpdateDocument(t *testing.T) {
	recoveryKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, e)

	updateKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, e)

	// protocol version switches at block 100
	pc := newMockProtocolClient()

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
		didDoc := document.DidDocumentFromJSONLDObject(result.Doc)
		require.Equal(t, "special1", didDoc["test"])

		// test consecutive update
		updateOp, nextUpdateKey, err = getAnchoredUpdateOperation(nextUpdateKey, uniqueSuffix, 2)
		require.Nil(t, err)
		err = store.Put(updateOp)
		require.Nil(t, err)

		result, err = p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		// check if service type value is updated again (done via json patch)
		didDoc = document.DidDocumentFromJSONLDObject(result.Doc)
		require.Equal(t, "special2", didDoc["test"])
	})

	t.Run("success - protocol version changed between create/update", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		// protocol value for hashing algorithm changed at block 100
		updateOp, _, err := getAnchoredUpdateOperation(updateKey, uniqueSuffix, 200)
		require.Nil(t, err)

		err = store.Put(updateOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		result, err := p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		// check if service type value is updated (done via json patch)
		didDoc := document.DidDocumentFromJSONLDObject(result.Doc)
		require.Equal(t, "special200", didDoc["test"])
	})

	t.Run("success - protocol version changed between consecutive updates", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		updateOp, nextUpdateKey, err := getAnchoredUpdateOperation(updateKey, uniqueSuffix, 50)
		require.Nil(t, err)

		err = store.Put(updateOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		result, err := p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		// check if service type value is updated (done via json patch)
		didDoc := document.DidDocumentFromJSONLDObject(result.Doc)
		require.Equal(t, "special50", didDoc["test"])

		// protocol value for hashing algorithm changed at block 100
		updateOp, nextUpdateKey, err = getAnchoredUpdateOperation(nextUpdateKey, uniqueSuffix, 500)
		require.Nil(t, err)
		err = store.Put(updateOp)
		require.Nil(t, err)

		result, err = p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		didDoc = document.DidDocumentFromJSONLDObject(result.Doc)
		require.Equal(t, "special500", didDoc["test"])

		// test consecutive update within new protocol value
		updateOp, nextUpdateKey, err = getAnchoredUpdateOperation(nextUpdateKey, uniqueSuffix, 700)
		require.Nil(t, err)
		err = store.Put(updateOp)
		require.Nil(t, err)

		result, err = p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		// check if service type value is updated again (done via json patch)
		didDoc = document.DidDocumentFromJSONLDObject(result.Doc)
		require.Equal(t, "special700", didDoc["test"])
	})

	t.Run("success -  operation with reused next commitment ignored", func(t *testing.T) {
		// scenario: update 1 followed by update 2 followed by update 3 with reused commitment from 1

		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		updateOp, nextUpdateKey, err := getUpdateOperation(updateKey, uniqueSuffix, 1)
		require.Nil(t, err)

		delta1 := updateOp.Delta

		err = store.Put(getAnchoredOperation(updateOp, 1))
		require.Nil(t, err)

		p := New("test", store, pc)
		result, err := p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		// check if service type value is updated (done via json patch)
		didDoc := document.DidDocumentFromJSONLDObject(result.Doc)
		require.Equal(t, "special1", didDoc["test"])

		// test consecutive update
		updateOp, nextUpdateKey, err = getUpdateOperation(nextUpdateKey, uniqueSuffix, 2)
		require.Nil(t, err)

		err = store.Put(getAnchoredOperation(updateOp, 2))
		require.Nil(t, err)

		result, err = p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		// service type value is updated since operation is valid
		didDoc = document.DidDocumentFromJSONLDObject(result.Doc)
		require.Equal(t, "special2", didDoc["test"])

		// two successful update operations - next update with reused commitment from op 1
		updateOp, nextUpdateKey, err = getUpdateOperation(nextUpdateKey, uniqueSuffix, 1)
		require.Nil(t, err)

		delta3 := updateOp.Delta
		delta3.UpdateCommitment = delta1.UpdateCommitment

		err = store.Put(getAnchoredOperation(updateOp, 1))
		require.Nil(t, err)

		result, err = p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		// service type value is not updated since commitment value was reused
		didDoc = document.DidDocumentFromJSONLDObject(result.Doc)
		require.Equal(t, "special2", didDoc["test"])
	})

	t.Run("success - operation with same commitment as next operation commitment is ignored", func(t *testing.T) {
		// scenario: update 1 followed by update 2 with same operation commitment as next operation commitment

		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		updateOp, nextUpdateKey, err := getUpdateOperation(updateKey, uniqueSuffix, 1)
		require.Nil(t, err)

		delta1 := updateOp.Delta
		require.NoError(t, err)

		err = store.Put(getAnchoredOperation(updateOp, 1))
		require.Nil(t, err)

		p := New("test", store, pc)
		result, err := p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		// check if service type value is updated (done via json patch)
		didDoc := document.DidDocumentFromJSONLDObject(result.Doc)
		require.Equal(t, "special1", didDoc["test"])

		// update operation commitment is the same as next operation commitment
		updateOp, nextUpdateKey, err = getUpdateOperation(nextUpdateKey, uniqueSuffix, 1)
		require.Nil(t, err)

		delta2 := updateOp.Delta
		delta2.UpdateCommitment = delta1.UpdateCommitment

		err = store.Put(getAnchoredOperation(updateOp, 1))
		require.Nil(t, err)

		result, err = p.Resolve(uniqueSuffix)
		require.Nil(t, err)

		// service type value is not updated since commitment value was reused
		didDoc = document.DidDocumentFromJSONLDObject(result.Doc)
		require.Equal(t, "special1", didDoc["test"])
	})
}

func TestProcessOperation(t *testing.T) {
	recoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	updateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pc := newMockProtocolClient()
	parser := operationparser.New(pc.Protocol)

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

		a := operationapplier.New(pc.Protocol, parser, &mockDocComposer{})
		doc, err := a.Apply(createOp, &protocol.ResolutionModel{
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
		doc, err := p.applyOperation(recoverOp, &protocol.ResolutionModel{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "recover can only be applied to an existing document")
		require.Nil(t, doc)
	})

	t.Run("invalid operation type error", func(t *testing.T) {
		store, _ := getDefaultStore(recoveryKey, updateKey)

		p := New("test", store, pc)
		doc, err := p.applyOperation(&operation.AnchoredOperation{Type: "invalid"}, &protocol.ResolutionModel{Doc: make(document.Document)})
		require.Error(t, err)
		require.Equal(t, "operation type not supported for process operation", err.Error())
		require.Nil(t, doc)
	})
}

func TestDeactivate(t *testing.T) {
	recoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	updateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pc := newMockProtocolClient()

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
}

func TestRecover(t *testing.T) {
	recoveryKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, e)

	updateKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, e)

	pc := newMockProtocolClient()

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
		docBytes, err := result.Doc.Bytes()
		require.NoError(t, err)
		require.Contains(t, string(docBytes), "recovered1")

		// apply recover again - consecutive recoveries are valid
		recoverOp, _, err = getAnchoredRecoverOperation(nextRecoveryKey, updateKey, uniqueSuffix, 2)
		require.NoError(t, err)
		err = store.Put(recoverOp)
		require.Nil(t, err)

		result, err = p.Resolve(uniqueSuffix)
		require.NoError(t, err)
		require.NotNil(t, result)

		docBytes, err = result.Doc.Bytes()
		require.NoError(t, err)
		require.Contains(t, string(docBytes), "recovered2")
	})

	t.Run("success - protocol version changed between create and recover", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		// hashing algorithm changed at block 100
		recoverOp, nextRecoveryKey, err := getAnchoredRecoverOperation(recoveryKey, updateKey, uniqueSuffix, 200)
		require.NoError(t, err)
		err = store.Put(recoverOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		result, err := p.Resolve(uniqueSuffix)
		require.NoError(t, err)

		// test for recovered key
		docBytes, err := result.Doc.Bytes()
		require.NoError(t, err)
		require.Contains(t, string(docBytes), "recovered200")

		// apply recover again - consecutive recoveries within new protocol version
		recoverOp, _, err = getAnchoredRecoverOperation(nextRecoveryKey, updateKey, uniqueSuffix, 300)
		require.NoError(t, err)
		err = store.Put(recoverOp)
		require.Nil(t, err)

		result, err = p.Resolve(uniqueSuffix)
		require.NoError(t, err)
		require.NotNil(t, result)

		// test for recovered key
		docBytes, err = result.Doc.Bytes()
		require.NoError(t, err)
		require.Contains(t, string(docBytes), "recovered300")
	})

	t.Run("success - protocol version changed between recoveries", func(t *testing.T) {
		store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)

		recoverOp, nextRecoveryKey, err := getAnchoredRecoverOperation(recoveryKey, updateKey, uniqueSuffix, 50)
		require.NoError(t, err)
		err = store.Put(recoverOp)
		require.Nil(t, err)

		p := New("test", store, pc)
		result, err := p.Resolve(uniqueSuffix)
		require.NoError(t, err)

		// test for recovered key
		docBytes, err := result.Doc.Bytes()
		require.NoError(t, err)
		require.Contains(t, string(docBytes), "recovered50")

		// apply recover again - there was a protocol change at 100 (new hashing algorithm)
		recoverOp, _, err = getAnchoredRecoverOperation(nextRecoveryKey, updateKey, uniqueSuffix, 200)
		require.NoError(t, err)
		err = store.Put(recoverOp)
		require.Nil(t, err)

		result, err = p.Resolve(uniqueSuffix)
		require.NoError(t, err)
		require.NotNil(t, result)

		// test for recovered key
		docBytes, err = result.Doc.Bytes()
		require.NoError(t, err)
		require.Contains(t, string(docBytes), "recovered200")
	})
}

func TestGetOperationCommitment(t *testing.T) {
	recoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	updateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pc := newMockProtocolClient()

	store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
	p := New("test", store, pc)

	t.Run("success - recover", func(t *testing.T) {
		recoverOp, _, err := getAnchoredRecoverOperation(recoveryKey, updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		reveal, p, err := p.getRevealValue(recoverOp)
		require.NoError(t, err)
		require.NotNil(t, reveal)
		require.NotEmpty(t, p)

		value, err := commitment.Calculate(reveal, p.MultihashAlgorithm)
		require.NoError(t, err)

		c, err := getCommitment(recoveryKey, getProtocol(1))
		require.NoError(t, err)
		require.Equal(t, c, value)
	})

	t.Run("success - update", func(t *testing.T) {
		updateOp, _, err := getAnchoredUpdateOperation(updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		reveal, p, err := p.getRevealValue(updateOp)
		require.NoError(t, err)
		require.NotNil(t, reveal)

		value, err := commitment.Calculate(reveal, p.MultihashAlgorithm)
		require.NoError(t, err)

		c, err := getCommitment(updateKey, getProtocol(1))
		require.NoError(t, err)
		require.Equal(t, c, value)
	})

	t.Run("success - deactivate", func(t *testing.T) {
		deactivateOp, err := getAnchoredDeactivateOperation(recoveryKey, uniqueSuffix)
		require.NoError(t, err)

		reveal, p, err := p.getRevealValue(deactivateOp)
		require.NoError(t, err)
		require.NotNil(t, reveal)

		value, err := commitment.Calculate(reveal, p.MultihashAlgorithm)
		require.NoError(t, err)

		c, err := getCommitment(recoveryKey, getProtocol(1))
		require.NoError(t, err)
		require.Equal(t, c, value)
	})

	t.Run("error - protocol error", func(t *testing.T) {
		pcWithoutProtocols := mocks.NewMockProtocolClient()
		pcWithoutProtocols.Versions = nil
		store, _ := getDefaultStore(recoveryKey, updateKey)

		updateOp, _, err := getAnchoredUpdateOperation(updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		value, _, err := New("test", store, pcWithoutProtocols).getRevealValue(updateOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "protocol parameters are not defined for blockchain time")
	})

	t.Run("error - create operation doesn't have reveal value", func(t *testing.T) {
		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		value, p, err := p.getRevealValue(createOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Equal(t, p, protocol.Protocol{})
		require.Contains(t, err.Error(), "create operation doesn't have reveal value")
	})

	t.Run("error - missing signed data", func(t *testing.T) {
		recoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix)
		require.NoError(t, err)

		recoverOp.SignedData = ""

		anchoredOp := getAnchoredOperation(recoverOp, 1)

		value, p, err := p.getRevealValue(anchoredOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Equal(t, p, protocol.Protocol{})
		require.Contains(t, err.Error(), "missing signed data")
	})

	t.Run("error - unmarshall signed models", func(t *testing.T) {
		// test recover signed model
		recoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix)
		require.NoError(t, err)

		recoverSigner := ecsigner.New(recoveryKey, "ES256", "")
		recoverCompactJWS, err := signutil.SignPayload([]byte("recover payload"), recoverSigner)
		require.NoError(t, err)

		recoverOp.SignedData = recoverCompactJWS

		anchoredOp := getAnchoredOperation(recoverOp, 1)

		value, pv, err := p.getRevealValue(anchoredOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Equal(t, pv, protocol.Protocol{})
		require.Contains(t, err.Error(), "failed to unmarshal signed data model for recover")

		// test deactivate signed model
		deactivateOp, err := getDeactivateOperation(recoveryKey, uniqueSuffix)
		require.NoError(t, err)

		deactivateOp.SignedData = recoverCompactJWS

		anchoredOp = getAnchoredOperation(deactivateOp, 1)

		value, pv, err = p.getRevealValue(anchoredOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Equal(t, pv, protocol.Protocol{})
		require.Contains(t, err.Error(), "failed to unmarshal signed data model for deactivate")

		// test deactivate signed model
		updateOp, _, err := getUpdateOperation(updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		updateSigner := ecsigner.New(recoveryKey, "ES256", "")
		updateCompactJWS, err := signutil.SignPayload([]byte("update payload"), updateSigner)
		require.NoError(t, err)

		updateOp.SignedData = updateCompactJWS

		anchoredOp = getAnchoredOperation(updateOp, 1)

		value, pv, err = p.getRevealValue(anchoredOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Equal(t, pv, protocol.Protocol{})
		require.Contains(t, err.Error(), "failed to unmarshal signed data model for update")
	})
}

func TestGetNextOperationCommitment(t *testing.T) {
	recoveryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	updateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pc := newMockProtocolClient()

	store, uniqueSuffix := getDefaultStore(recoveryKey, updateKey)
	p := New("test", store, pc)

	t.Run("success - recover", func(t *testing.T) {
		recoverOp, nextRecoveryKey, err := getAnchoredRecoverOperation(recoveryKey, updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		value, err := p.getCommitment(recoverOp)
		require.NoError(t, err)
		require.NotEmpty(t, value)

		c, err := getCommitment(nextRecoveryKey, getProtocol(1))
		require.NoError(t, err)
		require.Equal(t, c, value)
	})

	t.Run("success - update", func(t *testing.T) {
		updateOp, nextUpdateKey, err := getAnchoredUpdateOperation(updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		value, err := p.getCommitment(updateOp)
		require.NoError(t, err)
		require.NotEmpty(t, value)

		c, err := getCommitment(nextUpdateKey, getProtocol(1))
		require.NoError(t, err)
		require.Equal(t, c, value)
	})

	t.Run("success - deactivate", func(t *testing.T) {
		deactivateOp, err := getAnchoredDeactivateOperation(recoveryKey, uniqueSuffix)
		require.NoError(t, err)

		value, err := p.getCommitment(deactivateOp)
		require.NoError(t, err)
		require.Empty(t, value)
	})

	t.Run("error - protocol error", func(t *testing.T) {
		pcWithoutProtocols := mocks.NewMockProtocolClient()
		pcWithoutProtocols.Versions = nil
		store, _ := getDefaultStore(recoveryKey, updateKey)

		updateOp, _, err := getAnchoredUpdateOperation(updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		value, err := New("test", store, pcWithoutProtocols).getCommitment(updateOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "protocol parameters are not defined for blockchain time")
	})

	t.Run("error - create operation is currently not supported", func(t *testing.T) {
		createOp, err := getAnchoredCreateOperation(recoveryKey, updateKey)
		require.NoError(t, err)

		value, err := p.getCommitment(createOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "operation type 'create' not supported for getting next operation commitment")
	})

	t.Run("error - missing signed data", func(t *testing.T) {
		recoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix)
		require.NoError(t, err)

		recoverOp.SignedData = ""

		anchoredOp := getAnchoredOperation(recoverOp, 1)

		value, err := p.getCommitment(anchoredOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "missing signed data")
	})

	t.Run("error - invalid delta", func(t *testing.T) {
		updateOp, _, err := getUpdateOperation(updateKey, uniqueSuffix, 1)
		require.NoError(t, err)

		updateOp.Delta = &model.DeltaModel{}

		value, err := p.getCommitment(getAnchoredOperation(updateOp, 1))
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "get commitment - parse operation error: missing patches")
	})

	t.Run("error - operation type not supported", func(t *testing.T) {
		request := model.RecoverRequest{
			Operation: "other",
		}

		bytes, err := canonicalizer.MarshalCanonical(request)
		require.NoError(t, err)

		value, err := p.getCommitment(&operation.AnchoredOperation{OperationBuffer: bytes})
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "operation type [other] not supported")
	})

	t.Run("error - unmarshall signed model for recovery", func(t *testing.T) {
		// test recover signed model
		recoverOp, _, err := getRecoverOperation(recoveryKey, updateKey, uniqueSuffix)
		require.NoError(t, err)

		recoverSigner := ecsigner.New(recoveryKey, "ES256", "")
		recoverCompactJWS, err := signutil.SignPayload([]byte("recover payload"), recoverSigner)
		require.NoError(t, err)

		recoverOp.SignedData = recoverCompactJWS

		anchoredOp := getAnchoredOperation(recoverOp, 1)

		value, err := p.getCommitment(anchoredOp)
		require.Error(t, err)
		require.Empty(t, value)
		require.Contains(t, err.Error(), "failed to unmarshal signed data model for recover")
	})
}

func TestOpsWithTxnGreaterThan(t *testing.T) {
	op1 := &operation.AnchoredOperation{
		TransactionTime:   1,
		TransactionNumber: 1,
	}

	op2 := &operation.AnchoredOperation{
		TransactionTime:   1,
		TransactionNumber: 2,
	}

	ops := []*operation.AnchoredOperation{op1, op2}

	txns := getOpsWithTxnGreaterThan(ops, 0, 0)
	require.Equal(t, 2, len(txns))

	txns = getOpsWithTxnGreaterThan(ops, 2, 1)
	require.Equal(t, 0, len(txns))

	txns = getOpsWithTxnGreaterThan(ops, 1, 1)
	require.Equal(t, 1, len(txns))
}

func getUpdateOperation(privateKey *ecdsa.PrivateKey, uniqueSuffix string, blockNum uint64) (*model.Operation, *ecdsa.PrivateKey, error) {
	s := ecsigner.New(privateKey, "ES256", "")

	return getUpdateOperationWithSigner(s, privateKey, uniqueSuffix, blockNum)
}

func getAnchoredUpdateOperation(privateKey *ecdsa.PrivateKey, uniqueSuffix string, blockNumber uint64) (*operation.AnchoredOperation, *ecdsa.PrivateKey, error) {
	op, nextUpdateKey, err := getUpdateOperation(privateKey, uniqueSuffix, blockNumber)
	if err != nil {
		return nil, nil, err
	}

	return getAnchoredOperation(op, blockNumber), nextUpdateKey, nil
}

func getUpdateOperationWithSigner(s client.Signer, privateKey *ecdsa.PrivateKey, uniqueSuffix string, blockNumber uint64) (*model.Operation, *ecdsa.PrivateKey, error) {
	p := map[string]interface{}{
		"op":    "replace",
		"path":  "/test",
		"value": "special" + strconv.Itoa(int(blockNumber)),
	}

	patchBytes, err := canonicalizer.MarshalCanonical([]map[string]interface{}{p})
	if err != nil {
		return nil, nil, err
	}

	jsonPatch, err := patch.NewJSONPatch(string(patchBytes))
	if err != nil {
		return nil, nil, err
	}

	nextUpdateKey, updateCommitment, err := generateKeyAndCommitment(getProtocol(blockNumber))
	if err != nil {
		return nil, nil, err
	}

	delta := &model.DeltaModel{
		UpdateCommitment: updateCommitment,
		Patches:          []patch.Patch{jsonPatch},
	}

	deltaHash, err := hashing.CalculateModelMultihash(delta, getProtocol(blockNumber).MultihashAlgorithm)
	if err != nil {
		return nil, nil, err
	}

	updatePubKey, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	signedData := &model.UpdateSignedDataModel{
		DeltaHash: deltaHash,
		UpdateKey: updatePubKey,
	}

	jws, err := signutil.SignModel(signedData, s)
	if err != nil {
		return nil, nil, err
	}

	op := &model.Operation{
		Namespace:    mocks.DefaultNS,
		ID:           "did:sidetree:" + uniqueSuffix,
		UniqueSuffix: uniqueSuffix,
		Delta:        delta,
		Type:         operation.TypeUpdate,
		SignedData:   jws,
	}

	return op, nextUpdateKey, nil
}

func generateKeyAndCommitment(p protocol.Protocol) (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}

	pubKey, err := pubkey.GetPublicKeyJWK(&key.PublicKey)
	if err != nil {
		return nil, "", err
	}

	c, err := commitment.Calculate(pubKey, p.MultihashAlgorithm)
	if err != nil {
		return nil, "", err
	}

	return key, c, nil
}

func getDeactivateOperation(privateKey *ecdsa.PrivateKey, uniqueSuffix string) (*model.Operation, error) {
	signer := ecsigner.New(privateKey, "ES256", "")

	return getDeactivateOperationWithSigner(signer, privateKey, uniqueSuffix)
}

func getAnchoredDeactivateOperation(privateKey *ecdsa.PrivateKey, uniqueSuffix string) (*operation.AnchoredOperation, error) {
	op, err := getDeactivateOperation(privateKey, uniqueSuffix)
	if err != nil {
		return nil, err
	}

	return getAnchoredOperation(op, defaultBlockNumber), nil
}

func getDeactivateOperationWithSigner(singer client.Signer, privateKey *ecdsa.PrivateKey, uniqueSuffix string) (*model.Operation, error) {
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

	return &model.Operation{
		Namespace:    mocks.DefaultNS,
		ID:           "did:sidetree:" + uniqueSuffix,
		UniqueSuffix: uniqueSuffix,
		Type:         operation.TypeDeactivate,
		SignedData:   jws,
	}, nil
}

func getRecoverOperation(recoveryKey, updateKey *ecdsa.PrivateKey, uniqueSuffix string) (*model.Operation, *ecdsa.PrivateKey, error) {
	return getRecoverOperationWithBlockNum(recoveryKey, updateKey, uniqueSuffix, 1)
}

func getRecoverOperationWithBlockNum(recoveryKey, updateKey *ecdsa.PrivateKey, uniqueSuffix string, blockNum uint64) (*model.Operation, *ecdsa.PrivateKey, error) {
	signer := ecsigner.New(recoveryKey, "ES256", "")

	return getRecoverOperationWithSigner(signer, recoveryKey, updateKey, uniqueSuffix, blockNum)
}

func getAnchoredRecoverOperation(recoveryKey, updateKey *ecdsa.PrivateKey, uniqueSuffix string, blockNumber uint64) (*operation.AnchoredOperation, *ecdsa.PrivateKey, error) {
	op, nextRecoveryKey, err := getRecoverOperationWithBlockNum(recoveryKey, updateKey, uniqueSuffix, blockNumber)
	if err != nil {
		return nil, nil, err
	}

	return getAnchoredOperation(op, blockNumber), nextRecoveryKey, nil
}

func getRecoverOperationWithSigner(signer client.Signer, recoveryKey, updateKey *ecdsa.PrivateKey, uniqueSuffix string, blockNum uint64) (*model.Operation, *ecdsa.PrivateKey, error) {
	recoverRequest, nextRecoveryKey, err := getDefaultRecoverRequest(signer, recoveryKey, updateKey, blockNum)
	if err != nil {
		return nil, nil, err
	}

	return &model.Operation{
		Namespace:       mocks.DefaultNS,
		UniqueSuffix:    uniqueSuffix,
		Type:            operation.TypeRecover,
		OperationBuffer: []byte(recoverRequest.Operation),
		Delta:           recoverRequest.Delta,
		SignedData:      recoverRequest.SignedData,
	}, nextRecoveryKey, nil
}

func getRecoverRequest(signer client.Signer, deltaModel *model.DeltaModel, signedDataModel *model.RecoverSignedDataModel, blockNum uint64) (*model.RecoverRequest, error) {
	deltaHash, err := hashing.CalculateModelMultihash(deltaModel, getProtocol(blockNum).MultihashAlgorithm)
	if err != nil {
		return nil, err
	}

	signedDataModel.DeltaHash = deltaHash

	jws, err := signutil.SignModel(signedDataModel, signer)
	if err != nil {
		return nil, err
	}

	return &model.RecoverRequest{
		Operation:  operation.TypeRecover,
		DidSuffix:  "suffix",
		Delta:      deltaModel,
		SignedData: jws,
	}, nil
}

func getDefaultRecoverRequest(signer client.Signer, recoveryKey, updateKey *ecdsa.PrivateKey, blockNum uint64) (*model.RecoverRequest, *ecdsa.PrivateKey, error) {
	p := getProtocol(blockNum)

	updateCommitment, err := getCommitment(updateKey, p)
	if err != nil {
		return nil, nil, err
	}

	recoveredDoc := fmt.Sprintf(recoveredDocTemplate, strconv.Itoa(int(blockNum)))

	delta, err := getDeltaModel(recoveredDoc, updateCommitment)
	if err != nil {
		return nil, nil, err
	}

	deltaHash, err := hashing.CalculateModelMultihash(delta, p.MultihashAlgorithm)
	if err != nil {
		return nil, nil, err
	}

	recoveryPubKey, err := pubkey.GetPublicKeyJWK(&recoveryKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	nextRecoveryKey, recoveryCommitment, err := generateKeyAndCommitment(p)
	if err != nil {
		return nil, nil, err
	}

	recoverSignedData := &model.RecoverSignedDataModel{
		RecoveryKey:        recoveryPubKey,
		RecoveryCommitment: recoveryCommitment,
		DeltaHash:          deltaHash,
	}

	req, err := getRecoverRequest(signer, delta, recoverSignedData, blockNum)
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

func getCreateOperationWithDoc(recoveryKey, updateKey *ecdsa.PrivateKey, doc string, blockNum uint64) (*model.Operation, error) {
	p := getProtocol(blockNum)

	createRequest, err := getCreateRequest(recoveryKey, updateKey, p)
	if err != nil {
		return nil, err
	}

	operationBuffer, err := json.Marshal(createRequest)
	if err != nil {
		return nil, err
	}

	uniqueSuffix, err := hashing.CalculateModelMultihash(createRequest.SuffixData, sha2_256)
	if err != nil {
		return nil, err
	}

	updateCommitment, err := getCommitment(updateKey, p)
	if err != nil {
		return nil, err
	}

	delta, err := getDeltaModel(doc, updateCommitment)
	if err != nil {
		return nil, err
	}

	suffixData, err := getSuffixData(recoveryKey, delta, p)
	if err != nil {
		return nil, err
	}

	return &model.Operation{
		Namespace:       mocks.DefaultNS,
		ID:              "did:sidetree:" + uniqueSuffix,
		UniqueSuffix:    uniqueSuffix,
		Type:            operation.TypeCreate,
		OperationBuffer: operationBuffer,
		Delta:           delta,
		SuffixData:      suffixData,
	}, nil
}

func getCreateOperation(recoveryKey, updateKey *ecdsa.PrivateKey, blockNum uint64) (*model.Operation, error) {
	return getCreateOperationWithDoc(recoveryKey, updateKey, validDoc, blockNum)
}

func getAnchoredCreateOperation(recoveryKey, updateKey *ecdsa.PrivateKey) (*operation.AnchoredOperation, error) {
	op, err := getCreateOperation(recoveryKey, updateKey, defaultBlockNumber)
	if err != nil {
		return nil, err
	}

	return getAnchoredOperation(op, defaultBlockNumber), nil
}

func getAnchoredOperation(op *model.Operation, blockNum uint64) *operation.AnchoredOperation {
	anchoredOp, err := model.GetAnchoredOperation(op)
	if err != nil {
		panic(err)
	}

	anchoredOp.TransactionTime = blockNum
	anchoredOp.ProtocolGenesisTime = getProtocol(blockNum).GenesisTime

	return anchoredOp
}

func getCreateRequest(recoveryKey, updateKey *ecdsa.PrivateKey, p protocol.Protocol) (*model.CreateRequest, error) {
	updateCommitment, err := getCommitment(updateKey, p)
	if err != nil {
		return nil, err
	}

	delta, err := getDeltaModel(validDoc, updateCommitment)
	if err != nil {
		return nil, err
	}

	suffixData, err := getSuffixData(recoveryKey, delta, p)
	if err != nil {
		return nil, err
	}

	return &model.CreateRequest{
		Operation:  operation.TypeCreate,
		Delta:      delta,
		SuffixData: suffixData,
	}, nil
}

func getProtocol(blockNum uint64) protocol.Protocol {
	pc := newMockProtocolClient()
	pv, err := pc.Get(blockNum)
	if err != nil {
		panic(err)
	}

	return pv.Protocol()
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

func getCommitment(key *ecdsa.PrivateKey, p protocol.Protocol) (string, error) {
	pubKey, err := pubkey.GetPublicKeyJWK(&key.PublicKey)
	if err != nil {
		return "", err
	}

	return commitment.Calculate(pubKey, p.MultihashAlgorithm)
}

func getSuffixData(privateKey *ecdsa.PrivateKey, delta *model.DeltaModel, p protocol.Protocol) (*model.SuffixDataModel, error) {
	recoveryCommitment, err := getCommitment(privateKey, p)
	if err != nil {
		return nil, err
	}

	deltaHash, err := hashing.CalculateModelMultihash(delta, p.MultihashAlgorithm)
	if err != nil {
		return nil, err
	}

	return &model.SuffixDataModel{
		DeltaHash:          deltaHash,
		RecoveryCommitment: recoveryCommitment,
	}, nil
}

const validDoc = `{
	"publicKey": [{
		  "id": "key1",
		  "type": "JsonWebKey2020",
		  "publicKeyJwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		  }
	}]
}`

const recoveredDocTemplate = `{
	"publicKey": [{
		  "id": "recovered%s",
		  "type": "JsonWebKey2020",
		  "publicKeyJwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		  }
	}]
}`

type mockDocComposer struct {
	Err error
}

// ApplyPatches mocks applying patches to the document.
func (m *mockDocComposer) ApplyPatches(doc document.Document, patches []patch.Patch) (document.Document, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return make(document.Document), nil
}

// mock protocol client with two protocol versions, first one effective at block 0, second at block 100.
func newMockProtocolClient() *mocks.MockProtocolClient {
	pc := mocks.NewMockProtocolClient()

	//nolint:gomnd
	latest := protocol.Protocol{
		GenesisTime:                 100,
		MultihashAlgorithm:          sha2_512,
		MaxOperationCount:           2,
		MaxOperationSize:            mocks.MaxOperationByteSize,
		MaxDeltaSize:                mocks.MaxDeltaByteSize,
		MaxProofSize:                700, // has to be increased from 500 since we now use sha2_512
		MaxCasURILength:             100,
		CompressionAlgorithm:        "GZIP",
		MaxChunkFileSize:            mocks.MaxBatchFileSize,
		MaxProvisionalIndexFileSize: mocks.MaxBatchFileSize,
		MaxCoreIndexFileSize:        mocks.MaxBatchFileSize,
		SignatureAlgorithms:         []string{"EdDSA", "ES256"},
		KeyAlgorithms:               []string{"Ed25519", "P-256"},
		Patches:                     []string{"add-public-keys", "remove-public-keys", "add-services", "remove-services", "ietf-json-patch"},
	}

	latestVersion := mocks.GetProtocolVersion(latest)

	// has to be sorted for mock client to work
	pc.Versions = append(pc.Versions, latestVersion)

	pc.CurrentVersion = latestVersion

	for _, v := range pc.Versions {
		parser := operationparser.New(v.Protocol())
		dc := doccomposer.New()
		oa := operationapplier.New(v.Protocol(), parser, dc)
		v.OperationParserReturns(parser)
		v.OperationApplierReturns(oa)
		v.DocumentComposerReturns(dc)
	}

	return pc
}
