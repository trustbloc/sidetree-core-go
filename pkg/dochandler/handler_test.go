/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	batchapi "github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/cutter"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/opqueue"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/dochandler/didvalidator"
	"github.com/trustbloc/sidetree-core-go/pkg/dochandler/docvalidator"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/processor"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

const (
	namespace = "did:sidetree"

	sha2_256          = 18
	initialStateParam = "?-sidetree-initial-state="
)

func TestDocumentHandler_Namespace(t *testing.T) {
	dh := New(namespace, nil, nil, nil, nil)
	require.Equal(t, namespace, dh.Namespace())
}

func TestDocumentHandler_Protocol(t *testing.T) {
	pc := mocks.NewMockProtocolClient()
	dh := New("", pc, nil, nil, nil)
	require.Equal(t, pc, dh.Protocol())
}

func TestDocumentHandler_ProcessOperation_Create(t *testing.T) {
	dochandler := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	createOp := getCreateOperation()

	doc, err := dochandler.ProcessOperation(createOp)
	require.Nil(t, err)
	require.NotNil(t, doc)
}

func TestDocumentHandler_ProcessOperation_InitialDocumentError(t *testing.T) {
	dochandler := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	replacePatch, err := patch.NewAddPublicKeysPatch("{}")
	require.NoError(t, err)
	replacePatch["publicKeys"] = "invalid"

	createOp := getCreateOperation()

	createOp.DeltaModel = &model.DeltaModel{
		Patches: []patch.Patch{replacePatch},
	}

	doc, err := dochandler.ProcessOperation(createOp)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "expected array of interfaces")
}

func TestDocumentHandler_ProcessOperation_MaxOperationSizeError(t *testing.T) {
	dochandler := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	// modify handler protocol client to decrease max operation size
	protocol := mocks.NewMockProtocolClient()
	protocol.Protocol.MaxOperationSize = 2
	dochandler.protocol = protocol

	createOp := getCreateOperation()

	doc, err := dochandler.ProcessOperation(createOp)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "operation byte size exceeds protocol max operation byte size")
}

func TestDocumentHandler_ProcessOperation_ProtocolError(t *testing.T) {
	pc := mocks.NewMockProtocolClient()
	pc.Err = fmt.Errorf("injected protocol error")
	dochandler := getDocumentHandlerWithProtocolClient(mocks.NewMockOperationStore(nil), pc)
	require.NotNil(t, dochandler)

	createOp := getCreateOperation()

	doc, err := dochandler.ProcessOperation(createOp)
	require.EqualError(t, err, pc.Err.Error())
	require.Nil(t, doc)
}

func TestDocumentHandler_ResolveDocument_DID(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)
	dochandler := getDocumentHandler(store)
	require.NotNil(t, dochandler)

	docID := getCreateOperation().ID

	// scenario: not found in the store
	result, err := dochandler.ResolveDocument(docID)
	require.NotNil(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "not found")

	// insert document in the store
	err = store.Put(getAnchoredCreateOperation())
	require.Nil(t, err)

	// scenario: resolved document (success)
	result, err = dochandler.ResolveDocument(docID)
	require.Nil(t, err)
	require.NotNil(t, result)
	require.Equal(t, true, result.MethodMetadata.Published)

	// scenario: invalid namespace
	result, err = dochandler.ResolveDocument("doc:invalid:")
	require.NotNil(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "must start with configured namespace")

	// scenario: invalid id
	result, err = dochandler.ResolveDocument(namespace + docutil.NamespaceDelimiter)
	require.NotNil(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "did suffix is empty")
}

func TestDocumentHandler_ResolveDocument_InitialValue(t *testing.T) {
	pc := mocks.NewMockProtocolClient()
	dochandler := getDocumentHandlerWithProtocolClient(mocks.NewMockOperationStore(nil), pc)
	require.NotNil(t, dochandler)

	createReq, err := getCreateRequest()
	require.NoError(t, err)

	createOp := getCreateOperation()
	docID := createOp.ID

	initialState := createReq.SuffixData + "." + createReq.Delta

	t.Run("success", func(t *testing.T) {
		result, err := dochandler.ResolveDocument(docID + initialStateParam + initialState)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, false, result.MethodMetadata.Published)
		require.Equal(t, initialState, result.MethodMetadata.InitialState)
	})

	t.Run("error - initial state is empty", func(t *testing.T) {
		result, err := dochandler.ResolveDocument(docID + initialStateParam)
		require.NotNil(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "initial state is present but empty")
	})

	t.Run("error - invalid initial state", func(t *testing.T) {
		result, err := dochandler.ResolveDocument(docID + initialStateParam + "payload")
		require.NotNil(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "initial state should have two parts: suffix data and delta")
	})

	t.Run("error - did doesn't match the one created by parsing original create request", func(t *testing.T) {
		result, err := dochandler.ResolveDocument(dochandler.namespace + ":someID" + initialStateParam + initialState)
		require.NotNil(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "provided did doesn't match did created from initial state")
	})

	t.Run("error - delta and suffix data not encoded (parse create operation fails)", func(t *testing.T) {
		result, err := dochandler.ResolveDocument(docID + initialStateParam + "abc.123")
		require.NotNil(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "invalid character")
	})

	t.Run("error - transform create with initial state to external document", func(t *testing.T) {
		dochandlerWithValidator := getDocumentHandler(mocks.NewMockOperationStore(nil))
		require.NotNil(t, dochandler)

		dochandlerWithValidator.validator = &mocks.MockDocumentValidator{TransformDocumentErr: errors.New("test error")}

		result, err := dochandlerWithValidator.ResolveDocument(docID + initialStateParam + initialState)
		require.NotNil(t, err)
		require.Nil(t, result)
		require.Equal(t, err.Error(), "failed to transform create with initial state to external document: test error")
	})

	t.Run("error - original (create) document is not valid", func(t *testing.T) {
		dochandlerWithValidator := getDocumentHandler(mocks.NewMockOperationStore(nil))
		require.NotNil(t, dochandler)

		dochandlerWithValidator.validator = &mocks.MockDocumentValidator{IsValidOriginalDocumentErr: errors.New("test error")}

		result, err := dochandlerWithValidator.ResolveDocument(docID + initialStateParam + initialState)
		require.NotNil(t, err)
		require.Nil(t, result)
		require.Equal(t, err.Error(), "bad request: validate initial document: test error")
	})

	t.Run("error - protocol error", func(t *testing.T) {
		pc.Err = fmt.Errorf("injected protocol error")
		defer func() { pc.Err = nil }()

		result, err := dochandler.ResolveDocument(docID + initialStateParam + initialState)
		require.EqualError(t, err, pc.Err.Error())
		require.Nil(t, result)
	})
}

func TestDocumentHandler_ResolveDocument_Interop(t *testing.T) {
	dochandler := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	pc := mocks.NewMockProtocolClient()
	pc.Protocol.EnableReplacePatch = true
	dochandler.protocol = pc

	result, err := dochandler.ResolveDocument(interopResolveDidWithInitialState)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestDocumentHandler_ResolveDocument_InitialValue_MaxOperationSizeError(t *testing.T) {
	dochandler := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	// modify handler protocol client to decrease max operation size
	protocol := mocks.NewMockProtocolClient()
	protocol.Protocol.MaxOperationSize = 2
	dochandler.protocol = protocol

	docID := getCreateOperation().ID

	result, err := dochandler.ResolveDocument(docID + initialStateParam + "abc.123")
	require.NotNil(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "bad request: operation byte size exceeds protocol max operation byte size")
}

func TestDocumentHandler_ResolveDocument_InitialDocumentNotValid(t *testing.T) {
	dochandler := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	createReq, err := getCreateRequestWithDoc(invalidDocNoPurpose)
	require.NoError(t, err)

	createOp, err := getCreateOperationWithInitialState(createReq.SuffixData, createReq.Delta)
	require.NoError(t, err)

	docID := createOp.ID

	initialState := createReq.SuffixData + "." + createReq.Delta

	result, err := dochandler.ResolveDocument(docID + initialStateParam + initialState)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "missing purpose")
}

func TestTransformToExternalDocument(t *testing.T) {
	dochandler := getDocumentHandler(nil)

	result, err := dochandler.transformToExternalDoc(nil, "abc")
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "internal document is nil")

	doc := document.Document{}
	result, err = dochandler.transformToExternalDoc(doc, "abc")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "abc", result.Document[keyID])
}

func TestGetUniquePortion(t *testing.T) {
	const namespace = "did:sidetree"

	// id doesn't contain namespace
	uniquePortion, err := getSuffix(namespace, "invalid")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "did must start with configured namespace")

	// id equals namespace; unique portion is empty
	uniquePortion, err = getSuffix(namespace, namespace+docutil.NamespaceDelimiter)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "did suffix is empty")

	// valid unique portion
	const unique = "exKwW0HjS5y4zBtJ7vYDwglYhtckdO15JDt1j5F5Q0A"
	uniquePortion, err = getSuffix(namespace, namespace+docutil.NamespaceDelimiter+unique)
	require.Nil(t, err)
	require.Equal(t, unique, uniquePortion)
}

func TestProcessOperation_Update(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)
	dochandler := getDocumentHandler(store)
	require.NotNil(t, dochandler)

	// insert document in the store
	err := store.Put(getAnchoredCreateOperation())
	require.Nil(t, err)

	// modify default validator to did validator since update payload is did document update
	validator := didvalidator.New(store)
	dochandler.validator = validator

	doc, err := dochandler.ProcessOperation(getUpdateOperation())
	require.Nil(t, err)
	require.Nil(t, doc)
}

// BatchContext implements batch writer context
type BatchContext struct {
	ProtocolClient   *mocks.MockProtocolClient
	CasClient        *mocks.MockCasClient
	BlockchainClient *mocks.MockBlockchainClient
	OpQueue          cutter.OperationQueue
}

// Protocol returns the ProtocolClient
func (m *BatchContext) Protocol() protocol.Client {
	return m.ProtocolClient
}

// Blockchain returns the block chain client
func (m *BatchContext) Blockchain() batch.BlockchainClient {
	return m.BlockchainClient
}

// CAS returns the CAS client
func (m *BatchContext) CAS() cas.Client {
	return m.CasClient
}

// OperationQueue returns the queue of operations pending to be cut
func (m *BatchContext) OperationQueue() cutter.OperationQueue {
	return m.OpQueue
}

func getDocumentHandler(store processor.OperationStoreClient) *DocumentHandler {
	return getDocumentHandlerWithProtocolClient(store, mocks.NewMockProtocolClient())
}

func getDocumentHandlerWithProtocolClient(store processor.OperationStoreClient, protocol *mocks.MockProtocolClient) *DocumentHandler {
	validator := docvalidator.New(store)
	processor := processor.New("test", store, mocks.NewMockProtocolClient())

	ctx := &BatchContext{
		ProtocolClient:   protocol,
		CasClient:        mocks.NewMockCasClient(nil),
		BlockchainClient: mocks.NewMockBlockchainClient(nil),
		OpQueue:          &opqueue.MemQueue{},
	}
	writer, err := batch.New("test", ctx)
	if err != nil {
		panic(err)
	}

	// start go routine for cutting batches
	writer.Start()

	return New(namespace, protocol, validator, writer, processor)
}

func getCreateOperation() *batchapi.Operation {
	request, err := getCreateRequest()
	if err != nil {
		panic(err)
	}

	op, err := getCreateOperationWithInitialState(request.SuffixData, request.Delta)
	if err != nil {
		panic(err)
	}

	return op
}

func getCreateOperationWithInitialState(suffixData, delta string) (*batchapi.Operation, error) {
	request := &model.CreateRequest{
		Operation:  model.OperationTypeCreate,
		SuffixData: suffixData,
		Delta:      delta,
	}

	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	uniqueSuffix, err := docutil.CalculateUniqueSuffix(suffixData, sha2_256)
	if err != nil {
		return nil, err
	}

	deltaBytes, err := docutil.DecodeString(delta)
	if err != nil {
		panic(err)
	}

	deltaModel := &model.DeltaModel{}
	err = json.Unmarshal(deltaBytes, deltaModel)
	if err != nil {
		return nil, err
	}

	suffixDataBytes, err := docutil.DecodeString(suffixData)
	if err != nil {
		return nil, err
	}

	suffixDataModel := &model.SuffixDataModel{}
	err = json.Unmarshal(suffixDataBytes, suffixDataModel)
	if err != nil {
		return nil, err
	}

	return &batchapi.Operation{
		Type:            batchapi.OperationTypeCreate,
		UniqueSuffix:    uniqueSuffix,
		ID:              namespace + docutil.NamespaceDelimiter + uniqueSuffix,
		OperationBuffer: payload,
		DeltaModel:      deltaModel,
		Delta:           delta,
		SuffixData:      suffixData,
		SuffixDataModel: suffixDataModel,
	}, nil
}

func getAnchoredCreateOperation() *batchapi.AnchoredOperation {
	op := getCreateOperation()

	return &batchapi.AnchoredOperation{
		Type:         op.Type,
		UniqueSuffix: op.UniqueSuffix,
		Delta:        op.Delta,
		SuffixData:   op.SuffixData,
	}
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

const invalidDocNoPurpose = `{
	"publicKey": [{
		  "id": "key1",
		  "type": "JsonWebKey2020",	
		  "purpose": [],
		  "jwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		  }
	}]
}`

func getCreateRequest() (*model.CreateRequest, error) {
	return getCreateRequestWithDoc(validDoc)
}

func getCreateRequestWithDoc(doc string) (*model.CreateRequest, error) {
	delta, err := getDeltaWithDoc(doc)
	if err != nil {
		return nil, err
	}

	deltaBytes, err := canonicalizer.MarshalCanonical(delta)
	if err != nil {
		return nil, err
	}

	suffixData, err := getSuffixData(deltaBytes)
	if err != nil {
		return nil, err
	}

	suffixDataBytes, err := canonicalizer.MarshalCanonical(suffixData)
	if err != nil {
		return nil, err
	}

	encodedSuffixData := docutil.EncodeToString(suffixDataBytes)

	return &model.CreateRequest{
		Operation:  model.OperationTypeCreate,
		Delta:      docutil.EncodeToString(deltaBytes),
		SuffixData: encodedSuffixData,
	}, nil
}

func getDeltaWithDoc(doc string) (*model.DeltaModel, error) {
	patches, err := newAddPublicKeysPatch(doc)
	if err != nil {
		return nil, err
	}

	return &model.DeltaModel{
		Patches:          []patch.Patch{patches},
		UpdateCommitment: encodedMultihash([]byte("updateReveal")),
	}, nil
}

// newAddPublicKeysPatch creates new add public keys patch without validation
func newAddPublicKeysPatch(doc string) (patch.Patch, error) {
	parsed, err := document.FromBytes([]byte(doc))
	if err != nil {
		return nil, err
	}

	p := make(patch.Patch)
	p[patch.ActionKey] = patch.AddPublicKeys
	p[patch.PublicKeys] = parsed.PublicKeys()

	return p, nil
}

func getSuffixData(delta []byte) (*model.SuffixDataModel, error) {
	jwk := &jws.JWK{
		Kty: "kty",
		Crv: "crv",
		X:   "x",
	}

	c, err := commitment.Calculate(jwk, sha2_256)
	if err != nil {
		return nil, err
	}

	return &model.SuffixDataModel{
		DeltaHash:          encodedMultihash(delta),
		RecoveryCommitment: c,
	}, nil
}

func encodedMultihash(data []byte) string {
	mh, err := docutil.ComputeMultihash(sha2_256, data)
	if err != nil {
		panic(err)
	}
	return docutil.EncodeToString(mh)
}

func getUpdateRequest() (*model.UpdateRequest, error) {
	deltaBytes, err := json.Marshal(getUpdateDelta())
	if err != nil {
		return nil, err
	}

	return &model.UpdateRequest{
		Operation: model.OperationTypeUpdate,
		DidSuffix: getCreateOperation().UniqueSuffix,
		Delta:     docutil.EncodeToString(deltaBytes),
	}, nil
}

func getUpdateDelta() *model.DeltaModel {
	return &model.DeltaModel{
		UpdateCommitment: encodedMultihash([]byte("updateReveal")),
	}
}

func getUpdateOperation() *batchapi.Operation {
	request, err := getUpdateRequest()
	if err != nil {
		panic(err)
	}

	payload, err := json.Marshal(request)
	if err != nil {
		panic(err)
	}

	return &batchapi.Operation{
		OperationBuffer: payload,
		Type:            batchapi.OperationTypeUpdate,
		UniqueSuffix:    request.DidSuffix,
		ID:              namespace + docutil.NamespaceDelimiter + request.DidSuffix,
	}
}

// test value taken from reference implementation
const interopResolveDidWithInitialState = `did:sidetree:EiBFsUlzmZ3zJtSFeQKwJNtngjmB51ehMWWDuptf9b4Bag?-sidetree-initial-state=eyJkZWx0YV9oYXNoIjoiRWlCWE00b3RMdVAyZkc0WkE3NS1hbnJrV1ZYMDYzN3hadE1KU29Lb3AtdHJkdyIsInJlY292ZXJ5X2NvbW1pdG1lbnQiOiJFaUM4RzRJZGJEN0Q0Q281N0dqTE5LaG1ERWFicnprTzF3c0tFOU1RZVV2T2d3In0.eyJ1cGRhdGVfY29tbWl0bWVudCI6IkVpQ0lQY1hCempqUWFKVUljUjUyZXVJMHJJWHpoTlpfTWxqc0tLOXp4WFR5cVEiLCJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljX2tleXMiOlt7ImlkIjoic2lnbmluZ0tleSIsInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkiLCJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoieTlrenJWQnFYeDI0c1ZNRVFRazRDZS0wYnFaMWk1VHd4bGxXQ2t6QTd3VSIsInkiOiJjMkpIeFFxVVV0eVdJTEFJaWNtcEJHQzQ3UGdtSlQ0NjV0UG9jRzJxMThrIn0sInB1cnBvc2UiOlsiYXV0aCIsImdlbmVyYWwiXX1dLCJzZXJ2aWNlX2VuZHBvaW50cyI6W3siaWQiOiJzZXJ2aWNlRW5kcG9pbnRJZDEyMyIsInR5cGUiOiJzb21lVHlwZSIsImVuZHBvaW50IjoiaHR0cHM6Ly93d3cudXJsLmNvbSJ9XX19XX0`
