/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	batchapi "github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/cutter"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/opqueue"
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
	namespace = "doc:method"

	sha2_256          = 18
	initialStateParam = "?-method-initial-state="
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

	replacePatch, err := patch.NewReplacePatch("{}")
	require.NoError(t, err)
	replacePatch["document"] = "invalid"

	createOp := getCreateOperation()

	createOp.Delta = &model.DeltaModel{
		Patches: []patch.Patch{replacePatch},
	}

	doc, err := dochandler.ProcessOperation(createOp)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "unexpected interface for document")
}

func TestDocumentHandler_ProcessOperation_MaxDeltaSizeError(t *testing.T) {
	dochandler := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	// modify handler protocol client to decrease max operation size
	protocol := mocks.NewMockProtocolClient()
	protocol.Protocol.MaxDeltaByteSize = 2
	dochandler.protocol = protocol

	createOp := getCreateOperation()

	doc, err := dochandler.ProcessOperation(createOp)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "delta byte size exceeds protocol max delta byte size")
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
	err = store.Put(getCreateOperation())
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
	dochandler := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	createReq, err := getCreateRequest()
	require.NoError(t, err)

	createOp := getCreateOperation()
	docID := createOp.ID

	initialState := createReq.Delta + "." + createReq.SuffixData

	result, err := dochandler.ResolveDocument(docID + initialStateParam + initialState)
	require.NotNil(t, result)
	require.Equal(t, false, result.MethodMetadata.Published)

	result, err = dochandler.ResolveDocument(docID + initialStateParam)
	require.NotNil(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "initial state is present but empty")

	// create request not encoded
	result, err = dochandler.ResolveDocument(docID + initialStateParam + "payload")
	require.NotNil(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "initial state should have two parts: delta and suffix data")

	// did doesn't match the one created by parsing original create request
	result, err = dochandler.ResolveDocument(dochandler.namespace + ":someID" + initialStateParam + initialState)
	require.NotNil(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "provided did doesn't match did created from initial state")

	// delta and suffix data not encoded (parse create operation fails)
	result, err = dochandler.ResolveDocument(docID + initialStateParam + "abc.123")
	require.NotNil(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "invalid character")
}

func TestDocumentHandler_ResolveDocument_InitialValue_MaxDeltaSizeError(t *testing.T) {
	dochandler := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	// modify handler protocol client to decrease max operation size
	protocol := mocks.NewMockProtocolClient()
	protocol.Protocol.MaxDeltaByteSize = 2
	dochandler.protocol = protocol

	docID := getCreateOperation().ID

	result, err := dochandler.ResolveDocument(docID + initialStateParam + "abc.123")
	require.NotNil(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "delta byte size exceeds protocol max delta byte size")
}

func TestDocumentHandler_ResolveDocument_InitialDocumentNotValid(t *testing.T) {
	dochandler := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	createReq, err := getCreateRequestWithDoc(invalidDocNoUsage)
	require.NoError(t, err)

	createOp, err := getCreateOperationWithInitialState(createReq.SuffixData, createReq.Delta)
	require.NoError(t, err)

	docID := createOp.ID

	initialState := createReq.Delta + "." + createReq.SuffixData

	result, err := dochandler.ResolveDocument(docID + initialStateParam + initialState)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "missing usage")
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
	err := store.Put(getCreateOperation())
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
func (m *BatchContext) CAS() batch.CASClient {
	return m.CasClient
}

// OperationQueue returns the queue of operations pending to be cut
func (m *BatchContext) OperationQueue() cutter.OperationQueue {
	return m.OpQueue
}

func getDocumentHandler(store processor.OperationStoreClient) *DocumentHandler {
	protocol := mocks.NewMockProtocolClient()

	validator := docvalidator.New(store)
	processor := processor.New("test", store)

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
		OperationBuffer:              payload,
		Delta:                        deltaModel,
		EncodedDelta:                 delta,
		Type:                         batchapi.OperationTypeCreate,
		HashAlgorithmInMultiHashCode: sha2_256,
		UniqueSuffix:                 uniqueSuffix,
		ID:                           namespace + docutil.NamespaceDelimiter + uniqueSuffix,
		SuffixData:                   suffixDataModel,
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

const invalidDocNoUsage = `{
	"publicKey": [{
		  "id": "key1",
		  "type": "JwsVerificationKey2020",
		  "usage": [],		
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

	encodedDelta := docutil.EncodeToString(deltaBytes)

	suffixDataBytes, err := canonicalizer.MarshalCanonical(getSuffixData(encodedDelta))
	if err != nil {
		return nil, err
	}

	encodedSuffixData := docutil.EncodeToString(suffixDataBytes)

	return &model.CreateRequest{
		Operation:  model.OperationTypeCreate,
		Delta:      encodedDelta,
		SuffixData: encodedSuffixData,
	}, nil
}

func getDeltaWithDoc(doc string) (*model.DeltaModel, error) {
	replacePatch, err := newReplacePatch(doc)
	if err != nil {
		return nil, err
	}

	return &model.DeltaModel{
		Patches:          []patch.Patch{replacePatch},
		UpdateCommitment: encodedMultihash("updateReveal"),
	}, nil
}

// newReplacePatch creates new replace patch without validation
func newReplacePatch(doc string) (patch.Patch, error) {
	parsed, err := document.FromBytes([]byte(doc))
	if err != nil {
		return nil, err
	}

	p := make(patch.Patch)
	p[patch.ActionKey] = patch.Replace
	p[patch.DocumentKey] = parsed.JSONLdObject()

	return p, nil
}

func getSuffixData(encodedDelta string) *model.SuffixDataModel {
	return &model.SuffixDataModel{
		DeltaHash: encodedMultihash(encodedDelta),
		RecoveryKey: &jws.JWK{
			Kty: "kty",
			Crv: "crv",
			X:   "x",
		},
		RecoveryCommitment: encodedMultihash("recoveryReveal"),
	}
}

func encodedMultihash(data string) string {
	mh, err := docutil.ComputeMultihash(sha2_256, []byte(data))
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
		UpdateCommitment: encodedMultihash("updateReveal"),
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
		OperationBuffer:              payload,
		Type:                         batchapi.OperationTypeUpdate,
		HashAlgorithmInMultiHashCode: sha2_256,
		UniqueSuffix:                 request.DidSuffix,
		ID:                           namespace + docutil.NamespaceDelimiter + request.DidSuffix,
	}
}
