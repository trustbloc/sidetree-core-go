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
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/processor"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

const (
	namespace = "doc:namespace"

	sha2_256           = 18
	initialValuesParam = ";initial-values="
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

	createOp.PatchData = &model.PatchDataModel{
		Patches: []patch.Patch{replacePatch},
	}

	doc, err := dochandler.ProcessOperation(createOp)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "invalid character")
}

func TestDocumentHandler_ProcessOperation_MazOperationSizeError(t *testing.T) {
	dochandler := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	// modify handler protocol client to decrease max operation size
	protocol := mocks.NewMockProtocolClient()
	protocol.Protocol.MaxOperationByteSize = 2
	dochandler.protocol = protocol

	createOp := getCreateOperation()

	doc, err := dochandler.ProcessOperation(createOp)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "operation byte size exceeds protocol max operation byte size")
}

func TestDocumentHandler_ResolveDocument_DID(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)
	dochandler := getDocumentHandler(store)
	require.NotNil(t, dochandler)

	docID := getCreateOperation().ID

	// scenario: not found in the store
	doc, err := dochandler.ResolveDocument(docID)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "not found")

	// insert document in the store
	err = store.Put(getCreateOperation())
	require.Nil(t, err)

	// scenario: resolved document (success)
	doc, err = dochandler.ResolveDocument(docID)
	require.Nil(t, err)
	require.NotNil(t, doc)
	require.Equal(t, true, doc.JSONLdObject()[keyPublished])

	// scenario: invalid namespace
	doc, err = dochandler.ResolveDocument("doc:invalid:")
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "must start with configured namespace")

	// scenario: invalid id
	doc, err = dochandler.ResolveDocument(namespace + docutil.NamespaceDelimiter)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "unique portion is empty")
}

func TestDocumentHandler_ResolveDocument_InitialValue(t *testing.T) {
	dochandler := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	docID := getCreateOperation().ID

	encodedRequest := docutil.EncodeToString(getCreateOperation().OperationBuffer)

	doc, err := dochandler.ResolveDocument(docID + initialValuesParam + encodedRequest)
	require.NotNil(t, doc)
	require.Equal(t, false, doc.JSONLdObject()[keyPublished])

	doc, err = dochandler.ResolveDocument(docID + initialValuesParam)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "initial values is present but empty")

	doc, err = dochandler.ResolveDocument(docID + initialValuesParam + "payload")
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "illegal base64 data")
}

func TestDocumentHandler_ResolveDocument_InitialValue_MaxOperationSizeError(t *testing.T) {
	dochandler := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	// modify handler protocol client to decrease max operation size
	protocol := mocks.NewMockProtocolClient()
	protocol.Protocol.MaxOperationByteSize = 2
	dochandler.protocol = protocol

	docID := getCreateOperation().ID

	doc, err := dochandler.ResolveDocument(docID + initialValuesParam + docutil.EncodeToString(getCreateOperation().OperationBuffer))
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "operation byte size exceeds protocol max operation byte size")
}

func TestGetDocErrors(t *testing.T) {
	dochandler := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	const id = "doc:method:abc"

	// scenario: illegal payload (invalid json)
	doc, err := dochandler.getDoc(id, []byte("[test : 123]"), false)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "invalid character")

	// modify handler's protocol client multihash code in order to cause error
	protocol := mocks.NewMockProtocolClient()
	protocol.Protocol.HashAlgorithmInMultiHashCode = 999
	dochandler.protocol = protocol
}

func TestApplyID(t *testing.T) {
	dochandler := getDocumentHandler(nil)

	doc, err := dochandler.transformDoc(nil, "abc", false)
	require.NoError(t, err)
	require.Nil(t, doc)

	doc = document.Document{}
	doc, err = dochandler.transformDoc(doc, "abc", true)
	require.NoError(t, err)
	require.Equal(t, "abc", doc[keyID])
	require.Equal(t, true, doc[keyPublished])

	doc = document.Document{}
	doc, err = dochandler.transformDoc(doc, "abc", false)
	require.NoError(t, err)
	require.Equal(t, "abc", doc[keyID])
	require.Equal(t, false, doc[keyPublished])
}

func TestGetUniquePortion(t *testing.T) {
	const namespace = "did:sidetree"

	// id doesn't contain namespace
	uniquePortion, err := getUniquePortion(namespace, "invalid")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "ID must start with configured namespace")

	// id equals namespace; unique portion is empty
	uniquePortion, err = getUniquePortion(namespace, namespace+docutil.NamespaceDelimiter)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "unique portion is empty")

	// valid unique portion
	const unique = "exKwW0HjS5y4zBtJ7vYDwglYhtckdO15JDt1j5F5Q0A"
	uniquePortion, err = getUniquePortion(namespace, namespace+docutil.NamespaceDelimiter+unique)
	require.Nil(t, err)
	require.Equal(t, unique, uniquePortion)
}

func TestGetParts(t *testing.T) {
	const testDID = "did:method:abc"

	did, initial, err := getParts(testDID)
	require.Nil(t, err)
	require.Empty(t, initial)
	require.Equal(t, testDID, did)

	did, initial, err = getParts(testDID + initialValuesParam)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "initial values is present but empty")

	did, initial, err = getParts(testDID + initialValuesParam + "xyz")
	require.Nil(t, err)
	require.Equal(t, testDID, did)
	require.Equal(t, initial, "xyz")
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

func TestDocumentHandler_UnmarshalPatchData(t *testing.T) {
	doc, err := unmarshalPatchData([]byte(""))
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "unexpected end of JSON input")

	req, err := getCreateRequest()
	require.NoError(t, err)

	req.PatchData = "invalid"
	reqBytes, err := json.Marshal(req)
	require.NoError(t, err)

	doc, err = unmarshalPatchData(reqBytes)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "illegal base64 data")

	req.PatchData = docutil.EncodeToString([]byte("invalid"))
	reqBytes, err = json.Marshal(req)
	require.NoError(t, err)

	doc, err = unmarshalPatchData(reqBytes)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "invalid character")
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

	payload, err := json.Marshal(request)
	if err != nil {
		panic(err)
	}

	uniqueSuffix, err := docutil.CalculateUniqueSuffix(request.SuffixData, sha2_256)
	if err != nil {
		panic(err)
	}

	patchDataBytes, err := docutil.DecodeString(request.PatchData)
	if err != nil {
		panic(err)
	}

	patchData := &model.PatchDataModel{}
	err = json.Unmarshal(patchDataBytes, patchData)
	if err != nil {
		panic(err)
	}

	return &batchapi.Operation{
		OperationBuffer:              payload,
		PatchData:                    patchData,
		EncodedPatchData:             request.PatchData,
		Type:                         batchapi.OperationTypeCreate,
		HashAlgorithmInMultiHashCode: sha2_256,
		UniqueSuffix:                 uniqueSuffix,
		ID:                           namespace + docutil.NamespaceDelimiter + uniqueSuffix,
	}
}

const validDoc = `{
	"publicKey": [{
		"id": "#key-1",
		"publicKeyBase58": "GY4GunSXBPBfhLCzDL7iGmP5dR3sBDCJZkkaGK8VgYQf",
		"type": "Ed25519VerificationKey2018"
	}]
}`

func getCreateRequest() (*model.CreateRequest, error) {
	patchData, err := getPatchData()
	if err != nil {
		return nil, err
	}

	patchDataBytes, err := json.Marshal(patchData)
	if err != nil {
		return nil, err
	}

	suffixDataBytes, err := docutil.MarshalCanonical(getSuffixData())
	if err != nil {
		return nil, err
	}

	return &model.CreateRequest{
		Operation:  model.OperationTypeCreate,
		PatchData:  docutil.EncodeToString(patchDataBytes),
		SuffixData: docutil.EncodeToString(suffixDataBytes),
	}, nil
}

func getPatchData() (*model.PatchDataModel, error) {
	replacePatch, err := patch.NewReplacePatch(validDoc)
	if err != nil {
		return nil, err
	}

	return &model.PatchDataModel{
		Patches:                  []patch.Patch{replacePatch},
		NextUpdateCommitmentHash: computeMultihash("updateReveal"),
	}, nil
}

func getSuffixData() *model.SuffixDataModel {
	return &model.SuffixDataModel{
		PatchDataHash:              computeMultihash(validDoc),
		RecoveryKey:                model.PublicKey{PublicKeyHex: "HEX"},
		NextRecoveryCommitmentHash: computeMultihash("recoveryReveal"),
	}
}

func computeMultihash(data string) string {
	mh, err := docutil.ComputeMultihash(sha2_256, []byte(data))
	if err != nil {
		panic(err)
	}
	return docutil.EncodeToString(mh)
}

func getUpdateRequest() (*model.UpdateRequest, error) {
	patchDataBytes, err := json.Marshal(getUpdatePatchData())
	if err != nil {
		return nil, err
	}

	return &model.UpdateRequest{
		Operation:       model.OperationTypeUpdate,
		DidUniqueSuffix: getCreateOperation().UniqueSuffix,
		PatchData:       docutil.EncodeToString(patchDataBytes),
	}, nil
}

func getUpdatePatchData() *model.PatchDataModel {
	return &model.PatchDataModel{
		NextUpdateCommitmentHash: computeMultihash("updateReveal"),
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
		UniqueSuffix:                 request.DidUniqueSuffix,
		ID:                           namespace + docutil.NamespaceDelimiter + request.DidUniqueSuffix,
	}
}
