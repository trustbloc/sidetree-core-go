/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"encoding/json"
	"testing"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"

	jsonpatch "github.com/evanphx/json-patch"

	"github.com/trustbloc/sidetree-core-go/pkg/dochandler/didvalidator"
	"github.com/trustbloc/sidetree-core-go/pkg/dochandler/docvalidator"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/processor"

	batchapi "github.com/trustbloc/sidetree-core-go/pkg/api/batch"
)

const (
	namespace    = "doc:namespace"
	uniqueSuffix = "EiDOQXC2GnoVyHwIRbjhLx_cNc6vmZaS04SZjZdlLLAPRg=="
	docID        = namespace + docutil.NamespaceDelimiter + uniqueSuffix

	// encoded payload contains encoded document that corresponds to unique suffix above
	encodedPayload     = "ewogICJAY29udGV4dCI6ICJodHRwczovL3czaWQub3JnL2RpZC92MSIsCiAgInB1YmxpY0tleSI6IFt7CiAgICAiaWQiOiAiI2tleTEiLAogICAgInR5cGUiOiAiU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOCIsCiAgICAicHVibGljS2V5SGV4IjogIjAyZjQ5ODAyZmIzZTA5YzZkZDQzZjE5YWE0MTI5M2QxZTBkYWQwNDRiNjhjZjgxY2Y3MDc5NDk5ZWRmZDBhYTlmMSIKICB9XSwKICAic2VydmljZSI6IFt7CiAgICAiaWQiOiAiSWRlbnRpdHlIdWIiLAogICAgInR5cGUiOiAiSWRlbnRpdHlIdWIiLAogICAgInNlcnZpY2VFbmRwb2ludCI6IHsKICAgICAgIkBjb250ZXh0IjogInNjaGVtYS5pZGVudGl0eS5mb3VuZGF0aW9uL2h1YiIsCiAgICAgICJAdHlwZSI6ICJVc2VyU2VydmljZUVuZHBvaW50IiwKICAgICAgImluc3RhbmNlIjogWyJkaWQ6YmFyOjQ1NiIsICJkaWQ6emF6Ojc4OSJdCiAgICB9CiAgfV0KfQo="
	updatePayload      = "ewogICJkaWRVbmlxdWVTdWZmaXgiOiAiRWlET1FYQzJHbm9WeUh3SVJiamhMeF9jTmM2dm1aYVMwNFNaalpkbExMQVBSZz09IiwKICAib3BlcmF0aW9uTnVtYmVyIjogMSwKICAicHJldmlvdXNPcGVyYXRpb25IYXNoIjogIkVpRE9RWEMyR25vVnlId0lSYmpoTHhfY05jNnZtWmFTMDRTWmpaZGxMTEFQUmc9PSIsCiAgInBhdGNoIjogW3sKICAgICJvcCI6ICJyZW1vdmUiLAogICAgInBhdGgiOiAiL3NlcnZpY2UvMCIKICB9XQp9Cg=="
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

	createOp.EncodedPayload = "invalid"
	doc, err = dochandler.ProcessOperation(createOp)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "illegal base64 data")
}

func TestDocumentHandler_ProcessOperation_MaxOperationSizeError(t *testing.T) {
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

	doc, err := dochandler.ResolveDocument(docID + initialValuesParam + getCreateOperation().EncodedPayload)
	require.Nil(t, err)
	require.NotNil(t, doc)

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

	doc, err := dochandler.ResolveDocument(docID + initialValuesParam + getCreateOperation().EncodedPayload)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "operation byte size exceeds protocol max operation byte size")
}

func TestGetDocErrors(t *testing.T) {
	dochandler := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)

	// scenario: illegal payload (not base64)
	doc, err := dochandler.getDoc("{}")
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "illegal base64 data")

	// scenario: illegal payload (invalid json)
	doc, err = dochandler.getDoc(docutil.EncodeToString([]byte("[test : 123]")))
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "invalid character")

	// modify handler's protocol client multihash code in order to cause error
	protocol := mocks.NewMockProtocolClient()
	protocol.Protocol.HashAlgorithmInMultiHashCode = 999
	dochandler.protocol = protocol

	// scenario: invalid multihash code
	doc, err = dochandler.getDoc(getCreateOperation().EncodedPayload)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "algorithm not supported, unable to compute hash")
}

func TestApplyID(t *testing.T) {
	doc := applyID(nil, "abc")
	require.Nil(t, doc)

	doc = document.Document{}
	doc = applyID(doc, "abc")
	require.Equal(t, "abc", doc["id"])
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

// BatchContext implements batch writer context
type BatchContext struct {
	ProtocolClient   *mocks.MockProtocolClient
	CasClient        *mocks.MockCasClient
	BlockchainClient *mocks.MockBlockchainClient
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

func getDocumentHandler(store processor.OperationStoreClient) *DocumentHandler {
	protocol := mocks.NewMockProtocolClient()

	validator := docvalidator.New(store)
	processor := processor.New(store)

	ctx := &BatchContext{
		ProtocolClient:   protocol,
		CasClient:        mocks.NewMockCasClient(nil),
		BlockchainClient: mocks.NewMockBlockchainClient(nil),
	}
	writer, err := batch.New(ctx)
	if err != nil {
		panic(err)
	}

	// start go routine for cutting batches
	writer.Start()

	return New(namespace, protocol, validator, writer, processor)
}

func getCreateOperation() batchapi.Operation {
	return batchapi.Operation{
		EncodedPayload:               encodedPayload,
		Type:                         batchapi.OperationTypeCreate,
		HashAlgorithmInMultiHashCode: sha2_256,
		UniqueSuffix:                 uniqueSuffix,
		ID:                           namespace + uniqueSuffix,
	}
}

func getUpdateOperation() batchapi.Operation {
	decodedPayload, err := getDecodedPayload(updatePayload)
	if err != nil {
		panic(err)
	}

	return batchapi.Operation{
		EncodedPayload:               updatePayload,
		Type:                         batchapi.OperationTypeUpdate,
		HashAlgorithmInMultiHashCode: sha2_256,
		UniqueSuffix:                 decodedPayload.DidUniqueSuffix,
		Patch:                        decodedPayload.Patch,
	}
}

func getDecodedPayload(encodedPayload string) (*payloadSchema, error) {
	decodedPayload, err := docutil.DecodeString(encodedPayload)
	if err != nil {
		return nil, err
	}
	uploadPayloadSchema := &payloadSchema{}
	err = json.Unmarshal(decodedPayload, uploadPayloadSchema)
	if err != nil {
		return nil, err
	}
	return uploadPayloadSchema, nil
}

//payloadSchema is the struct for update payload
type payloadSchema struct {
	//The unique suffix of the DID
	DidUniqueSuffix string
	//An RFC 6902 JSON patch to the current DID Document
	Patch jsonpatch.Patch
}
