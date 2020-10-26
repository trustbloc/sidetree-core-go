/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"crypto"
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
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/dochandler/transformer/doctransformer"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/processor"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/doccomposer"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/operationapplier"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/operationparser"
)

const (
	namespace = "did:sidetree"
	alias     = "did:domain.com"

	sha2_256 = 18
)

func TestDocumentHandler_New(t *testing.T) {
	aliases := []string{"alias1", "alias2"}
	dh := New(namespace, aliases, nil, nil, nil, nil)
	require.Equal(t, namespace, dh.Namespace())
	require.Equal(t, aliases, dh.aliases)
}

func TestDocumentHandler_Protocol(t *testing.T) {
	pc := newMockProtocolClient()
	dh := New("", nil, pc, nil, nil, nil)
	require.NotNil(t, dh)
}

func TestDocumentHandler_ProcessOperation_Create(t *testing.T) {
	dochandler, cleanup := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)
	defer cleanup()

	createOp := getCreateOperation()

	doc, err := dochandler.ProcessOperation(createOp.OperationBuffer, 0)
	require.Nil(t, err)
	require.NotNil(t, doc)
}

func TestDocumentHandler_ProcessOperation_MaxOperationSizeError(t *testing.T) {
	dochandler, cleanup := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)
	defer cleanup()

	// modify handler protocol client to decrease max operation size
	pc := newMockProtocolClient()
	pc.Protocol.MaxOperationSize = 2
	pc.CurrentVersion.ProtocolReturns(pc.Protocol)
	dochandler.protocol = pc

	createOp := getCreateOperation()

	doc, err := dochandler.ProcessOperation(createOp.OperationBuffer, 0)
	require.Error(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "operation byte size exceeds protocol max operation byte size")
}

func TestDocumentHandler_ProcessOperation_ProtocolError(t *testing.T) {
	pc := newMockProtocolClient()
	pc.Err = fmt.Errorf("injected protocol error")
	dochandler, cleanup := getDocumentHandlerWithProtocolClient(mocks.NewMockOperationStore(nil), pc)
	require.NotNil(t, dochandler)
	defer cleanup()

	createOp := getCreateOperation()

	doc, err := dochandler.ProcessOperation(createOp.OperationBuffer, 0)
	require.EqualError(t, err, pc.Err.Error())
	require.Nil(t, doc)
}

func TestDocumentHandler_ResolveDocument_DID(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)
	dochandler, cleanup := getDocumentHandler(store)
	require.NotNil(t, dochandler)
	defer cleanup()

	docID := getCreateOperation().ID
	uniqueSuffix := getCreateOperation().UniqueSuffix

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

	// scenario: resolve document with alias namespace (success)
	aliasID := alias + ":" + uniqueSuffix
	result, err = dochandler.ResolveDocument(aliasID)
	require.Nil(t, err)
	require.NotNil(t, result)
	require.Equal(t, true, result.MethodMetadata.Published)
	require.Equal(t, result.MethodMetadata.CanonicalID, docID)
	require.Equal(t, result.Document[keyID], aliasID)

	// scenario: invalid namespace
	result, err = dochandler.ResolveDocument("doc:invalid")
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
	pc := newMockProtocolClient()
	dochandler, cleanup := getDocumentHandlerWithProtocolClient(mocks.NewMockOperationStore(nil), pc)
	require.NotNil(t, dochandler)
	defer cleanup()

	createOp := getCreateOperation()
	docID := createOp.ID

	createReq, err := canonicalizer.MarshalCanonical(model.CreateRequest{
		Delta:      createOp.Delta,
		SuffixData: createOp.SuffixData,
	})
	require.NoError(t, err)

	longFormPart := ":" + docutil.EncodeToString(createReq)

	t.Run("success - initial state", func(t *testing.T) {
		result, err := dochandler.ResolveDocument(docID + longFormPart)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, false, result.MethodMetadata.Published)
	})

	t.Run("error - invalid initial state format (not encoded JCS)", func(t *testing.T) {
		result, err := dochandler.ResolveDocument(docID + ":payload")
		require.NotNil(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "bad request: invalid character")
	})

	t.Run("error - did doesn't match the one created by parsing original create request", func(t *testing.T) {
		result, err := dochandler.ResolveDocument(dochandler.namespace + ":someID" + longFormPart)
		require.NotNil(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "provided did doesn't match did created from initial state")
	})

	t.Run("error - transform create with initial state to external document", func(t *testing.T) {
		dochandlerWithValidator, cleanup := getDocumentHandler(mocks.NewMockOperationStore(nil))
		require.NotNil(t, dochandlerWithValidator)
		defer cleanup()

		dochandlerWithValidator.transformer = &mocks.MockDocumentTransformer{Err: errors.New("test error")}

		result, err := dochandlerWithValidator.ResolveDocument(docID + longFormPart)
		require.NotNil(t, err)
		require.Nil(t, result)
		require.Equal(t, err.Error(), "failed to transform create with initial state to external document: test error")
	})

	t.Run("error - original (create) document is not valid", func(t *testing.T) {
		dv := &mocks.DocumentValidator{}
		dv.IsValidOriginalDocumentReturns(errors.New("test error"))

		pc := newMockProtocolClient()
		pc.CurrentVersion.DocumentValidatorReturns(dv)

		dochandlerWithValidator, cleanup := getDocumentHandlerWithProtocolClient(mocks.NewMockOperationStore(nil), pc)
		require.NotNil(t, dochandlerWithValidator)
		defer cleanup()

		result, err := dochandlerWithValidator.ResolveDocument(docID + longFormPart)
		require.Error(t, err)
		require.Nil(t, result)
		require.Equal(t, err.Error(), "bad request: validate initial document: test error")
	})

	t.Run("error - protocol error", func(t *testing.T) {
		pc := newMockProtocolClient()
		pc.Err = fmt.Errorf("injected protocol error")

		dochandler, cleanup := getDocumentHandlerWithProtocolClient(mocks.NewMockOperationStore(nil), pc)
		require.NotNil(t, dochandler)
		defer cleanup()

		result, err := dochandler.ResolveDocument(docID + longFormPart)
		require.EqualError(t, err, pc.Err.Error())
		require.Nil(t, result)
	})
}

func TestDocumentHandler_ResolveDocument_Interop(t *testing.T) {
	pc := newMockProtocolClient()
	pc.Protocol.Patches = []string{"replace", "add-public-keys", "remove-public-keys", "add-services", "remove-services", "ietf-json-patch"}

	parser := operationparser.New(pc.Protocol)
	oa := operationapplier.New(pc.Protocol, parser, doccomposer.New())

	pv := pc.CurrentVersion
	pv.OperationParserReturns(parser)
	pv.OperationApplierReturns(oa)

	pc.CurrentVersion.ProtocolReturns(pc.Protocol)

	dochandler, cleanup := getDocumentHandlerWithProtocolClient(mocks.NewMockOperationStore(nil), pc)
	require.NotNil(t, dochandler)
	defer cleanup()

	dochandler.protocol = pc

	result, err := dochandler.ResolveDocument(interopResolveDidWithInitialState)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestDocumentHandler_ResolveDocument_InitialValue_MaxOperationSizeError(t *testing.T) {
	dochandler, cleanup := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)
	defer cleanup()

	// modify handler protocol client to decrease max operation size
	protocol := newMockProtocolClient()
	protocol.Protocol.MaxOperationSize = 2
	protocol.CurrentVersion.ProtocolReturns(protocol.Protocol)
	dochandler.protocol = protocol

	createOp := getCreateOperation()
	docID := createOp.ID

	createReq, err := canonicalizer.MarshalCanonical(model.CreateRequest{
		Delta:      createOp.Delta,
		SuffixData: createOp.SuffixData,
	})
	require.NoError(t, err)

	longFormPart := ":" + docutil.EncodeToString(createReq)

	result, err := dochandler.ResolveDocument(docID + longFormPart)
	require.NotNil(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "bad request: operation byte size exceeds protocol max operation byte size")
}

func TestDocumentHandler_ResolveDocument_InitialDocumentNotValid(t *testing.T) {
	dochandler, cleanup := getDocumentHandler(mocks.NewMockOperationStore(nil))
	require.NotNil(t, dochandler)
	defer cleanup()

	createReq, err := getCreateRequestWithDoc(invalidDocNoPurpose)
	require.NoError(t, err)

	createOp, err := getCreateOperationWithInitialState(createReq.SuffixData, createReq.Delta)
	require.NoError(t, err)

	docID := createOp.ID

	initialReq, err := canonicalizer.MarshalCanonical(model.CreateRequest{
		Delta:      createOp.Delta,
		SuffixData: createOp.SuffixData,
	})
	require.NoError(t, err)

	longFormPart := ":" + docutil.EncodeToString(initialReq)

	result, err := dochandler.ResolveDocument(docID + longFormPart)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "missing purpose")
}

func TestTransformToExternalDocument(t *testing.T) {
	dochandler, cleanup := getDocumentHandler(nil)
	defer cleanup()

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

func TestProcessOperation_ParseOperationError(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)
	dochandler, cleanup := getDocumentHandler(store)
	require.NotNil(t, dochandler)
	defer cleanup()

	// insert document in the store
	err := store.Put(getAnchoredCreateOperation())
	require.Nil(t, err)

	doc, err := dochandler.ProcessOperation(getUpdateOperation().OperationBuffer, 0)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "bad request: missing signed data")
}

// BatchContext implements batch writer context.
type BatchContext struct {
	ProtocolClient   *mocks.MockProtocolClient
	CasClient        *mocks.MockCasClient
	BlockchainClient *mocks.MockBlockchainClient
	OpQueue          cutter.OperationQueue
}

// Protocol returns the ProtocolClient.
func (m *BatchContext) Protocol() protocol.Client {
	return m.ProtocolClient
}

// Blockchain returns the block chain client.
func (m *BatchContext) Blockchain() batch.BlockchainClient {
	return m.BlockchainClient
}

// CAS returns the CAS client.
func (m *BatchContext) CAS() cas.Client {
	return m.CasClient
}

// OperationQueue returns the queue of operations pending to be cut.
func (m *BatchContext) OperationQueue() cutter.OperationQueue {
	return m.OpQueue
}

type cleanup func()

func getDocumentHandler(store processor.OperationStoreClient) (*DocumentHandler, cleanup) {
	return getDocumentHandlerWithProtocolClient(store, newMockProtocolClient())
}

func getDocumentHandlerWithProtocolClient(store processor.OperationStoreClient, protocol *mocks.MockProtocolClient) (*DocumentHandler, cleanup) {
	transformer := doctransformer.New()
	processor := processor.New("test", store, protocol)

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

	return New(namespace, []string{alias}, protocol, transformer, writer, processor), func() { writer.Stop() }
}

func getCreateOperation() *model.Operation {
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

func getCreateOperationWithInitialState(suffixData *model.SuffixDataModel, delta *model.DeltaModel) (*model.Operation, error) {
	request := &model.CreateRequest{
		Operation:  batchapi.OperationTypeCreate,
		SuffixData: suffixData,
		Delta:      delta,
	}

	payload, err := canonicalizer.MarshalCanonical(request)
	if err != nil {
		return nil, err
	}

	uniqueSuffix, err := docutil.CalculateModelMultihash(suffixData, sha2_256)
	if err != nil {
		return nil, err
	}

	return &model.Operation{
		Type:            batchapi.OperationTypeCreate,
		UniqueSuffix:    uniqueSuffix,
		ID:              namespace + docutil.NamespaceDelimiter + uniqueSuffix,
		OperationBuffer: payload,
		Delta:           delta,
		SuffixData:      suffixData,
	}, nil
}

func getAnchoredCreateOperation() *batchapi.AnchoredOperation {
	op := getCreateOperation()

	return getAnchoredOperation(op)
}

func getAnchoredOperation(op *model.Operation) *batchapi.AnchoredOperation {
	anchoredOp, err := model.GetAnchoredOperation(op)
	if err != nil {
		panic(err)
	}

	return anchoredOp
}

const validDoc = `{
	"publicKey": [{
		  "id": "key1",
		  "type": "JsonWebKey2020",
		  "purposes": ["verificationMethod"],
		  "publicKeyJwk": {
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
		  "purposes": [],
		  "publicKeyJwk": {
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

	suffixData, err := getSuffixData(delta)
	if err != nil {
		return nil, err
	}

	return &model.CreateRequest{
		Operation:  batchapi.OperationTypeCreate,
		Delta:      delta,
		SuffixData: suffixData,
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

// newAddPublicKeysPatch creates new add public keys patch without validation.
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

func getSuffixData(delta *model.DeltaModel) (*model.SuffixDataModel, error) {
	jwk := &jws.JWK{
		Kty: "kty",
		Crv: "crv",
		X:   "x",
	}

	c, err := commitment.Calculate(jwk, sha2_256, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	deltaHash, err := docutil.CalculateModelMultihash(delta, sha2_256)
	if err != nil {
		return nil, err
	}

	return &model.SuffixDataModel{
		DeltaHash:          deltaHash,
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

func getUpdateDelta() *model.DeltaModel {
	return &model.DeltaModel{
		UpdateCommitment: encodedMultihash([]byte("updateReveal")),
	}
}

func getUpdateOperation() *batchapi.Operation {
	request := &model.UpdateRequest{
		Operation: batchapi.OperationTypeUpdate,
		DidSuffix: getCreateOperation().UniqueSuffix,
		Delta:     getUpdateDelta(),
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

// test value taken from reference implementation.
const interopResolveDidWithInitialState = "did:sidetree:EiA5vyaRzJIxbkuZbvwEXiC__u8ieFx50TAAo98tBzCuyA:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWduaW5nS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6InNlY3AyNTZrMSIsImt0eSI6IkVDIiwieCI6ImRTYUJSTnRHdnlqMjJlOVQ0TjVMajdYdjd1eGlQTHdTRnhraHYwNC1tZzAiLCJ5IjoieDY3U0lmaURlMWxOdjhvS1MxeGNCb29iLTlsTm1hM2FmbzFlcmQzNXBnZyJ9LCJwdXJwb3NlcyI6WyJ2ZXJpZmljYXRpb25NZXRob2QiLCJhdXRoZW50aWNhdGlvbiIsImFzc2VydGlvbk1ldGhvZCIsImNhcGFiaWxpdHlJbnZvY2F0aW9uIiwiY2FwYWJpbGl0eURlbGVnYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZUlkMTIzIiwic2VydmljZUVuZHBvaW50IjoiaHR0cHM6Ly93d3cudXJsLmNvbSIsInR5cGUiOiJzb21lVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpQXZUSVQtMFhCV1hhcnBqdk1QUGhaaTNjNHNVMUNpX3JPelBEN1c1djhTaHcifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUJPbWtQNmtuN3lqdDBWb2NtY1B1OU9RT3NaaTE5OUV2aC14QjQ4ZWJ1YlFBIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlBQVpKWXJ5Mjl2SUNrd21zbzhGTDkyV0FJU01BaHNMOHhrQ204ZFlWbnFfdyJ9fQ"

func newMockProtocolClient() *mocks.MockProtocolClient {
	pc := mocks.NewMockProtocolClient()

	for _, v := range pc.Versions {
		parser := operationparser.New(v.Protocol())
		dc := doccomposer.New()
		oa := operationapplier.New(v.Protocol(), parser, dc)
		dv := &mocks.DocumentValidator{}
		v.OperationParserReturns(parser)
		v.OperationApplierReturns(oa)
		v.DocumentComposerReturns(dc)
		v.DocumentValidatorReturns(dv)
	}

	return pc
}
