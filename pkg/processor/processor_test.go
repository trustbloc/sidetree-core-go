/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package processor

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

const (
	dummyUniqueSuffix = "dummy"
	uniqueSuffix      = "EiDOQXC2GnoVyHwIRbjhLx_cNc6vmZaS04SZjZdlLLAPRg=="
	// encoded payload contains encoded document that corresponds to unique suffix above
	encodedPayload = "ewogICJAY29udGV4dCI6ICJodHRwczovL3czaWQub3JnL2RpZC92MSIsCiAgInB1YmxpY0tleSI6IFt7CiAgICAiaWQiOiAiI2tleTEiLAogICAgInR5cGUiOiAiU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOCIsCiAgICAicHVibGljS2V5SGV4IjogIjAyZjQ5ODAyZmIzZTA5YzZkZDQzZjE5YWE0MTI5M2QxZTBkYWQwNDRiNjhjZjgxY2Y3MDc5NDk5ZWRmZDBhYTlmMSIKICB9XSwKICAic2VydmljZSI6IFt7CiAgICAiaWQiOiAiSWRlbnRpdHlIdWIiLAogICAgInR5cGUiOiAiSWRlbnRpdHlIdWIiLAogICAgInNlcnZpY2VFbmRwb2ludCI6IHsKICAgICAgIkBjb250ZXh0IjogInNjaGVtYS5pZGVudGl0eS5mb3VuZGF0aW9uL2h1YiIsCiAgICAgICJAdHlwZSI6ICJVc2VyU2VydmljZUVuZHBvaW50IiwKICAgICAgImluc3RhbmNlIjogWyJkaWQ6YmFyOjQ1NiIsICJkaWQ6emF6Ojc4OSJdCiAgICB9CiAgfV0KfQo="
	sha2_256       = 18
	updateOTP      = "updateOTP"
)

func TestResolve(t *testing.T) {
	op := New(getDefaultStore())

	doc, err := op.Resolve(uniqueSuffix)

	require.Nil(t, err)
	require.NotNil(t, doc)
	require.NotEmpty(t, doc["@context"])
}

func TestDocumentNotFoundError(t *testing.T) {
	op := New(getDefaultStore())
	doc, err := op.Resolve(dummyUniqueSuffix)
	require.Nil(t, doc)
	require.NotNil(t, err)
	require.Equal(t, "uniqueSuffix not found in the store", err.Error())
}

func TestResolveMockStoreError(t *testing.T) {
	testErr := errors.New("test store error")
	store := mocks.NewMockOperationStore(testErr)
	p := New(store)

	doc, err := p.Resolve(uniqueSuffix)
	require.Nil(t, doc)
	require.NotNil(t, err)
	require.Equal(t, testErr, err)
}

func TestResolveError(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)

	createOp := batch.Operation{
		HashAlgorithmInMultiHashCode: sha2_256,
		UniqueSuffix:                 uniqueSuffix,
		Type:                         batch.OperationTypeCreate,
		EncodedPayload:               "invalid payload",
	}

	err := store.Put(createOp)
	require.Nil(t, err)

	p := New(store)
	doc, err := p.Resolve(uniqueSuffix)
	require.Nil(t, doc)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "illegal base64 data")
}

func TestUpdateDocument(t *testing.T) {
	store := getDefaultStore()

	updateOp := getUpdateOperation(uniqueSuffix, 1)
	err := store.Put(updateOp)
	require.Nil(t, err)

	p := New(store) //Storing operation in the test store
	doc, err := p.Resolve(uniqueSuffix)
	require.Nil(t, err)

	//updated instance value inside service end point through a json patch
	require.Equal(t, doc["service"], []interface{}{map[string]interface{}{
		"id": "IdentityHub",
		"serviceEndpoint": map[string]interface{}{
			"@context": "schema.identity.foundation/hub",
			"@type":    "UserServiceEndpoint",
			"instance": []interface{}{
				"did:sidetree:updateid1",
				"did:zaz:789"}},
		"type": "IdentityHub",
	}})
}

func TestUpdateDocument_InvalidOTP(t *testing.T) {
	store := getDefaultStore()

	updateOp := getUpdateOperation(uniqueSuffix, 77)
	err := store.Put(updateOp)
	require.Nil(t, err)

	p := New(store) //Storing operation in the test store
	doc, err := p.Resolve(uniqueSuffix)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "supplied hash doesn't match original content")
	require.Nil(t, doc)
}

func TestConsecutiveUpdates(t *testing.T) {
	store := getDefaultStore()

	updateOp := getUpdateOperation(uniqueSuffix, 1)
	err := store.Put(updateOp)
	require.Nil(t, err)

	updateOp = getUpdateOperation(uniqueSuffix, 2)
	err = store.Put(updateOp)
	require.Nil(t, err)

	p := New(store)
	doc, err := p.Resolve(uniqueSuffix)
	require.Nil(t, err)
	require.NotContains(t, doc["service"], "did:bar:456")

	//patched twice instance replaced from did:bar:456 to did:sidetree:updateid0  and then to did:sidetree:updateid1
	require.Equal(t, doc["service"], []interface{}{map[string]interface{}{
		"id": "IdentityHub",
		"serviceEndpoint": map[string]interface{}{
			"@context": "schema.identity.foundation/hub",
			"@type":    "UserServiceEndpoint",
			"instance": []interface{}{
				"did:sidetree:updateid2",
				"did:zaz:789"}},
		"type": "IdentityHub",
	}})
}

func TestProcessOperation_UpdateIsFirstOperation(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)

	updateOp := getUpdateOperation(uniqueSuffix, 1)
	err := store.Put(updateOp)
	require.Nil(t, err)

	p := New(store)
	doc, err := p.Resolve(uniqueSuffix)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Equal(t, "update cannot be first operation", err.Error())
}

func TestProcessOperation_CreateIsSecondOperation(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)
	store.Validate = false

	createOp := batch.Operation{
		HashAlgorithmInMultiHashCode: sha2_256,
		UniqueSuffix:                 uniqueSuffix,
		Type:                         batch.OperationTypeCreate,
		EncodedPayload:               encodedPayload,
	}

	// store create operation
	err := store.Put(createOp)
	require.Nil(t, err)

	// store create operation again
	err = store.Put(createOp)
	require.Nil(t, err)

	p := New(store)
	doc, err := p.Resolve(uniqueSuffix)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Equal(t, "create has to be the first operation", err.Error())
}

func TestProcessOperation_InvalidOperationType(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)

	createOp := batch.Operation{
		HashAlgorithmInMultiHashCode: sha2_256,
		UniqueSuffix:                 uniqueSuffix,
		Type:                         "invalid",
		EncodedPayload:               encodedPayload,
	}

	// store create operation
	err := store.Put(createOp)
	require.Nil(t, err)

	p := New(store)
	doc, err := p.Resolve(uniqueSuffix)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Equal(t, "operation type not supported for process operation", err.Error())
}

func TestIsValidHashErrors(t *testing.T) {
	multihash, err := docutil.ComputeMultihash(sha2_256, []byte("test"))
	require.NoError(t, err)

	encodedMultihash := docutil.EncodeToString(multihash)

	err = isValidHash("", encodedMultihash)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty bytes")

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

func getUpdateOperation(uniqueSuffix string, operationNumber uint) batch.Operation { //nolint:unparam
	patch := map[string]interface{}{
		"op":    "replace",
		"path":  "/service/0/serviceEndpoint/instance/0",
		"value": "did:sidetree:updateid" + strconv.Itoa(int(operationNumber)),
	}

	patchBytes, err := docutil.MarshalCanonical([]map[string]interface{}{patch})
	if err != nil {
		panic(err)
	}

	jsonPatch := jsonpatch.Patch{}
	err = json.Unmarshal(patchBytes, &jsonPatch)
	if err != nil {
		panic(err)
	}

	updatePayload := updatePayloadSchema{
		DidUniqueSuffix: uniqueSuffix,
		Patch:           jsonPatch,
	}

	return generateUpdateOperationBuffer(updatePayload, "#key1", uniqueSuffix, operationNumber)
}

func generateUpdateOperationBuffer(updatePayload updatePayloadSchema, keyID string, didUniqueSuffix string, operationNumber uint) batch.Operation { //nolint:unparam
	updatePayloadJSON, err := docutil.MarshalCanonical(updatePayload)
	if err != nil {
		panic(err)
	}

	encodedPayload := docutil.EncodeToString(updatePayloadJSON)

	nextUpdateOTPHash, err := docutil.ComputeMultihash(sha2_256, []byte(updateOTP+strconv.Itoa(int(operationNumber+1))))
	if err != nil {
		panic(err)
	}

	operation := batch.Operation{
		UniqueSuffix:                 didUniqueSuffix,
		HashAlgorithmInMultiHashCode: sha2_256,
		Patch:                        updatePayload.Patch,
		Type:                         batch.OperationTypeUpdate,
		EncodedPayload:               encodedPayload,
		TransactionNumber:            1,
		UpdateOTP:                    base64.URLEncoding.EncodeToString([]byte(updateOTP + strconv.Itoa(int(operationNumber)))),
		NextUpdateOTPHash:            base64.URLEncoding.EncodeToString(nextUpdateOTPHash),
	}
	return operation
}

//updatePayloadSchema is the struct for update payload
type updatePayloadSchema struct {
	//The unique suffix of the DID
	DidUniqueSuffix string

	//An RFC 6902 JSON patch to the current DID Document
	Patch jsonpatch.Patch
}

func getDefaultStore() *mocks.MockOperationStore {
	store := mocks.NewMockOperationStore(nil)

	nextUpdateOTPHash, err := docutil.ComputeMultihash(sha2_256, []byte(updateOTP+"1"))
	if err != nil {
		panic(err)
	}

	createOp := batch.Operation{
		HashAlgorithmInMultiHashCode: sha2_256,
		UniqueSuffix:                 uniqueSuffix,
		Type:                         batch.OperationTypeCreate,
		EncodedPayload:               encodedPayload,
		TransactionNumber:            0,
		NextUpdateOTPHash:            base64.URLEncoding.EncodeToString(nextUpdateOTPHash),
	}

	// store default create operation
	err = store.Put(createOp)
	if err != nil {
		panic(err)
	}

	return store
}
