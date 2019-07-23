/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package processor

import (
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

	updateOp := getUpdateOperation(uniqueSuffix, uniqueSuffix, 1)
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

func TestUpdateInvalidPreviousOperation(t *testing.T) {

	store := getDefaultStore()

	updateOp := getUpdateOperation(uniqueSuffix, "", 1)
	err := store.Put(updateOp)
	require.Nil(t, err)

	p := New(store)
	doc, err := p.Resolve(uniqueSuffix)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Equal(t, err.Error(), "any non-create needs a previous operation hash")
}

func TestUpdateMisMatchPreviousOperation(t *testing.T) {

	store := getDefaultStore()

	updateOp := getUpdateOperation(uniqueSuffix, "this is invalid operation hash", 1)
	err := store.Put(updateOp)
	require.Nil(t, err)

	p := New(store)
	doc, err := p.Resolve(uniqueSuffix)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Equal(t, "previous operation hash has to match the hash of the previous valid operation", err.Error())
}

func TestConsecutiveUpdates(t *testing.T) {

	store := getDefaultStore()

	updateOp := getUpdateOperation(uniqueSuffix, uniqueSuffix, 1)
	err := store.Put(updateOp)
	require.Nil(t, err)

	previousOperationHash, err := docutil.GetOperationHash(updateOp)
	require.Nil(t, err)

	updateOp = getUpdateOperation(uniqueSuffix, previousOperationHash, 2)
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

	updateOp := getUpdateOperation(uniqueSuffix, uniqueSuffix, 1)
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

func getUpdateOperation(uniqueSuffix string, previousOperationHash string, operationNumber uint) batch.Operation {

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
		DidUniqueSuffix:       uniqueSuffix,
		OperationNumber:       operationNumber,
		PreviousOperationHash: previousOperationHash,
		Patch:                 jsonPatch,
	}

	return generateUpdateOperationBuffer(updatePayload, "#key1", uniqueSuffix)
}

func generateUpdateOperationBuffer(updatePayload updatePayloadSchema, keyID string, didUniqueSuffix string) batch.Operation {

	updatePayloadJson, err := docutil.MarshalCanonical(updatePayload)
	if err != nil {
		panic(err)
	}

	encodedPayload := docutil.EncodeToString(updatePayloadJson)

	operation := batch.Operation{
		UniqueSuffix:                 didUniqueSuffix,
		HashAlgorithmInMultiHashCode: sha2_256,
		PreviousOperationHash:        updatePayload.PreviousOperationHash,
		Patch:                        updatePayload.Patch,
		Type:                         batch.OperationTypeUpdate,
		EncodedPayload:               encodedPayload,
	}
	return operation
}

//updatePayloadSchema is the struct for update payload
type updatePayloadSchema struct {
	//The unique suffix of the DID
	DidUniqueSuffix string
	//The number incremented from the last change version number. 1 if first change.
	OperationNumber uint
	//The hash of the previous operation made to the DID Document.
	PreviousOperationHash string
	//An RFC 6902 JSON patch to the current DID Document
	Patch jsonpatch.Patch
}

func getDefaultStore() *mocks.MockOperationStore {

	store := mocks.NewMockOperationStore(nil)

	createOp := batch.Operation{
		HashAlgorithmInMultiHashCode: sha2_256,
		UniqueSuffix:                 uniqueSuffix,
		Type:                         batch.OperationTypeCreate,
		EncodedPayload:               encodedPayload,
	}

	// store default create operation
	err := store.Put(createOp)
	if err != nil {
		panic(err)
	}

	return store

}
