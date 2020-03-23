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
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

const (
	sha2_256          = 18
	dummyUniqueSuffix = "dummy"

	updateOTP   = "updateOTP"
	recoveryOTP = "recoveryOTP"
)

func TestResolve(t *testing.T) {
	op := New("test", getDefaultStore())

	doc, err := op.Resolve(getCreateOperation().UniqueSuffix)

	require.Nil(t, err)
	require.NotNil(t, doc)
}

func TestDocumentNotFoundError(t *testing.T) {
	op := New("test", getDefaultStore())
	doc, err := op.Resolve(dummyUniqueSuffix)
	require.Nil(t, doc)
	require.NotNil(t, err)
	require.Equal(t, "uniqueSuffix not found in the store", err.Error())
}

func TestResolveMockStoreError(t *testing.T) {
	testErr := errors.New("test store error")
	store := mocks.NewMockOperationStore(testErr)
	p := New("test", store)

	doc, err := p.Resolve(getCreateOperation().UniqueSuffix)
	require.Nil(t, doc)
	require.NotNil(t, err)
	require.Equal(t, testErr, err)
}

func TestResolveError(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)

	createOp := getCreateOperation()
	createOp.Document = "invalid payload"

	err := store.Put(createOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(createOp.UniqueSuffix)
	require.Nil(t, doc)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "invalid character")
}

func TestUpdateDocument(t *testing.T) {
	store := getDefaultStore()

	uniqueSuffix := getCreateOperation().UniqueSuffix

	updateOp := getUpdateOperation(uniqueSuffix, 1)
	err := store.Put(updateOp)
	require.Nil(t, err)

	p := New("test", store) //Storing operation in the test store
	doc, err := p.Resolve(uniqueSuffix)
	require.Nil(t, err)

	//updated instance value inside service end point through a json patch
	require.Equal(t, doc["publicKey"], []interface{}{map[string]interface{}{
		"controller":      "controller1",
		"id":              "#key-1",
		"publicKeyBase58": "GY4GunSXBPBfhLCzDL7iGmP5dR3sBDCJZkkaGK8VgYQf",
		"type":            "Ed25519VerificationKey2018",
	}})
}

func TestUpdateDocument_InvalidOTP(t *testing.T) {
	store := getDefaultStore()

	uniqueSuffix := getCreateOperation().UniqueSuffix

	updateOp := getUpdateOperation(uniqueSuffix, 77)
	err := store.Put(updateOp)
	require.Nil(t, err)

	p := New("test", store) //Storing operation in the test store
	doc, err := p.Resolve(uniqueSuffix)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "supplied hash doesn't match original content")
	require.Nil(t, doc)
}

func TestConsecutiveUpdates(t *testing.T) {
	store := getDefaultStore()

	uniqueSuffix := getCreateOperation().UniqueSuffix

	updateOp := getUpdateOperation(uniqueSuffix, 1)
	err := store.Put(updateOp)
	require.Nil(t, err)

	updateOp = getUpdateOperation(uniqueSuffix, 2)
	err = store.Put(updateOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(uniqueSuffix)
	require.Nil(t, err)

	//patched twice instance replaced from did:bar:456 to did:sidetree:updateid0  and then to did:sidetree:updateid1
	require.Equal(t, doc["publicKey"], []interface{}{map[string]interface{}{
		"controller":      "controller2",
		"id":              "#key-1",
		"publicKeyBase58": "GY4GunSXBPBfhLCzDL7iGmP5dR3sBDCJZkkaGK8VgYQf",
		"type":            "Ed25519VerificationKey2018",
	}})
}

func TestProcessOperation_UpdateIsFirstOperation(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)

	uniqueSuffix := getCreateOperation().UniqueSuffix

	updateOp := getUpdateOperation(uniqueSuffix, 1)
	err := store.Put(updateOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(uniqueSuffix)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Equal(t, "missing create operation", err.Error())
}

func TestProcessOperation_CreateIsSecondOperation(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)
	store.Validate = false

	createOp := getCreateOperation()

	// store create operation
	err := store.Put(createOp)
	require.Nil(t, err)

	// store create operation again
	err = store.Put(createOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(getCreateOperation().UniqueSuffix)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Equal(t, "create has to be the first operation", err.Error())
}

func TestProcessOperation_InvalidOperationType(t *testing.T) {
	store := mocks.NewMockOperationStore(nil)

	createOp := getCreateOperation()
	createOp.Type = "invalid"

	// store create operation
	err := store.Put(createOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(createOp.UniqueSuffix)
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Equal(t, "operation type not supported for process operation", err.Error())
}

func TestIsValidHashErrors(t *testing.T) {
	multihash, err := docutil.ComputeMultihash(sha2_256, []byte("test"))
	require.NoError(t, err)

	encodedMultihash := docutil.EncodeToString(multihash)

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

func TestRevoke(t *testing.T) {
	store := getDefaultStore()
	uniqueSuffix := getCreateOperation().UniqueSuffix

	revokeOp := getRevokeOperation(uniqueSuffix, 1)
	err := store.Put(revokeOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(uniqueSuffix)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "document was revoked")
	require.Nil(t, doc)
}

func TestConsecutiveRevoke(t *testing.T) {
	store := getDefaultStore()
	uniqueSuffix := getCreateOperation().UniqueSuffix

	revokeOp := getRevokeOperation(uniqueSuffix, 1)
	err := store.Put(revokeOp)
	require.Nil(t, err)

	revokeOp = getRevokeOperation(uniqueSuffix, 2)
	err = store.Put(revokeOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(uniqueSuffix)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "revoke can only be applied to an existing document")
	require.Nil(t, doc)
}

func TestRevoke_DocumentNotFound(t *testing.T) {
	store := getDefaultStore()

	revokeOp := getRevokeOperation(dummyUniqueSuffix, 0)
	err := store.Put(revokeOp)
	require.Nil(t, err)

	p := New("test", store)
	doc, err := p.Resolve(dummyUniqueSuffix)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "revoke can only be applied to an existing document")
	require.Nil(t, doc)
}

func TestRevoke_InvalidRecoveryOTP(t *testing.T) {
	store := getDefaultStore()

	uniqueSuffix := getCreateOperation().UniqueSuffix

	revokeOp := getRevokeOperation(uniqueSuffix, 1)
	revokeOp.RecoveryOTP = base64.URLEncoding.EncodeToString([]byte("invalid"))
	err := store.Put(revokeOp)
	require.NoError(t, err)

	p := New("test", store)
	doc, err := p.Resolve(uniqueSuffix)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "supplied hash doesn't match original content")
	require.Nil(t, doc)
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

func getUpdateOperation(uniqueSuffix string, operationNumber uint) *batch.Operation {
	patch := map[string]interface{}{
		"op":    "replace",
		"path":  "/publicKey/0/controller",
		"value": "controller" + strconv.Itoa(int(operationNumber)),
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

	nextUpdateOTPHash, err := docutil.ComputeMultihash(sha2_256, []byte(updateOTP+strconv.Itoa(int(operationNumber+1))))
	if err != nil {
		panic(err)
	}

	operation := &batch.Operation{
		ID:                           "did:sidetree:" + uniqueSuffix,
		UniqueSuffix:                 uniqueSuffix,
		HashAlgorithmInMultiHashCode: sha2_256,
		Patch:                        jsonPatch,
		Type:                         batch.OperationTypeUpdate,
		TransactionNumber:            uint64(operationNumber),
		UpdateOTP:                    base64.URLEncoding.EncodeToString([]byte(updateOTP + strconv.Itoa(int(operationNumber)))),
		NextUpdateOTPHash:            base64.URLEncoding.EncodeToString(nextUpdateOTPHash),
	}

	return operation
}

func getRevokeOperation(uniqueSuffix string, operationNumber uint) *batch.Operation {
	return &batch.Operation{
		ID:                "did:sidetree:" + uniqueSuffix,
		UniqueSuffix:      uniqueSuffix,
		Type:              batch.OperationTypeRevoke,
		TransactionTime:   0,
		TransactionNumber: uint64(operationNumber),
		RecoveryOTP:       base64.URLEncoding.EncodeToString([]byte(recoveryOTP)),
	}
}

func getDefaultStore() *mocks.MockOperationStore {
	store := mocks.NewMockOperationStore(nil)

	// store default create operation
	err := store.Put(getCreateOperation())
	if err != nil {
		panic(err)
	}

	return store
}

func getCreateOperation() *batch.Operation {
	nextUpdateOTPHash, err := docutil.ComputeMultihash(sha2_256, []byte(updateOTP+"1"))
	if err != nil {
		panic(err)
	}

	nextRecoveryOTPHash, err := docutil.ComputeMultihash(sha2_256, []byte(recoveryOTP))
	if err != nil {
		panic(err)
	}

	createRequest, err := getCreateRequest()
	if err != nil {
		panic(err)
	}

	operationBuffer, err := json.Marshal(createRequest)
	if err != nil {
		panic(err)
	}

	uniqueSuffix, err := docutil.CalculateUniqueSuffix(createRequest.SuffixData, sha2_256)
	if err != nil {
		panic(err)
	}

	return &batch.Operation{
		HashAlgorithmInMultiHashCode: sha2_256,
		ID:                           "did:sidetree:" + uniqueSuffix,
		UniqueSuffix:                 uniqueSuffix,
		Type:                         batch.OperationTypeCreate,
		OperationBuffer:              operationBuffer,
		Document:                     validDoc,
		TransactionNumber:            0,
		NextUpdateOTPHash:            base64.URLEncoding.EncodeToString(nextUpdateOTPHash),
		NextRecoveryOTPHash:          base64.URLEncoding.EncodeToString(nextRecoveryOTPHash),
	}
}

func getCreateRequest() (*model.CreateRequest, error) {
	operationDataBytes, err := docutil.MarshalCanonical(getOperationData())
	if err != nil {
		return nil, err
	}

	suffixDataBytes, err := docutil.MarshalCanonical(getSuffixData())
	if err != nil {
		return nil, err
	}

	return &model.CreateRequest{
		Operation:     model.OperationTypeCreate,
		OperationData: docutil.EncodeToString(operationDataBytes),
		SuffixData:    docutil.EncodeToString(suffixDataBytes),
	}, nil
}

func getOperationData() *model.CreateOperationData {
	return &model.CreateOperationData{
		Document:          validDoc,
		NextUpdateOTPHash: computeMultihash("updateOTP"),
	}
}

func getSuffixData() *model.SuffixDataSchema {
	return &model.SuffixDataSchema{
		OperationDataHash:   computeMultihash(validDoc),
		RecoveryKey:         model.PublicKey{PublicKeyHex: "HEX"},
		NextRecoveryOTPHash: computeMultihash("recoveryOTP"),
	}
}

func computeMultihash(data string) string {
	mh, err := docutil.ComputeMultihash(sha2_256, []byte(data))
	if err != nil {
		panic(err)
	}
	return docutil.EncodeToString(mh)
}

const validDoc = `{
	"publicKey": [{
		"controller": "id",
		"id": "#key-1",
		"publicKeyBase58": "GY4GunSXBPBfhLCzDL7iGmP5dR3sBDCJZkkaGK8VgYQf",
		"type": "Ed25519VerificationKey2018"
	}]
}`
