/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnhandler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/helper"
	"github.com/trustbloc/sidetree-core-go/pkg/txnhandler/models"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
)

const sha2_256 = 18
const defaultNS = "did:sidetree"

func TestNewOperationHandler(t *testing.T) {
	handler := NewOperationHandler(mocks.NewMockCasClient(nil))
	require.NotNil(t, handler)
}

func TestOperationHandler_PrepareTxnFiles(t *testing.T) {
	const createOpsNum = 2
	const recoverOpsNum = 1
	const deactivateOpsNum = 1
	const updateOpsNum = 1

	t.Run("success", func(t *testing.T) {
		ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

		handler := NewOperationHandler(mocks.NewMockCasClient(nil))

		anchorString, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)

		anchorData, err := ParseAnchorData(anchorString)
		require.NoError(t, err)

		bytes, err := handler.cas.Read(anchorData.AnchorAddress)
		require.NoError(t, err)
		require.NotNil(t, bytes)

		var af models.AnchorFile
		err = json.Unmarshal(bytes, &af)
		require.NoError(t, err)
		require.NotNil(t, af)
		require.Equal(t, createOpsNum, len(af.Operations.Create))
		require.Equal(t, recoverOpsNum, len(af.Operations.Recover))
		require.Equal(t, deactivateOpsNum, len(af.Operations.Deactivate))
		require.Equal(t, 0, len(af.Operations.Update))

		bytes, err = handler.cas.Read(af.MapFileHash)
		require.NoError(t, err)
		require.NotNil(t, bytes)

		var mf models.MapFile
		err = json.Unmarshal(bytes, &mf)
		require.NoError(t, err)
		require.NotNil(t, mf)
		require.Equal(t, updateOpsNum, len(mf.Operations.Update))
		require.Equal(t, 0, len(mf.Operations.Create))
		require.Equal(t, 0, len(mf.Operations.Recover))
		require.Equal(t, 0, len(mf.Operations.Deactivate))

		bytes, err = handler.cas.Read(mf.Chunks[0].ChunkFileURI)
		require.NoError(t, err)
		require.NotNil(t, bytes)

		var cf models.ChunkFile
		err = json.Unmarshal(bytes, &cf)
		require.NoError(t, err)
		require.NotNil(t, cf)
		require.Equal(t, createOpsNum+recoverOpsNum+updateOpsNum, len(cf.Deltas))
	})

	t.Run("error - write to CAS error for chunk file", func(t *testing.T) {
		ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

		handler := NewOperationHandler(mocks.NewMockCasClient(errors.New("CAS error")))

		anchorString, err := handler.PrepareTxnFiles(ops)
		require.Error(t, err)
		require.Empty(t, anchorString)
		require.Contains(t, err.Error(), "failed to store chunk file: CAS error")
	})

	t.Run("error - write to CAS error for anchor file", func(t *testing.T) {
		ops := getTestOperations(0, 0, deactivateOpsNum, 0)

		handler := NewOperationHandler(mocks.NewMockCasClient(errors.New("CAS error")))

		anchorString, err := handler.PrepareTxnFiles(ops)
		require.Error(t, err)
		require.Empty(t, anchorString)
		require.Contains(t, err.Error(), "failed to store anchor file: CAS error")
	})
}

func TestWriteModelToCAS(t *testing.T) {
	handler := NewOperationHandler(mocks.NewMockCasClient(nil))

	t.Run("success", func(t *testing.T) {
		address, err := handler.writeModelToCAS(&models.AnchorFile{}, "alias")
		require.NoError(t, err)
		require.NotEmpty(t, address)
	})

	t.Run("error - marshal fails", func(t *testing.T) {
		address, err := handler.writeModelToCAS("test", "alias")
		require.Error(t, err)
		require.Empty(t, address)
		require.Contains(t, err.Error(), "failed to marshal alias file")
	})

	t.Run("error - CAS error", func(t *testing.T) {
		handlerWithCASError := NewOperationHandler(mocks.NewMockCasClient(errors.New("CAS error")))

		address, err := handlerWithCASError.writeModelToCAS(&models.AnchorFile{}, "alias")
		require.Error(t, err)
		require.Empty(t, address)
		require.Contains(t, err.Error(), "failed to store alias file: CAS error")
	})
}

func getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum int) []*batch.Operation {
	var ops []*batch.Operation
	ops = append(ops, generateOperations(createOpsNum, batch.OperationTypeCreate)...)
	ops = append(ops, generateOperations(recoverOpsNum, batch.OperationTypeRecover)...)
	ops = append(ops, generateOperations(deactivateOpsNum, batch.OperationTypeDeactivate)...)
	ops = append(ops, generateOperations(updateOpsNum, batch.OperationTypeUpdate)...)

	return ops
}

func generateOperations(numOfOperations int, opType batch.OperationType) (ops []*batch.Operation) {
	for j := 1; j <= numOfOperations; j++ {
		op, err := generateOperation(j, opType)
		if err != nil {
			panic(err)
		}

		ops = append(ops, op)
	}
	return
}

func generateOperation(num int, opType batch.OperationType) (*batch.Operation, error) {
	switch opType {
	case batch.OperationTypeCreate:
		return generateCreateOperation(num)
	case batch.OperationTypeRecover:
		return generateRecoverOperation(num)
	case batch.OperationTypeDeactivate:
		return generateDeactivateOperation(num)
	case batch.OperationTypeUpdate:
		return generateUpdateOperation(num)
	}

	return nil, errors.New("operation type not supported")
}

func generateCreateOperation(num int) (*batch.Operation, error) {
	doc := fmt.Sprintf(`{"test":%d}`, num)
	info := &helper.CreateRequestInfo{OpaqueDocument: doc,
		RecoveryKey: &jws.JWK{
			Crv: "crv",
			Kty: "kty",
			X:   "x",
		},
		MultihashCode: sha2_256}

	request, err := helper.NewCreateRequest(info)
	if err != nil {
		return nil, err
	}

	return operation.ParseOperation(defaultNS, request, mocks.NewMockProtocolClient().Current())
}

func generateRecoverOperation(num int) (*batch.Operation, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	jwk, err := pubkey.GetPublicKeyJWK(&privKey.PublicKey)
	if err != nil {
		return nil, err
	}

	info := &helper.RecoverRequestInfo{
		DidSuffix:      fmt.Sprintf("did:sidetree:recover-%d", num),
		OpaqueDocument: `{"test":"value"}`,
		RecoveryKey:    jwk,
		MultihashCode:  sha2_256,
		Signer:         ecsigner.New(privKey, "ES256", "")}

	request, err := helper.NewRecoverRequest(info)
	if err != nil {
		return nil, err
	}
	return operation.ParseOperation(defaultNS, request, mocks.NewMockProtocolClient().Current())
}

func generateDeactivateOperation(num int) (*batch.Operation, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	info := &helper.DeactivateRequestInfo{
		DidSuffix: fmt.Sprintf("did:sidetree:deactivate-%d", num),
		Signer:    ecsigner.New(privateKey, "ES256", "")}

	request, err := helper.NewDeactivateRequest(info)
	if err != nil {
		return nil, err
	}

	return operation.ParseOperation(defaultNS, request, mocks.NewMockProtocolClient().Current())
}

func generateUpdateOperation(num int) (*batch.Operation, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	testPatch, err := getTestPatch()
	if err != nil {
		return nil, err
	}

	info := &helper.UpdateRequestInfo{
		DidSuffix:     fmt.Sprintf("did:sidetree:update-%d", num),
		Signer:        ecsigner.New(privateKey, "ES256", "key-1"),
		Patch:         testPatch,
		MultihashCode: sha2_256,
	}

	request, err := helper.NewUpdateRequest(info)
	if err != nil {
		return nil, err
	}

	return operation.ParseOperation(defaultNS, request, mocks.NewMockProtocolClient().Current())
}

func getTestPatch() (patch.Patch, error) {
	return patch.NewJSONPatch(`[{"op": "replace", "path": "/name", "value": "Jane"}]`)
}
