/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnprovider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/compression"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/client"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/operationparser"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/txnprovider/models"
)

//go:generate counterfeiter -o operationparser.gen.go --fake-name MockOperationParser . OperationParser

const (
	sha2_256  = 18
	defaultNS = "did:sidetree"
)

func TestNewOperationHandler(t *testing.T) {
	protocol := mocks.NewMockProtocolClient().Protocol

	handler := NewOperationHandler(
		protocol,
		mocks.NewMockCasClient(nil),
		compression.New(compression.WithDefaultAlgorithms()),
		operationparser.New(protocol))
	require.NotNil(t, handler)
}

func TestOperationHandler_PrepareTxnFiles(t *testing.T) {
	const createOpsNum = 2
	const recoverOpsNum = 1
	const deactivateOpsNum = 1
	const updateOpsNum = 1

	compression := compression.New(compression.WithDefaultAlgorithms())

	protocol := mocks.NewMockProtocolClient().Protocol

	t.Run("success", func(t *testing.T) {
		ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

		handler := NewOperationHandler(
			protocol,
			mocks.NewMockCasClient(nil),
			compression,
			operationparser.New(protocol))

		anchorString, refs, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)
		require.Equal(t, len(refs), createOpsNum+updateOpsNum+deactivateOpsNum+recoverOpsNum)

		anchorData, err := ParseAnchorData(anchorString)
		require.NoError(t, err)

		bytes, err := handler.cas.Read(anchorData.CoreIndexFileURI)
		require.NoError(t, err)
		require.NotNil(t, bytes)

		content, err := compression.Decompress(compressionAlgorithm, bytes)
		require.NoError(t, err)

		var cif models.CoreIndexFile
		err = json.Unmarshal(content, &cif)
		require.NoError(t, err)
		require.NotNil(t, cif)
		require.Equal(t, createOpsNum, len(cif.Operations.Create))
		require.Equal(t, recoverOpsNum, len(cif.Operations.Recover))
		require.Equal(t, deactivateOpsNum, len(cif.Operations.Deactivate))

		bytes, err = handler.cas.Read(cif.ProvisionalIndexFileURI)
		require.NoError(t, err)
		require.NotNil(t, bytes)

		content, err = compression.Decompress(compressionAlgorithm, bytes)
		require.NoError(t, err)

		var mf models.ProvisionalIndexFile
		err = json.Unmarshal(content, &mf)
		require.NoError(t, err)
		require.NotNil(t, mf)
		require.Equal(t, updateOpsNum, len(mf.Operations.Update))

		bytes, err = handler.cas.Read(mf.Chunks[0].ChunkFileURI)
		require.NoError(t, err)
		require.NotNil(t, bytes)

		content, err = compression.Decompress(compressionAlgorithm, bytes)
		require.NoError(t, err)

		var cf models.ChunkFile
		err = json.Unmarshal(content, &cf)
		require.NoError(t, err)
		require.NotNil(t, cf)
		require.Equal(t, createOpsNum+recoverOpsNum+updateOpsNum, len(cf.Deltas))

		bytes, err = handler.cas.Read(cif.CoreProofFileURI)
		require.NoError(t, err)
		require.NotNil(t, bytes)

		content, err = compression.Decompress(compressionAlgorithm, bytes)
		require.NoError(t, err)

		var cpf models.CoreProofFile
		err = json.Unmarshal(content, &cpf)
		require.NoError(t, err)
		require.NotNil(t, cpf)
		require.Equal(t, recoverOpsNum, len(cpf.Operations.Recover))
		require.Equal(t, deactivateOpsNum, len(cpf.Operations.Deactivate))

		bytes, err = handler.cas.Read(mf.ProvisionalProofFileURI)
		require.NoError(t, err)
		require.NotNil(t, bytes)

		content, err = compression.Decompress(compressionAlgorithm, bytes)
		require.NoError(t, err)

		var ppf models.ProvisionalProofFile
		err = json.Unmarshal(content, &ppf)
		require.NoError(t, err)
		require.NotNil(t, ppf)
		require.Equal(t, updateOpsNum, len(ppf.Operations.Update))
	})

	t.Run("success - no recover, deactivate or update ops", func(t *testing.T) {
		const zeroUpdateOps = 0
		const zeroRecoverOps = 0
		const zeroDeactiveOps = 0
		ops := getTestOperations(createOpsNum, zeroUpdateOps, zeroDeactiveOps, zeroRecoverOps)

		handler := NewOperationHandler(
			protocol,
			mocks.NewMockCasClient(nil),
			compression,
			operationparser.New(protocol))

		anchorString, refs, err := handler.PrepareTxnFiles(ops)
		require.NoError(t, err)
		require.NotEmpty(t, anchorString)
		require.Equal(t, len(refs), createOpsNum)

		anchorData, err := ParseAnchorData(anchorString)
		require.NoError(t, err)

		bytes, err := handler.cas.Read(anchorData.CoreIndexFileURI)
		require.NoError(t, err)
		require.NotNil(t, bytes)

		content, err := compression.Decompress(compressionAlgorithm, bytes)
		require.NoError(t, err)

		var cif models.CoreIndexFile
		err = json.Unmarshal(content, &cif)
		require.NoError(t, err)
		require.NotNil(t, cif)
		require.Equal(t, createOpsNum, len(cif.Operations.Create))
		require.Equal(t, zeroRecoverOps, len(cif.Operations.Recover))
		require.Equal(t, zeroDeactiveOps, len(cif.Operations.Deactivate))
		require.Empty(t, cif.CoreProofFileURI)

		bytes, err = handler.cas.Read(cif.ProvisionalIndexFileURI)
		require.NoError(t, err)
		require.NotNil(t, bytes)

		content, err = compression.Decompress(compressionAlgorithm, bytes)
		require.NoError(t, err)

		var pif models.ProvisionalIndexFile
		err = json.Unmarshal(content, &pif)
		require.NoError(t, err)
		require.NotNil(t, pif)
		require.Nil(t, pif.Operations)

		bytes, err = handler.cas.Read(pif.Chunks[0].ChunkFileURI)
		require.NoError(t, err)
		require.NotNil(t, bytes)

		content, err = compression.Decompress(compressionAlgorithm, bytes)
		require.NoError(t, err)

		var cf models.ChunkFile
		err = json.Unmarshal(content, &cf)
		require.NoError(t, err)
		require.NotNil(t, cf)
		require.Equal(t, createOpsNum+zeroRecoverOps+zeroUpdateOps, len(cf.Deltas))
	})

	t.Run("error - no operations provided", func(t *testing.T) {
		handler := NewOperationHandler(
			protocol,
			mocks.NewMockCasClient(nil),
			compression,
			operationparser.New(protocol))

		anchorString, refs, err := handler.PrepareTxnFiles(nil)
		require.Error(t, err)
		require.Empty(t, anchorString)
		require.Empty(t, refs)
		require.Contains(t, err.Error(), "prepare txn operations called without operations, should not happen")
	})

	t.Run("error - parse operation fails", func(t *testing.T) {
		handler := NewOperationHandler(
			protocol,
			mocks.NewMockCasClient(nil),
			compression,
			operationparser.New(protocol))

		op := &operation.QueuedOperation{
			OperationBuffer: []byte(`{"key":"value"}`),
			UniqueSuffix:    "suffix",
			Namespace:       defaultNS,
		}

		anchorString, refs, err := handler.PrepareTxnFiles([]*operation.QueuedOperation{op})
		require.Error(t, err)
		require.Empty(t, anchorString)
		require.Empty(t, refs)
		require.Contains(t, err.Error(), "parse operation: operation type [] not supported")
	})

	t.Run("error - write to CAS error for chunk file", func(t *testing.T) {
		ops := getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum)

		handler := NewOperationHandler(
			protocol,
			mocks.NewMockCasClient(errors.New("CAS error")),
			compression,
			operationparser.New(protocol))

		anchorString, _, err := handler.PrepareTxnFiles(ops)
		require.Error(t, err)
		require.Empty(t, anchorString)
		require.Contains(t, err.Error(), "failed to store chunk file: CAS error")
	})

	t.Run("error - write to CAS error for core index file", func(t *testing.T) {
		ops := getTestOperations(0, 0, deactivateOpsNum, 0)

		handler := NewOperationHandler(
			protocol,
			mocks.NewMockCasClient(errors.New("CAS error")),
			compression,
			operationparser.New(protocol))

		anchorString, refs, err := handler.PrepareTxnFiles(ops)
		require.Error(t, err)
		require.Empty(t, anchorString)
		require.Empty(t, refs)
		require.Contains(t, err.Error(), "failed to store core proof file: CAS error")
	})
}

func TestWriteModelToCAS(t *testing.T) {
	protocol := mocks.NewMockProtocolClient().Protocol

	handler := NewOperationHandler(
		protocol,
		mocks.NewMockCasClient(nil),
		compression.New(compression.WithDefaultAlgorithms()),
		operationparser.New(protocol))

	t.Run("success", func(t *testing.T) {
		address, err := handler.writeModelToCAS(&models.CoreIndexFile{}, "alias")
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
		handlerWithCASError := NewOperationHandler(
			protocol,
			mocks.NewMockCasClient(errors.New("CAS error")),
			compression.New(compression.WithDefaultAlgorithms()),
			operationparser.New(protocol))

		address, err := handlerWithCASError.writeModelToCAS(&models.CoreIndexFile{}, "alias")
		require.Error(t, err)
		require.Empty(t, address)
		require.Contains(t, err.Error(), "failed to store alias file: CAS error")
	})

	t.Run("error - compression error", func(t *testing.T) {
		pc := mocks.NewMockProtocolClient()
		pc.Protocol.CompressionAlgorithm = "invalid"

		handlerWithProtocolError := NewOperationHandler(
			pc.Protocol,
			mocks.NewMockCasClient(nil),
			compression.New(compression.WithDefaultAlgorithms()),
			operationparser.New(pc.Protocol),
		)

		address, err := handlerWithProtocolError.writeModelToCAS(&models.CoreIndexFile{}, "alias")
		require.Error(t, err)
		require.Empty(t, address)
		require.Contains(t, err.Error(), "compression algorithm 'invalid' not supported")
	})
}

func getTestOperations(createOpsNum, updateOpsNum, deactivateOpsNum, recoverOpsNum int) []*operation.QueuedOperation {
	var ops []*operation.QueuedOperation
	ops = append(ops, generateOperations(createOpsNum, operation.TypeCreate)...)
	ops = append(ops, generateOperations(recoverOpsNum, operation.TypeRecover)...)
	ops = append(ops, generateOperations(deactivateOpsNum, operation.TypeDeactivate)...)
	ops = append(ops, generateOperations(updateOpsNum, operation.TypeUpdate)...)

	return ops
}

func generateOperations(numOfOperations int, opType operation.Type) (ops []*operation.QueuedOperation) {
	for j := 1; j <= numOfOperations; j++ {
		op, err := generateOperationInfo(j, opType)
		if err != nil {
			panic(err)
		}

		ops = append(ops, op)
	}

	return
}

func generateOperationInfo(num int, opType operation.Type) (*operation.QueuedOperation, error) {
	op, err := generateOperationBuffer(num, opType)
	if err != nil {
		return nil, err
	}

	return &operation.QueuedOperation{
		OperationBuffer: op,
		UniqueSuffix:    fmt.Sprintf("%s-%d", opType, num),
		Namespace:       defaultNS,
	}, nil
}

func generateOperation(num int, opType operation.Type) (*model.Operation, error) {
	op, err := generateOperationBuffer(num, opType)
	if err != nil {
		return nil, err
	}

	cp, err := mocks.NewMockProtocolClient().Current()
	if err != nil {
		panic(err)
	}

	parser := operationparser.New(cp.Protocol())

	return parser.ParseOperation(defaultNS, op, false)
}

func generateOperationBuffer(num int, opType operation.Type) ([]byte, error) {
	switch opType {
	case operation.TypeCreate:
		return generateCreateOperation(num)
	case operation.TypeRecover:
		return generateRecoverOperation(num)
	case operation.TypeDeactivate:
		return generateDeactivateOperation(num)
	case operation.TypeUpdate:
		return generateUpdateOperation(num)
	default:
		return nil, errors.New("operation type not supported")
	}
}

func generateCreateOperation(num int) ([]byte, error) {
	recoverJWK := &jws.JWK{
		Crv: "crv",
		Kty: "kty",
		X:   "x",
	}

	updateJWK := &jws.JWK{
		Crv: "crv",
		Kty: "kty",
		X:   "x",
		Y:   "y",
	}

	recoverCommitment, err := commitment.GetCommitment(recoverJWK, sha2_256)
	if err != nil {
		return nil, err
	}

	updateCommitment, err := commitment.GetCommitment(updateJWK, sha2_256)
	if err != nil {
		return nil, err
	}

	doc := fmt.Sprintf(`{"test":%d}`, num)
	info := &client.CreateRequestInfo{
		OpaqueDocument:     doc,
		RecoveryCommitment: recoverCommitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      sha2_256,
	}

	return client.NewCreateRequest(info)
}

func generateRecoverOperation(num int) ([]byte, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	jwk, err := pubkey.GetPublicKeyJWK(&privKey.PublicKey)
	if err != nil {
		return nil, err
	}

	recoveryCommitment, err := generateUniqueCommitment()
	if err != nil {
		return nil, err
	}

	updateCommitment, err := generateUniqueCommitment()
	if err != nil {
		return nil, err
	}

	rv, err := commitment.GetRevealValue(jwk, sha2_256)
	if err != nil {
		return nil, err
	}

	info := &client.RecoverRequestInfo{
		DidSuffix:          fmt.Sprintf("recover-%d", num),
		OpaqueDocument:     `{"test":"value"}`,
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment,
		RecoveryKey:        jwk,
		MultihashCode:      sha2_256,
		Signer:             ecsigner.New(privKey, "ES256", ""),
		RevealValue:        rv,
	}

	return client.NewRecoverRequest(info)
}

func generateDeactivateOperation(num int) ([]byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	recoveryPubKey, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	rv, err := commitment.GetRevealValue(recoveryPubKey, sha2_256)
	if err != nil {
		return nil, err
	}

	info := &client.DeactivateRequestInfo{
		DidSuffix:   fmt.Sprintf("deactivate-%d", num),
		Signer:      ecsigner.New(privateKey, "ES256", ""),
		RecoveryKey: recoveryPubKey,
		RevealValue: rv,
	}

	return client.NewDeactivateRequest(info)
}

func generateUpdateOperation(num int) ([]byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	testPatch, err := getTestPatch()
	if err != nil {
		return nil, err
	}

	updateCommitment, err := generateUniqueCommitment()
	if err != nil {
		return nil, err
	}

	updatePubKey, err := pubkey.GetPublicKeyJWK(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	rv, err := commitment.GetRevealValue(updatePubKey, sha2_256)
	if err != nil {
		return nil, err
	}

	info := &client.UpdateRequestInfo{
		DidSuffix:        fmt.Sprintf("update-%d", num),
		Signer:           ecsigner.New(privateKey, "ES256", ""),
		UpdateCommitment: updateCommitment,
		UpdateKey:        updatePubKey,
		Patches:          []patch.Patch{testPatch},
		MultihashCode:    sha2_256,
		RevealValue:      rv,
	}

	return client.NewUpdateRequest(info)
}

func getTestPatch() (patch.Patch, error) {
	return patch.NewJSONPatch(`[{"op": "replace", "path": "/name", "value": "Jane"}]`)
}

func generateUniqueCommitment() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}

	pubKey, err := pubkey.GetPublicKeyJWK(&key.PublicKey)
	if err != nil {
		return "", err
	}

	c, err := commitment.GetCommitment(pubKey, sha2_256)
	if err != nil {
		return "", err
	}

	return c, nil
}
