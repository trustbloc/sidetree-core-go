/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

const invalid = "invalid"

func TestParseCreateOperation(t *testing.T) {
	p := protocol.Protocol{
		HashAlgorithmInMultiHashCode: sha2_256,
	}

	t.Run("success", func(t *testing.T) {
		request, err := getCreateRequestBytes()
		require.NoError(t, err)

		op, err := ParseCreateOperation(request, p)
		require.NoError(t, err)
		require.Equal(t, batch.OperationTypeCreate, op.Type)
	})
	t.Run("parse create request error", func(t *testing.T) {
		schema, err := ParseCreateOperation([]byte(""), p)
		require.Error(t, err)
		require.Nil(t, schema)
		require.Contains(t, err.Error(), "unexpected end of JSON input")
	})
	t.Run("parse suffix data error", func(t *testing.T) {
		create, err := getCreateRequest()
		require.NoError(t, err)

		create.SuffixData = invalid
		request, err := json.Marshal(create)
		require.NoError(t, err)

		op, err := ParseCreateOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "illegal base64 data")
		require.Nil(t, op)
	})
	t.Run("parse patch data error", func(t *testing.T) {
		create, err := getCreateRequest()
		require.NoError(t, err)

		create.PatchData = invalid
		request, err := json.Marshal(create)
		require.NoError(t, err)

		op, err := ParseCreateOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "illegal base64 data")
		require.Nil(t, op)
	})
}

func TestValidateSuffixData(t *testing.T) {
	t.Run("missing recovery key", func(t *testing.T) {
		suffixData := getSuffixData()
		suffixData.RecoveryKey.PublicKeyHex = ""
		err := validateSuffixData(suffixData, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"missing recovery key")
	})
	t.Run("invalid patch data hash", func(t *testing.T) {
		suffixData := getSuffixData()
		suffixData.PatchDataHash = ""
		err := validateSuffixData(suffixData, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(), "patch data hash is not computed with the latest supported hash algorithm")
	})
	t.Run("invalid next recovery OTP hash", func(t *testing.T) {
		suffixData := getSuffixData()
		suffixData.NextRecoveryOTPHash = ""
		err := validateSuffixData(suffixData, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(), "next recovery OTP hash is not computed with the latest supported hash algorithm")
	})
}

func TestValidatePatchData(t *testing.T) {
	t.Run("invalid next update OTP", func(t *testing.T) {
		patchData := getPatchData()
		patchData.NextUpdateOTPHash = ""
		err := validatePatchData(patchData, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"next update OTP hash is not computed with the latest supported hash algorithm")
	})
	t.Run("missing patches", func(t *testing.T) {
		patchData := getPatchData()
		patchData.Patches = []patch.Patch{}
		err := validatePatchData(patchData, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"missing patches")
	})
}

func getCreateRequest() (*model.CreateRequest, error) {
	patchDataBytes, err := docutil.MarshalCanonical(getPatchData())
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

func getCreateRequestBytes() ([]byte, error) {
	req, err := getCreateRequest()
	if err != nil {
		return nil, err
	}

	return json.Marshal(req)
}

func getPatchData() *model.PatchDataModel {
	return &model.PatchDataModel{
		Patches:           []patch.Patch{patch.NewReplacePatch(validDoc)},
		NextUpdateOTPHash: computeMultihash("updateOTP"),
	}
}

func getSuffixData() *model.SuffixDataModel {
	return &model.SuffixDataModel{
		PatchDataHash:       computeMultihash(validDoc),
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
		"id": "#key-1",
		"publicKeyBase58": "GY4GunSXBPBfhLCzDL7iGmP5dR3sBDCJZkkaGK8VgYQf",
		"type": "Ed25519VerificationKey2018"
	}]
}`
