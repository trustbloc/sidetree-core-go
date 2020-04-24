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
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
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
		require.Contains(t, err.Error(), "invalid character")
		require.Nil(t, op)
	})
	t.Run("parse patch data error", func(t *testing.T) {
		create, err := getCreateRequest()
		require.NoError(t, err)

		create.Delta = invalid
		request, err := json.Marshal(create)
		require.NoError(t, err)

		op, err := ParseCreateOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
		require.Nil(t, op)
	})
}

func TestValidateSuffixData(t *testing.T) {
	t.Run("missing recovery key", func(t *testing.T) {
		suffixData := getSuffixData()
		suffixData.RecoveryKey = nil
		err := validateSuffixData(suffixData, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"missing recovery key")
	})
	t.Run("validate recovery key error", func(t *testing.T) {
		suffixData := getSuffixData()
		suffixData.RecoveryKey = &jws.JWK{
			Kty: "kty",
			Crv: "curve",
		}
		err := validateSuffixData(suffixData, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"x is missing")
	})
	t.Run("invalid patch data hash", func(t *testing.T) {
		suffixData := getSuffixData()
		suffixData.DeltaHash = ""
		err := validateSuffixData(suffixData, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(), "patch data hash is not computed with the latest supported hash algorithm")
	})
	t.Run("invalid next recovery commitment hash", func(t *testing.T) {
		suffixData := getSuffixData()
		suffixData.RecoveryCommitment = ""
		err := validateSuffixData(suffixData, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(), "next recovery commitment hash is not computed with the latest supported hash algorithm")
	})
}

func TestValidatedelta(t *testing.T) {
	t.Run("invalid next update commitment hash", func(t *testing.T) {
		delta, err := getDelta()
		require.NoError(t, err)

		delta.UpdateCommitment = ""
		err = validateDelta(delta, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"next update commitment hash is not computed with the latest supported hash algorithm")
	})
	t.Run("missing patches", func(t *testing.T) {
		delta, err := getDelta()
		require.NoError(t, err)

		delta.Patches = []patch.Patch{}
		err = validateDelta(delta, sha2_256)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"missing patches")
	})
}

func TestValidateCreateRequest(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		create, err := getCreateRequest()
		require.NoError(t, err)

		err = validateCreateRequest(create)
		require.NoError(t, err)
	})

	t.Run("missing suffix data", func(t *testing.T) {
		create, err := getCreateRequest()
		require.NoError(t, err)
		create.SuffixData = ""

		err = validateCreateRequest(create)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing suffix data")
	})
	t.Run("missing delta", func(t *testing.T) {
		create, err := getCreateRequest()
		require.NoError(t, err)
		create.Delta = ""

		err = validateCreateRequest(create)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing delta")
	})
}

func getCreateRequest() (*model.CreateRequest, error) {
	delta, err := getDelta()
	if err != nil {
		return nil, err
	}

	deltaBytes, err := docutil.MarshalCanonical(delta)
	if err != nil {
		return nil, err
	}

	suffixDataBytes, err := docutil.MarshalCanonical(getSuffixData())
	if err != nil {
		return nil, err
	}

	return &model.CreateRequest{
		Operation:  model.OperationTypeCreate,
		Delta:      docutil.EncodeToString(deltaBytes),
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

func getDelta() (*model.DeltaModel, error) {
	replacePatch, err := patch.NewReplacePatch(validDoc)
	if err != nil {
		return nil, err
	}

	return &model.DeltaModel{
		Patches:          []patch.Patch{replacePatch},
		UpdateCommitment: computeMultihash("updateReveal"),
	}, nil
}

func getSuffixData() *model.SuffixDataModel {
	return &model.SuffixDataModel{
		DeltaHash: computeMultihash(validDoc),
		RecoveryKey: &jws.JWK{
			Kty: "kty",
			Crv: "crv",
			X:   "x",
		},
		RecoveryCommitment: computeMultihash("recoveryReveal"),
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
	"publicKey": [
		{
		  "id": "key1",
		  "type": "JwsVerificationKey2020",
		  "usage": ["ops", "general"],
		  "jwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		  }
		}
	]
}`
