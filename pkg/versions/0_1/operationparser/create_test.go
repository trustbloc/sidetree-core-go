/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationparser

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/encoder"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
)

const invalid = "invalid"

func TestParseCreateOperation(t *testing.T) {
	p := protocol.Protocol{
		MultihashAlgorithm: sha2_256,
		Patches:            []string{"replace", "add-public-keys", "remove-public-keys", "add-services", "remove-services", "ietf-json-patch"},
	}

	parser := New(p)

	t.Run("success", func(t *testing.T) {
		request, err := getCreateRequestBytes()
		require.NoError(t, err)

		op, err := parser.ParseCreateOperation(request, false)
		require.NoError(t, err)
		require.Equal(t, operation.TypeCreate, op.Type)
	})

	t.Run("success - JCS", func(t *testing.T) {
		op, err := parser.ParseCreateOperation([]byte(jcsRequest), true)
		require.NoError(t, err)
		require.Equal(t, operation.TypeCreate, op.Type)
	})

	t.Run("parse create request error", func(t *testing.T) {
		schema, err := parser.ParseCreateOperation([]byte(""), true)
		require.Error(t, err)
		require.Nil(t, schema)
		require.Contains(t, err.Error(), "unexpected end of JSON input")
	})
	t.Run("missing suffix data", func(t *testing.T) {
		create, err := getCreateRequest()
		require.NoError(t, err)
		create.SuffixData = nil

		request, err := json.Marshal(create)
		require.NoError(t, err)

		op, err := parser.ParseCreateOperation(request, true)
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(), "missing suffix data")
	})

	t.Run("parse suffix data error", func(t *testing.T) {
		create, err := getCreateRequest()
		require.NoError(t, err)

		create.SuffixData = &model.SuffixDataModel{}
		request, err := json.Marshal(create)
		require.NoError(t, err)

		op, err := parser.ParseCreateOperation(request, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "next recovery commitment hash is not computed with the required supported hash algorithm: 18")
		require.Nil(t, op)
	})
	t.Run("missing delta", func(t *testing.T) {
		create, err := getCreateRequest()
		require.NoError(t, err)
		create.Delta = nil

		request, err := json.Marshal(create)
		require.NoError(t, err)

		op, err := parser.ParseCreateOperation(request, false)
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(), "missing delta")
	})

	t.Run("missing delta is ok in anchor mode", func(t *testing.T) {
		create, err := getCreateRequest()
		require.NoError(t, err)
		create.Delta = nil

		request, err := json.Marshal(create)
		require.NoError(t, err)

		op, err := parser.ParseCreateOperation(request, true)
		require.NoError(t, err)
		require.NotNil(t, op)
		require.Nil(t, op.Delta)
	})

	t.Run("parse patch data error", func(t *testing.T) {
		create, err := getCreateRequest()
		require.NoError(t, err)

		create.Delta = &model.DeltaModel{}
		request, err := json.Marshal(create)
		require.NoError(t, err)

		op, err := parser.ParseCreateOperation(request, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing patches")
		require.Nil(t, op)
	})

	t.Run("delta doesn't match suffix data delta hash", func(t *testing.T) {
		create, err := getCreateRequest()
		require.NoError(t, err)

		delta, err := getDelta()
		delta.UpdateCommitment = computeMultihash([]byte("different"))

		create.Delta = delta
		request, err := json.Marshal(create)
		require.NoError(t, err)

		op, err := parser.ParseCreateOperation(request, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "delta doesn't match suffix data delta hash")
		require.Nil(t, op)
	})
}

func TestValidateSuffixData(t *testing.T) {
	p := protocol.Protocol{
		MultihashAlgorithm: sha2_256,
	}

	parser := New(p)

	t.Run("invalid patch data hash", func(t *testing.T) {
		suffixData, err := getSuffixData()
		require.NoError(t, err)

		suffixData.DeltaHash = ""
		err = parser.ValidateSuffixData(suffixData)
		require.Error(t, err)
		require.Contains(t, err.Error(), "patch data hash is not computed with the required supported hash algorithm")
	})
	t.Run("invalid next recovery commitment hash", func(t *testing.T) {
		suffixData, err := getSuffixData()
		require.NoError(t, err)

		suffixData.RecoveryCommitment = ""
		err = parser.ValidateSuffixData(suffixData)
		require.Error(t, err)
		require.Contains(t, err.Error(), "next recovery commitment hash is not computed with the required supported hash algorithm")
	})
}

func TestValidateDelta(t *testing.T) {
	p := protocol.Protocol{
		MultihashAlgorithm: sha2_256,
		Patches:            []string{"add-public-keys", "remove-public-keys", "add-services", "remove-services", "ietf-json-patch"},
	}

	parser := New(p)

	t.Run("invalid next update commitment hash", func(t *testing.T) {
		delta, err := getDelta()
		require.NoError(t, err)

		delta.UpdateCommitment = ""
		err = parser.ValidateDelta(delta)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"next update commitment hash is not computed with the required supported hash algorithm")
	})
	t.Run("missing patches", func(t *testing.T) {
		delta, err := getDelta()
		require.NoError(t, err)

		delta.Patches = []patch.Patch{}
		err = parser.ValidateDelta(delta)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"missing patches")
	})
}

func TestValidateCreateRequest(t *testing.T) {
	p := protocol.Protocol{}

	parser := New(p)

	t.Run("success", func(t *testing.T) {
		create, err := getCreateRequest()
		require.NoError(t, err)

		err = parser.validateCreateRequest(create)
		require.NoError(t, err)
	})

	t.Run("missing suffix data", func(t *testing.T) {
		create, err := getCreateRequest()
		require.NoError(t, err)
		create.SuffixData = nil

		err = parser.validateCreateRequest(create)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing suffix data")
	})
}

func getCreateRequest() (*model.CreateRequest, error) {
	delta, err := getDelta()
	if err != nil {
		return nil, err
	}

	suffixData, err := getSuffixData()
	if err != nil {
		return nil, err
	}

	return &model.CreateRequest{
		Operation:  operation.TypeCreate,
		Delta:      delta,
		SuffixData: suffixData,
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
	patches, err := patch.PatchesFromDocument(validDoc)
	if err != nil {
		return nil, err
	}

	return &model.DeltaModel{
		Patches:          patches,
		UpdateCommitment: computeMultihash([]byte("updateReveal")),
	}, nil
}

func getSuffixData() (*model.SuffixDataModel, error) {
	jwk := &jws.JWK{
		Kty: "kty",
		Crv: "crv",
		X:   "x",
	}

	recoveryCommitment, err := commitment.Calculate(jwk, sha2_256)
	if err != nil {
		return nil, err
	}

	delta, err := getDelta()
	if err != nil {
		return nil, err
	}

	deltaHash, err := hashing.CalculateModelMultihash(delta, sha2_256)
	if err != nil {
		return nil, err
	}

	return &model.SuffixDataModel{
		DeltaHash:          deltaHash,
		RecoveryCommitment: recoveryCommitment,
	}, nil
}

func computeMultihash(data []byte) string {
	mh, err := hashing.ComputeMultihash(sha2_256, data)
	if err != nil {
		panic(err)
	}

	return encoder.EncodeToString(mh)
}

const validDoc = `{
	"publicKey": [
		{
		  "id": "key1",
		  "type": "JsonWebKey2020",
		  "purposes": ["authentication"],
		  "publicKeyJwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		  }
		}
	]
}`

// samples bellow are taken from reference implementation tests.
const (
	jcsRequest = `{"delta":{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"anySigningKeyId","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"H61vqAm_-TC3OrFSqPrEfSfg422NR8QHPqr0mLx64DM","y":"s0WnWY87JriBjbyoY3FdUmifK7JJRLR65GtPthXeyuc"},"purposes":["authentication"],"type":"EcdsaSecp256k1VerificationKey2019"}],"services":[{"serviceEndpoint":"http://any.endpoint","id":"anyServiceEndpointId","type":"anyType"}]}}],"updateCommitment":"EiBMWE2JFaFipPdthcFiQek-SXTMi5IWIFXAN8hKFCyLJw"},"suffixData":{"deltaHash":"EiBP6gAOxx3YOL8PZPZG3medFgdqWSDayVX3u1W2f-IPEQ","recoveryCommitment":"EiBg8oqvU0Zq_H5BoqmWf0IrhetQ91wXc5fDPpIjB9wW5w"},"type":"create"}`
)
