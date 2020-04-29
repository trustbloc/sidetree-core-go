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
	"github.com/trustbloc/sidetree-core-go/pkg/internal/canonicalizer"
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

func TestParseSuffixData(t *testing.T) {
	suffixData, err := parseSuffixData(refEncodedSuffixData, sha2_256)
	require.NoError(t, err)
	require.NotNil(t, suffixData)
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

func TestParseDelta(t *testing.T) {
	// reference encoded delta fails because it contains 'replace' patch
	delta, err := parseDelta(refEncodedDelta, sha2_256)
	require.Error(t, err)
	require.Nil(t, delta)
	require.Contains(t, err.Error(), "action 'replace' is not supported")
}

func TestValidateDelta(t *testing.T) {
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

	deltaBytes, err := canonicalizer.MarshalCanonical(delta)
	if err != nil {
		return nil, err
	}

	suffixDataBytes, err := canonicalizer.MarshalCanonical(getSuffixData())
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
	patches, err := patch.PatchesFromDocument(validDoc)
	if err != nil {
		return nil, err
	}

	return &model.DeltaModel{
		Patches:          patches,
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

// samples are taken from reference implementation tests
const refEncodedDelta = `eyJ1cGRhdGVfY29tbWl0bWVudCI6IkVpRGl3YWI0b0EyTno2a25qSVp0dEctSzBSb05xVlJCM2lQbzJLT2Nvb3MyUlEiLCJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWduaW5nS2V5IiwidHlwZSI6IlNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkiLCJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoidHRzcFN6TnR0RUhoRk1CeG5BZUxEb0stLTJRTGVLeWFuTlVBQ3ZjUnFWVSIsInkiOiJtaTFvaFFONW93dWxRRlFiamQtOS05bG1uQ1piVGFSZ2Rta2hBcEVsVnRzIn0sInVzYWdlIjpbIm9wcyIsImF1dGgiLCJnZW5lcmFsIl19XSwic2VydmljZUVuZHBvaW50cyI6W3siaWQiOiJzZXJ2aWNlRW5kcG9pbnRJZDEyMyIsInR5cGUiOiJzb21lVHlwZSIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vd3d3LnVybC5jb20ifV19fV19`
const refEncodedSuffixData = `eyJkZWx0YV9oYXNoIjoiRWlEc0YySVZJV3oxSEN2eHpLS2ItXzVISW1PQVhZN2RkZUFyZURZVkYtVFRjUSIsInJlY292ZXJ5X2tleSI6eyJrdHkiOiJFQyIsImNydiI6InNlY3AyNTZrMSIsIngiOiJuWEdmTlN6ZU9pemZiYjlsZy1ZT1VYS0c0SWl1a2t5YmVtbXlZTGpYVmZ3IiwieSI6ImNsd0hobmNJRnd5ZHp4RTVTYnE5YjNHNGlZWXJHa0VULVhQUEFNaEx1TkUifSwicmVjb3ZlcnlfY29tbWl0bWVudCI6IkVpQWQzb2MydEtMeXR0eGJzSEZjel9MOUl1WEZNQ3NSOGlQMVl5R1VQU1V5T2cifQ`
