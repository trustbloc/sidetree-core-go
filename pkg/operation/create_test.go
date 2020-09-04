/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"crypto"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
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
	t.Run("missing suffix data", func(t *testing.T) {
		create, err := getCreateRequest()
		require.NoError(t, err)
		create.SuffixData = ""

		request, err := json.Marshal(create)
		require.NoError(t, err)

		op, err := ParseCreateOperation(request, p)
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(), "missing suffix data")
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

	t.Run("delta doesn't match suffix data delta hash", func(t *testing.T) {
		create, err := getCreateRequest()
		require.NoError(t, err)

		delta, err := getDelta()
		delta.UpdateCommitment = computeMultihash([]byte("different"))

		deltaBytes, err := canonicalizer.MarshalCanonical(delta)
		require.NoError(t, err)

		create.Delta = docutil.EncodeToString(deltaBytes)
		request, err := json.Marshal(create)
		require.NoError(t, err)

		op, err := ParseCreateOperation(request, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "delta doesn't match suffix data delta hash")
		require.Nil(t, op)
	})
}

func TestParseSuffixData(t *testing.T) {
	p := protocol.Protocol{
		HashAlgorithmInMultiHashCode: sha2_256,
	}

	suffixData, err := ParseSuffixData(interopEncodedSuffixData, p)
	require.NoError(t, err)
	require.NotNil(t, suffixData)

	suffix, err := docutil.CalculateUniqueSuffix(interopEncodedSuffixData, p.HashAlgorithmInMultiHashCode)
	require.NoError(t, err)
	require.Equal(t, interopExpectedSuffix, suffix)
}

func TestValidateSuffixData(t *testing.T) {
	p := protocol.Protocol{
		HashAlgorithmInMultiHashCode: sha2_256,
	}

	t.Run("invalid patch data hash", func(t *testing.T) {
		suffixData, err := getSuffixData()
		require.NoError(t, err)

		suffixData.DeltaHash = ""
		err = validateSuffixData(suffixData, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "patch data hash is not computed with the required supported hash algorithm")
	})
	t.Run("invalid next recovery commitment hash", func(t *testing.T) {
		suffixData, err := getSuffixData()
		require.NoError(t, err)

		suffixData.RecoveryCommitment = ""
		err = validateSuffixData(suffixData, p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "next recovery commitment hash is not computed with the required supported hash algorithm")
	})
}

func TestParseDelta(t *testing.T) {
	t.Run("success - replace patch enabled", func(t *testing.T) {
		p := protocol.Protocol{
			HashAlgorithmInMultiHashCode: sha2_256,
			EnableReplacePatch:           true,
		}

		delta, err := ParseDelta(interopEncodedDelta, p)
		require.NoError(t, err)
		require.NotNil(t, delta)
	})
	t.Run("error - replace patch disabled (default)", func(t *testing.T) {
		p := protocol.Protocol{
			HashAlgorithmInMultiHashCode: sha2_256,
		}

		delta, err := ParseDelta(interopEncodedDelta, p)
		require.Error(t, err)
		require.Nil(t, delta)
		require.Contains(t, err.Error(), "replace patch action is not enabled")
	})
}

func TestValidateDelta(t *testing.T) {
	p := protocol.Protocol{
		HashAlgorithmInMultiHashCode: sha2_256,
	}

	t.Run("invalid next update commitment hash", func(t *testing.T) {
		delta, err := getDelta()
		require.NoError(t, err)

		delta.UpdateCommitment = ""
		err = validateDelta(delta, p)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"next update commitment hash is not computed with the required supported hash algorithm")
	})
	t.Run("missing patches", func(t *testing.T) {
		delta, err := getDelta()
		require.NoError(t, err)

		delta.Patches = []patch.Patch{}
		err = validateDelta(delta, p)
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

	suffixData, err := getSuffixData()
	if err != nil {
		return nil, err
	}

	suffixDataBytes, err := canonicalizer.MarshalCanonical(suffixData)
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
		UpdateCommitment: computeMultihash([]byte("updateReveal")),
	}, nil
}

func getSuffixData() (*model.SuffixDataModel, error) {
	jwk := &jws.JWK{
		Kty: "kty",
		Crv: "crv",
		X:   "x",
	}

	recoveryCommitment, err := commitment.Calculate(jwk, sha2_256, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	delta, err := getDelta()
	if err != nil {
		return nil, err
	}

	deltaBytes, err := canonicalizer.MarshalCanonical(delta)
	if err != nil {
		return nil, err
	}

	return &model.SuffixDataModel{
		DeltaHash:          computeMultihash(deltaBytes),
		RecoveryCommitment: recoveryCommitment,
	}, nil
}
func computeMultihash(data []byte) string {
	mh, err := docutil.ComputeMultihash(sha2_256, data)
	if err != nil {
		panic(err)
	}
	return docutil.EncodeToString(mh)
}

const validDoc = `{
	"publicKey": [
		{
		  "id": "key1",
		  "type": "JsonWebKey2020",
		  "purpose": ["general"],
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
const interopEncodedDelta = `eyJ1cGRhdGVfY29tbWl0bWVudCI6IkVpQ0lQY1hCempqUWFKVUljUjUyZXVJMHJJWHpoTlpfTWxqc0tLOXp4WFR5cVEiLCJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljX2tleXMiOlt7ImlkIjoic2lnbmluZ0tleSIsInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkiLCJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoieTlrenJWQnFYeDI0c1ZNRVFRazRDZS0wYnFaMWk1VHd4bGxXQ2t6QTd3VSIsInkiOiJjMkpIeFFxVVV0eVdJTEFJaWNtcEJHQzQ3UGdtSlQ0NjV0UG9jRzJxMThrIn0sInB1cnBvc2UiOlsiYXV0aCIsImdlbmVyYWwiXX1dLCJzZXJ2aWNlX2VuZHBvaW50cyI6W3siaWQiOiJzZXJ2aWNlRW5kcG9pbnRJZDEyMyIsInR5cGUiOiJzb21lVHlwZSIsImVuZHBvaW50IjoiaHR0cHM6Ly93d3cudXJsLmNvbSJ9XX19XX0`
const interopEncodedSuffixData = `eyJkZWx0YV9oYXNoIjoiRWlCWE00b3RMdVAyZkc0WkE3NS1hbnJrV1ZYMDYzN3hadE1KU29Lb3AtdHJkdyIsInJlY292ZXJ5X2NvbW1pdG1lbnQiOiJFaUM4RzRJZGJEN0Q0Q281N0dqTE5LaG1ERWFicnprTzF3c0tFOU1RZVV2T2d3In0`
const interopExpectedSuffix = "EiBFsUlzmZ3zJtSFeQKwJNtngjmB51ehMWWDuptf9b4Bag"
