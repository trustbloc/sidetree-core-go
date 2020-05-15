/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// ParseUpdateOperation will parse update operation
func ParseUpdateOperation(request []byte, protocol protocol.Protocol) (*batch.Operation, error) {
	schema, err := parseUpdateRequest(request)
	if err != nil {
		return nil, err
	}

	_, err = parseSignedDataForUpdate(schema.SignedData, protocol.HashAlgorithmInMultiHashCode)
	if err != nil {
		return nil, err
	}

	delta, err := parseUpdateDelta(schema.Delta, protocol.HashAlgorithmInMultiHashCode)
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		Type:              batch.OperationTypeUpdate,
		OperationBuffer:   request,
		UniqueSuffix:      schema.DidSuffix,
		Delta:             delta,
		EncodedDelta:      schema.Delta,
		UpdateRevealValue: schema.UpdateRevealValue,
		SignedData:        schema.SignedData,
	}, nil
}

func parseUpdateRequest(payload []byte) (*model.UpdateRequest, error) {
	schema := &model.UpdateRequest{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, err
	}

	if err := validateUpdateRequest(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

func parseUpdateDelta(encoded string, code uint) (*model.DeltaModel, error) {
	bytes, err := docutil.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	schema := &model.DeltaModel{}
	err = json.Unmarshal(bytes, schema)
	if err != nil {
		return nil, err
	}

	if err := validateDelta(schema, code); err != nil {
		return nil, err
	}

	return schema, nil
}

func parseSignedDataForUpdate(compactJWS string, code uint) (*model.UpdateSignedDataModel, error) {
	jws, err := parseSignedData(compactJWS)
	if err != nil {
		return nil, err
	}

	bytes, err := docutil.DecodeString(string(jws.Payload))
	if err != nil {
		return nil, err
	}

	schema := &model.UpdateSignedDataModel{}
	err = json.Unmarshal(bytes, schema)
	if err != nil {
		return nil, err
	}

	if !docutil.IsComputedUsingHashAlgorithm(schema.DeltaHash, uint64(code)) {
		return nil, errors.New("delta hash is not computed with the latest supported hash algorithm")
	}

	return schema, nil
}

func validateUpdateRequest(update *model.UpdateRequest) error {
	if update.DidSuffix == "" {
		return errors.New("missing did suffix")
	}

	if update.Delta == "" {
		return errors.New("missing delta")
	}

	if update.SignedData == "" {
		return errors.New("missing signed data")
	}

	return nil
}
