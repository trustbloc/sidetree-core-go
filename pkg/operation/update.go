/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"errors"
	"fmt"

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

	_, err = ParseSignedDataForUpdate(schema.SignedData, protocol.HashAlgorithmInMultiHashCode)
	if err != nil {
		return nil, err
	}

	delta, err := ParseDelta(schema.Delta, protocol)
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		Type:            batch.OperationTypeUpdate,
		OperationBuffer: request,
		UniqueSuffix:    schema.DidSuffix,
		DeltaModel:      delta,
		Delta:           schema.Delta,
		SignedData:      schema.SignedData,
	}, nil
}

func parseUpdateRequest(payload []byte) (*model.UpdateRequest, error) {
	schema := &model.UpdateRequest{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal update request: %s", err.Error())
	}

	if err := validateUpdateRequest(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

// ParseSignedDataForUpdate will parse and validate signed data for update
func ParseSignedDataForUpdate(compactJWS string, code uint) (*model.UpdateSignedDataModel, error) {
	jws, err := parseSignedData(compactJWS)
	if err != nil {
		return nil, fmt.Errorf("update: %s", err.Error())
	}

	schema := &model.UpdateSignedDataModel{}
	err = json.Unmarshal(jws.Payload, schema)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed data model for update: %s", err.Error())
	}

	if err := validateSignedDataForUpdate(schema, code); err != nil {
		return nil, err
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

func validateSignedDataForUpdate(signedData *model.UpdateSignedDataModel, code uint) error {
	if err := validateKey(signedData.UpdateKey); err != nil {
		return fmt.Errorf("signed data for update: %s", err.Error())
	}

	if !docutil.IsComputedUsingHashAlgorithm(signedData.DeltaHash, uint64(code)) {
		return errors.New("delta hash is not computed with the latest supported hash algorithm")
	}

	return nil
}
