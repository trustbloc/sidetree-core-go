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
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// ParseDeactivateOperation will parse deactivate operation
func ParseDeactivateOperation(request []byte, p protocol.Protocol) (*batch.Operation, error) {
	schema, err := parseDeactivateRequest(request)
	if err != nil {
		return nil, err
	}

	signedData, err := ParseSignedDataForDeactivate(schema.SignedData)
	if err != nil {
		return nil, err
	}

	if signedData.DidSuffix != schema.DidSuffix {
		return nil, errors.New("signed did suffix mismatch for deactivate")
	}

	return &batch.Operation{
		Type:            batch.OperationTypeDeactivate,
		OperationBuffer: request,
		UniqueSuffix:    schema.DidSuffix,
		SignedData:      schema.SignedData,
	}, nil
}

func parseDeactivateRequest(payload []byte) (*model.DeactivateRequest, error) {
	schema := &model.DeactivateRequest{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal deactivate request: %s", err.Error())
	}

	if err := validateDeactivateRequest(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

func validateDeactivateRequest(req *model.DeactivateRequest) error {
	if req.DidSuffix == "" {
		return errors.New("missing unique suffix")
	}

	if req.SignedData == "" {
		return errors.New("missing signed data")
	}

	return nil
}

// ParseSignedDataForDeactivate will parse and validate signed data for deactivate
func ParseSignedDataForDeactivate(compactJWS string) (*model.DeactivateSignedDataModel, error) {
	jws, err := parseSignedData(compactJWS)
	if err != nil {
		return nil, fmt.Errorf("deactivate: %s", err.Error())
	}

	signedData := &model.DeactivateSignedDataModel{}
	err = json.Unmarshal(jws.Payload, signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed data model for deactivate: %s", err.Error())
	}

	return signedData, nil
}
