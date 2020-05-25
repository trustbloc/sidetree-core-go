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

// ParseDeactivateOperation will parse deactivate operation
func ParseDeactivateOperation(request []byte, p protocol.Protocol) (*batch.Operation, error) {
	schema, err := parseDeactivateRequest(request)
	if err != nil {
		return nil, err
	}

	_, err = parseSignedDataForDeactivate(schema)
	if err != nil {
		return nil, err
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
		return nil, err
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

func parseSignedDataForDeactivate(req *model.DeactivateRequest) (*model.DeactivateSignedDataModel, error) {
	jws, err := parseSignedData(req.SignedData)
	if err != nil {
		return nil, err
	}

	bytes, err := docutil.DecodeString(string(jws.Payload))
	if err != nil {
		return nil, err
	}

	signedData := &model.DeactivateSignedDataModel{}
	err = json.Unmarshal(bytes, signedData)
	if err != nil {
		return nil, err
	}

	if signedData.RecoveryRevealValue != req.RecoveryRevealValue {
		return nil, errors.New("signed recovery reveal mismatch for deactivate")
	}

	if signedData.DidSuffix != req.DidSuffix {
		return nil, errors.New("signed did suffix mismatch for deactivate")
	}

	return signedData, nil
}
