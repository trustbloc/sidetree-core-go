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

// ParseRevokeOperation will parse revoke operation
func ParseRevokeOperation(request []byte, p protocol.Protocol) (*batch.Operation, error) {
	schema, err := parseRevokeRequest(request)
	if err != nil {
		return nil, err
	}

	_, err = parseSignedDataForRevoke(schema)
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		Type:                         batch.OperationTypeRevoke,
		OperationBuffer:              request,
		UniqueSuffix:                 schema.DidUniqueSuffix,
		RecoveryRevealValue:          schema.RecoveryRevealValue,
		HashAlgorithmInMultiHashCode: p.HashAlgorithmInMultiHashCode,
		SignedData:                   schema.SignedData,
	}, nil
}

func parseRevokeRequest(payload []byte) (*model.RevokeRequest, error) {
	schema := &model.RevokeRequest{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, err
	}

	if err := validateRevokeRequest(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

func validateRevokeRequest(req *model.RevokeRequest) error {
	if req.DidUniqueSuffix == "" {
		return errors.New("missing unique suffix")
	}

	return nil
}

func parseSignedDataForRevoke(req *model.RevokeRequest) (*model.RevokeSignedDataModel, error) {
	bytes, err := docutil.DecodeString(req.SignedData.Payload)
	if err != nil {
		return nil, err
	}

	signedData := &model.RevokeSignedDataModel{}
	err = json.Unmarshal(bytes, signedData)
	if err != nil {
		return nil, err
	}

	if signedData.RecoveryRevealValue != req.RecoveryRevealValue {
		return nil, errors.New("signed recovery reveal mismatch for revoke")
	}

	if signedData.DidUniqueSuffix != req.DidUniqueSuffix {
		return nil, errors.New("signed did suffix mismatch for revoke")
	}

	return signedData, nil
}
