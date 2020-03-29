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
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// ParseRevokeOperation will parse revoke operation
func ParseRevokeOperation(request []byte, protocol protocol.Protocol) (*batch.Operation, error) {
	schema, err := parseRevokeRequest(request)
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		Type:                         batch.OperationTypeRevoke,
		OperationBuffer:              request,
		UniqueSuffix:                 schema.DidUniqueSuffix,
		RecoveryRevealValue:          schema.RecoveryRevealValue,
		HashAlgorithmInMultiHashCode: protocol.HashAlgorithmInMultiHashCode,
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
