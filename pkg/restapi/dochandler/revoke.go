/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"encoding/json"
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

func (h *UpdateHandler) parseRevokeOperation(request []byte) (*batch.Operation, error) {
	schema, err := parseRevokeRequest(request)
	if err != nil {
		return nil, err
	}

	id := h.processor.Namespace() + docutil.NamespaceDelimiter + schema.DidUniqueSuffix

	return &batch.Operation{
		Type:                         batch.OperationTypeRevoke,
		OperationBuffer:              request,
		ID:                           id,
		UniqueSuffix:                 schema.DidUniqueSuffix,
		RecoveryOTP:                  schema.RecoveryOTP,
		HashAlgorithmInMultiHashCode: h.processor.Protocol().Current().HashAlgorithmInMultiHashCode,
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
