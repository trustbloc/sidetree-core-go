/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"

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

	delta, err := parseUpdateDelta(schema.Delta, protocol.HashAlgorithmInMultiHashCode)
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		Type:                         batch.OperationTypeUpdate,
		OperationBuffer:              request,
		UniqueSuffix:                 schema.DidSuffix,
		Delta:                        delta,
		EncodedDelta:                 schema.Delta,
		UpdateRevealValue:            schema.UpdateRevealValue,
		UpdateCommitment:             delta.UpdateCommitment,
		HashAlgorithmInMultiHashCode: protocol.HashAlgorithmInMultiHashCode,
		SignedData:                   schema.SignedData,
	}, nil
}

func parseUpdateRequest(payload []byte) (*model.UpdateRequest, error) {
	schema := &model.UpdateRequest{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
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
