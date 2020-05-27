/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// ParseOperation parses and validates operation
func ParseOperation(namespace string, operationBuffer []byte, protocol protocol.Protocol) (*batch.Operation, error) {
	schema := &operationSchema{}
	err := json.Unmarshal(operationBuffer, schema)
	if err != nil {
		return nil, err
	}

	var op *batch.Operation
	var parseErr error
	switch schema.Operation {
	case model.OperationTypeCreate:
		op, parseErr = ParseCreateOperation(operationBuffer, protocol)
	case model.OperationTypeUpdate:
		op, parseErr = ParseUpdateOperation(operationBuffer, protocol)
	case model.OperationTypeDeactivate:
		op, parseErr = ParseDeactivateOperation(operationBuffer, protocol)
	case model.OperationTypeRecover:
		op, parseErr = ParseRecoverOperation(operationBuffer, protocol)
	default:
		return nil, fmt.Errorf("operation type [%s] not implemented", schema.Operation)
	}

	if parseErr != nil {
		return nil, parseErr
	}

	op.Namespace = namespace
	op.ID = namespace + docutil.NamespaceDelimiter + op.UniqueSuffix

	return op, nil
}

// operationSchema is used to get operation type
type operationSchema struct {

	// operation
	Operation model.OperationType `json:"type"`
}
