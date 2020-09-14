/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationparser

import (
	"encoding/json"
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// Parser is an operation parser
type Parser struct {
	protocol.Protocol
}

// New returns a new operation parser
func New(p protocol.Protocol) *Parser {
	return &Parser{
		Protocol: p,
	}
}

// Parse parses and validates operation
func (p *Parser) Parse(namespace string, operationBuffer []byte) (*batch.Operation, error) {
	schema := &operationSchema{}
	err := json.Unmarshal(operationBuffer, schema)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal operation buffer into operation schema: %s", err.Error())
	}

	var op *batch.Operation
	var parseErr error
	switch schema.Operation {
	case model.OperationTypeCreate:
		op, parseErr = p.ParseCreateOperation(operationBuffer)
	case model.OperationTypeUpdate:
		op, parseErr = p.ParseUpdateOperation(operationBuffer)
	case model.OperationTypeDeactivate:
		op, parseErr = p.ParseDeactivateOperation(operationBuffer)
	case model.OperationTypeRecover:
		op, parseErr = p.ParseRecoverOperation(operationBuffer)
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
