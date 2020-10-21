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
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
)

// Parser is an operation parser.
type Parser struct {
	protocol.Protocol
}

// New returns a new operation parser.
func New(p protocol.Protocol) *Parser {
	return &Parser{
		Protocol: p,
	}
}

// Parse parses and validates operation.
func (p *Parser) Parse(namespace string, operationBuffer []byte) (*batch.Operation, error) {
	// parse and validate operation buffer using this versions model and validation rules
	internal, err := p.ParseOperation(namespace, operationBuffer)
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		Type:            internal.Type,
		UniqueSuffix:    internal.UniqueSuffix,
		ID:              internal.ID,
		OperationBuffer: operationBuffer,
	}, nil
}

// ParseOperation parses and validates operation.
func (p *Parser) ParseOperation(namespace string, operationBuffer []byte) (*model.Operation, error) {
	schema := &operationSchema{}
	err := json.Unmarshal(operationBuffer, schema)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal operation buffer into operation schema: %s", err.Error())
	}

	var op *model.Operation
	var parseErr error
	switch schema.Operation {
	case batch.OperationTypeCreate:
		op, parseErr = p.ParseCreateOperation(operationBuffer, false)
	case batch.OperationTypeUpdate:
		op, parseErr = p.ParseUpdateOperation(operationBuffer, false)
	case batch.OperationTypeDeactivate:
		op, parseErr = p.ParseDeactivateOperation(operationBuffer, false)
	case batch.OperationTypeRecover:
		op, parseErr = p.ParseRecoverOperation(operationBuffer, false)
	default:
		return nil, fmt.Errorf("parse operation: operation type [%s] not supported", schema.Operation)
	}

	if parseErr != nil {
		return nil, parseErr
	}

	op.Namespace = namespace
	op.ID = namespace + docutil.NamespaceDelimiter + op.UniqueSuffix

	return op, nil
}

// operationSchema is used to get operation type.
type operationSchema struct {

	// operation
	Operation batch.OperationType `json:"type"`
}
