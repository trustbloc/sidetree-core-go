/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationparser

import (
	"encoding/json"
	"fmt"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
)

var logger = log.New("sidetree-core-parser")

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
func (p *Parser) Parse(namespace string, operationBuffer []byte) (*operation.Operation, error) {
	// parse and validate operation buffer using this versions model and validation rules
	internal, err := p.ParseOperation(namespace, operationBuffer, false)
	if err != nil {
		return nil, err
	}

	return &operation.Operation{
		Type:            internal.Type,
		UniqueSuffix:    internal.UniqueSuffix,
		ID:              internal.ID,
		OperationBuffer: operationBuffer,
	}, nil
}

// ParseOperation parses and validates operation. Batch mode flag gives hints for the validation of
// operation object (anticipating future pruning/checkpoint requirements).
func (p *Parser) ParseOperation(namespace string, operationBuffer []byte, batch bool) (*model.Operation, error) {
	schema := &operationSchema{}
	err := json.Unmarshal(operationBuffer, schema)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal operation buffer into operation schema: %s", err.Error())
	}

	var op *model.Operation
	var parseErr error
	switch schema.Operation {
	case operation.TypeCreate:
		op, parseErr = p.ParseCreateOperation(operationBuffer, batch)
	case operation.TypeUpdate:
		op, parseErr = p.ParseUpdateOperation(operationBuffer, batch)
	case operation.TypeDeactivate:
		op, parseErr = p.ParseDeactivateOperation(operationBuffer, batch)
	case operation.TypeRecover:
		op, parseErr = p.ParseRecoverOperation(operationBuffer, batch)
	default:
		return nil, fmt.Errorf("parse operation: operation type [%s] not supported", schema.Operation)
	}

	if parseErr != nil {
		logger.Warnf("parse '%s' operation for batch[%t]: %s", schema.Operation, batch, parseErr.Error())

		return nil, parseErr
	}

	op.Namespace = namespace
	op.ID = namespace + docutil.NamespaceDelimiter + op.UniqueSuffix

	return op, nil
}

// operationSchema is used to get operation type.
type operationSchema struct {

	// operation
	Operation operation.Type `json:"type"`
}
