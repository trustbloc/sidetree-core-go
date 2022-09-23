/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationparser

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/log"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/model"
)

var logger = log.New("sidetree-core-parser")

// Parser is an operation parser.
type Parser struct {
	protocol.Protocol
	anchorOriginValidator ObjectValidator
	anchorTimeValidator   TimeValidator
}

// New returns a new operation parser.
func New(p protocol.Protocol, opts ...Option) *Parser {
	parser := &Parser{
		Protocol: p,
	}

	// default anchor origin validator
	parser.anchorOriginValidator = &objectValidator{}

	// default anchor time validator
	parser.anchorTimeValidator = &timeValidator{}

	// apply options
	for _, opt := range opts {
		opt(parser)
	}

	return parser
}

// ObjectValidator validates object. Currently used for anchor origin validation
// however it can be used for any object validation.
type ObjectValidator interface {
	Validate(obj interface{}) error
}

// Option is a parser instance option.
type Option func(opts *Parser)

// WithAnchorOriginValidator sets optional anchor origin validator.
func WithAnchorOriginValidator(v ObjectValidator) Option {
	return func(opts *Parser) {
		if v != nil {
			opts.anchorOriginValidator = v
		}
	}
}

// ErrOperationExpired is thrown if anchor until time is less then reference time(e.g. server time or anchoring time).
var ErrOperationExpired = errors.New("operation expired")

// ErrOperationEarly is thrown if anchor from time is greater then reference time(e.g. server time or anchoring time).
var ErrOperationEarly = errors.New("operation early")

// TimeValidator validates earliest and expiry time for an operation against server time.
type TimeValidator interface {
	Validate(from, until int64) error
}

// WithAnchorTimeValidator sets optional anchor time validator.
func WithAnchorTimeValidator(v TimeValidator) Option {
	return func(opts *Parser) {
		if v != nil {
			opts.anchorTimeValidator = v
		}
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
		Type:             internal.Type,
		UniqueSuffix:     internal.UniqueSuffix,
		ID:               internal.ID,
		OperationRequest: operationBuffer,
	}, nil
}

// ParseOperation parses and validates operation. Batch mode flag gives hints for the validation of
// operation object (anticipating future pruning/checkpoint requirements).
func (p *Parser) ParseOperation(namespace string, operationBuffer []byte, batch bool) (*model.Operation, error) {
	// check maximum operation size against protocol before parsing
	if len(operationBuffer) > int(p.MaxOperationSize) {
		return nil, fmt.Errorf("operation size[%d] exceeds maximum operation size[%d]", len(operationBuffer), int(p.MaxOperationSize))
	}

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

type objectValidator struct {
}

func (ov *objectValidator) Validate(_ interface{}) error {
	// default validator allows any anchor origin
	return nil
}

type timeValidator struct {
}

func (tv *timeValidator) Validate(_, _ int64) error {
	// default time validator allows any anchor time
	return nil
}
