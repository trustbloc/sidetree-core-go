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
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
)

// ParseDeactivateOperation will parse deactivate operation.
func (p *Parser) ParseDeactivateOperation(request []byte, batch bool) (*model.Operation, error) {
	schema, err := p.parseDeactivateRequest(request)
	if err != nil {
		return nil, err
	}

	signedData, err := p.ParseSignedDataForDeactivate(schema.SignedData)
	if err != nil {
		return nil, err
	}

	if signedData.DidSuffix != schema.DidSuffix {
		return nil, errors.New("signed did suffix mismatch for deactivate")
	}

	err = hashing.IsValidModelMultihash(signedData.RecoveryKey, schema.RevealValue)
	if err != nil {
		return nil, fmt.Errorf("canonicalized recovery public key hash doesn't match reveal value: %s", err.Error())
	}

	if !batch {
		until := p.getAnchorUntil(signedData.AnchorFrom, signedData.AnchorUntil)

		if err := p.anchorTimeValidator.Validate(signedData.AnchorFrom, until); err != nil {
			return nil, err
		}
	}

	return &model.Operation{
		Type:            operation.TypeDeactivate,
		OperationBuffer: request,
		UniqueSuffix:    schema.DidSuffix,
		SignedData:      schema.SignedData,
		RevealValue:     schema.RevealValue,
	}, nil
}

func (p *Parser) parseDeactivateRequest(payload []byte) (*model.DeactivateRequest, error) {
	schema := &model.DeactivateRequest{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal deactivate request: %s", err.Error())
	}

	if err := p.validateDeactivateRequest(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

func (p *Parser) validateDeactivateRequest(req *model.DeactivateRequest) error {
	if req.DidSuffix == "" {
		return errors.New("missing did suffix")
	}

	if req.SignedData == "" {
		return errors.New("missing signed data")
	}

	return p.validateMultihash(req.RevealValue, "reveal value")
}

// ParseSignedDataForDeactivate will parse and validate signed data for deactivate.
func (p *Parser) ParseSignedDataForDeactivate(compactJWS string) (*model.DeactivateSignedDataModel, error) {
	jws, err := p.parseSignedData(compactJWS)
	if err != nil {
		return nil, err
	}

	signedData := &model.DeactivateSignedDataModel{}
	err = json.Unmarshal(jws.Payload, signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed data model for deactivate: %s", err.Error())
	}

	if err := p.validateSigningKey(signedData.RecoveryKey, p.KeyAlgorithms); err != nil {
		return nil, fmt.Errorf("validate signed data for deactivate: %s", err.Error())
	}

	return signedData, nil
}
