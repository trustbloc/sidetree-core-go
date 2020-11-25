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

// ParseUpdateOperation will parse update operation.
func (p *Parser) ParseUpdateOperation(request []byte, batch bool) (*model.Operation, error) {
	schema, err := p.parseUpdateRequest(request)
	if err != nil {
		return nil, err
	}

	signedData, err := p.ParseSignedDataForUpdate(schema.SignedData)
	if err != nil {
		return nil, err
	}

	if !batch {
		err = p.ValidateDelta(schema.Delta)
		if err != nil {
			return nil, err
		}
	}

	revealValue, err := p.getRevealValueMultihash(signedData.UpdateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get reveal value multihash for update: %s", err.Error())
	}

	return &model.Operation{
		Type:            operation.TypeUpdate,
		OperationBuffer: request,
		UniqueSuffix:    schema.DidSuffix,
		Delta:           schema.Delta,
		SignedData:      schema.SignedData,
		RevealValue:     revealValue,
	}, nil
}

func (p *Parser) parseUpdateRequest(payload []byte) (*model.UpdateRequest, error) {
	schema := &model.UpdateRequest{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal update request: %s", err.Error())
	}

	if err := p.validateUpdateRequest(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

// ParseSignedDataForUpdate will parse and validate signed data for update.
func (p *Parser) ParseSignedDataForUpdate(compactJWS string) (*model.UpdateSignedDataModel, error) {
	jws, err := p.parseSignedData(compactJWS)
	if err != nil {
		return nil, fmt.Errorf("update: %s", err.Error())
	}

	schema := &model.UpdateSignedDataModel{}
	err = json.Unmarshal(jws.Payload, schema)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed data model for update: %s", err.Error())
	}

	if err := p.validateSignedDataForUpdate(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

func (p *Parser) validateUpdateRequest(update *model.UpdateRequest) error {
	if update.DidSuffix == "" {
		return errors.New("missing did suffix")
	}

	if update.SignedData == "" {
		return errors.New("missing signed data")
	}

	return nil
}

func (p *Parser) validateSignedDataForUpdate(signedData *model.UpdateSignedDataModel) error {
	if err := p.validateSigningKey(signedData.UpdateKey, p.KeyAlgorithms); err != nil {
		return fmt.Errorf("signed data for update: %s", err.Error())
	}

	code := uint64(p.MultihashAlgorithm)
	if !hashing.IsComputedUsingMultihashAlgorithm(signedData.DeltaHash, code) {
		return fmt.Errorf("delta hash is not computed with the required multihash algorithm: %d", code)
	}

	return nil
}
