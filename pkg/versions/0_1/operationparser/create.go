/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationparser

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// ParseCreateOperation will parse create operation
func (p *Parser) ParseCreateOperation(request []byte) (*batch.Operation, error) {
	schema, err := p.ParseCreateRequest(request)
	if err != nil {
		return nil, err
	}

	suffixData, err := p.ParseSuffixData(schema.SuffixData)
	if err != nil {
		return nil, err
	}

	delta, err := p.ParseDelta(schema.Delta)
	if err != nil {
		return nil, err
	}

	// verify actual delta hash matches expected delta hash
	err = docutil.IsValidHash(schema.Delta, suffixData.DeltaHash)
	if err != nil {
		return nil, fmt.Errorf("parse create operation: delta doesn't match suffix data delta hash: %s", err.Error())
	}

	uniqueSuffix, err := docutil.CalculateUniqueSuffix(schema.SuffixData, p.HashAlgorithmInMultiHashCode)
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		OperationBuffer: request,
		Type:            batch.OperationTypeCreate,
		UniqueSuffix:    uniqueSuffix,
		DeltaModel:      delta,
		Delta:           schema.Delta,
		SuffixDataModel: suffixData,
		SuffixData:      schema.SuffixData,
	}, nil
}

// ParseCreateRequest parses a 'create' request
func (p *Parser) ParseCreateRequest(payload []byte) (*model.CreateRequest, error) {
	schema := &model.CreateRequest{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, err
	}

	if err := p.validateCreateRequest(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

// ParseDelta parses encoded delta string into delta model
func (p *Parser) ParseDelta(encoded string) (*model.DeltaModel, error) {
	bytes, err := docutil.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	schema := &model.DeltaModel{}
	err = json.Unmarshal(bytes, schema)
	if err != nil {
		return nil, err
	}

	if err := p.validateDelta(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

// ParseSuffixData parses encoded suffix data into suffix data model
func (p *Parser) ParseSuffixData(encoded string) (*model.SuffixDataModel, error) {
	bytes, err := docutil.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	schema := &model.SuffixDataModel{}
	err = json.Unmarshal(bytes, schema)
	if err != nil {
		return nil, err
	}

	if err := p.validateSuffixData(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

func (p *Parser) validateDelta(delta *model.DeltaModel) error {
	if len(delta.Patches) == 0 {
		return errors.New("missing patches")
	}

	for _, ptch := range delta.Patches {
		if ptch.GetAction() == patch.Replace && !p.EnableReplacePatch {
			return fmt.Errorf("%s patch action is not enabled", ptch.GetAction())
		}

		if err := ptch.Validate(); err != nil {
			return err
		}
	}

	if !docutil.IsComputedUsingHashAlgorithm(delta.UpdateCommitment, uint64(p.HashAlgorithmInMultiHashCode)) {
		return fmt.Errorf("next update commitment hash is not computed with the required supported hash algorithm: %d", p.HashAlgorithmInMultiHashCode)
	}

	return nil
}

func (p *Parser) validateSuffixData(suffixData *model.SuffixDataModel) error {
	if !docutil.IsComputedUsingHashAlgorithm(suffixData.RecoveryCommitment, uint64(p.HashAlgorithmInMultiHashCode)) {
		return fmt.Errorf("next recovery commitment hash is not computed with the required supported hash algorithm: %d", p.HashAlgorithmInMultiHashCode)
	}

	if !docutil.IsComputedUsingHashAlgorithm(suffixData.DeltaHash, uint64(p.HashAlgorithmInMultiHashCode)) {
		return fmt.Errorf("patch data hash is not computed with the required supported hash algorithm: %d", p.HashAlgorithmInMultiHashCode)
	}

	return nil
}

func (p *Parser) validateCreateRequest(create *model.CreateRequest) error {
	if create.Delta == "" {
		return errors.New("missing delta")
	}

	if create.SuffixData == "" {
		return errors.New("missing suffix data")
	}

	return nil
}
