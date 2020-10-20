/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationparser

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/operationparser/patchvalidator"
)

// ParseCreateOperation will parse create operation.
func (p *Parser) ParseCreateOperation(request []byte, anchor bool) (*model.Operation, error) {
	schema, err := p.parseCreateRequest(request)
	if err != nil {
		return nil, err
	}

	// create is not valid if suffix data is not valid
	err = p.ValidateSuffixData(schema.SuffixData)
	if err != nil {
		return nil, err
	}

	if !anchor {
		err = p.ValidateDelta(schema.Delta)
		if err != nil {
			return nil, err
		}

		// verify actual delta hash matches expected delta hash
		err = docutil.IsValidModelMultihash(schema.Delta, schema.SuffixData.DeltaHash)
		if err != nil {
			return nil, fmt.Errorf("parse create operation: delta doesn't match suffix data delta hash: %s", err.Error())
		}
	}

	uniqueSuffix, err := docutil.CalculateModelMultihash(schema.SuffixData, p.HashAlgorithmInMultiHashCode)
	if err != nil {
		return nil, err
	}

	return &model.Operation{
		OperationBuffer: request,
		Type:            batch.OperationTypeCreate,
		UniqueSuffix:    uniqueSuffix,
		Delta:           schema.Delta,
		SuffixData:      schema.SuffixData,
	}, nil
}

// parseCreateRequest parses a 'create' request.
func (p *Parser) parseCreateRequest(payload []byte) (*model.CreateRequest, error) {
	schema := &model.CreateRequest{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, err
	}

	return schema, nil
}

// ValidateDelta validates delta.
func (p *Parser) ValidateDelta(delta *model.DeltaModel) error {
	if delta == nil {
		return errors.New("missing delta")
	}

	if len(delta.Patches) == 0 {
		return errors.New("missing patches")
	}

	for _, ptch := range delta.Patches {
		action, err := ptch.GetAction()
		if err != nil {
			return err
		}

		if !p.isPatchEnabled(action) {
			return fmt.Errorf("%s patch action is not enabled", action)
		}

		if err := patchvalidator.Validate(ptch); err != nil {
			return err
		}
	}

	if !docutil.IsComputedUsingHashAlgorithm(delta.UpdateCommitment, uint64(p.HashAlgorithmInMultiHashCode)) {
		return fmt.Errorf("next update commitment hash is not computed with the required supported hash algorithm: %d", p.HashAlgorithmInMultiHashCode)
	}

	return nil
}

func (p *Parser) isPatchEnabled(action patch.Action) bool {
	for _, allowed := range p.Patches {
		if patch.Action(allowed) == action {
			return true
		}
	}

	return false
}

// ValidateSuffixData validates suffix data.
func (p *Parser) ValidateSuffixData(suffixData *model.SuffixDataModel) error {
	if suffixData == nil {
		return errors.New("missing suffix data")
	}

	if !docutil.IsComputedUsingHashAlgorithm(suffixData.RecoveryCommitment, uint64(p.HashAlgorithmInMultiHashCode)) {
		return fmt.Errorf("next recovery commitment hash is not computed with the required supported hash algorithm: %d", p.HashAlgorithmInMultiHashCode)
	}

	if !docutil.IsComputedUsingHashAlgorithm(suffixData.DeltaHash, uint64(p.HashAlgorithmInMultiHashCode)) {
		return fmt.Errorf("patch data hash is not computed with the required supported hash algorithm: %d", p.HashAlgorithmInMultiHashCode)
	}

	return nil
}

func (p *Parser) validateCreateRequest(create *model.CreateRequest) error {
	if create.SuffixData == nil {
		return errors.New("missing suffix data")
	}

	return nil
}
