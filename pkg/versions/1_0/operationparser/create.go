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
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/model"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/operationparser/patchvalidator"
)

// ParseCreateOperation will parse create operation.
func (p *Parser) ParseCreateOperation(request []byte, batch bool) (*model.Operation, error) {
	schema, err := p.parseCreateRequest(request)
	if err != nil {
		return nil, err
	}

	// create is not valid if suffix data is not valid
	err = p.ValidateSuffixData(schema.SuffixData)
	if err != nil {
		return nil, err
	}

	if !batch {
		err = p.anchorOriginValidator.Validate(schema.SuffixData.AnchorOrigin)
		if err != nil {
			return nil, err
		}

		err = p.ValidateDelta(schema.Delta)
		if err != nil {
			return nil, err
		}

		// verify actual delta hash matches expected delta hash
		err = hashing.IsValidModelMultihash(schema.Delta, schema.SuffixData.DeltaHash)
		if err != nil {
			return nil, fmt.Errorf("delta doesn't match suffix data delta hash: %s", err.Error())
		}

		if schema.Delta.UpdateCommitment == schema.SuffixData.RecoveryCommitment {
			return nil, errors.New("recovery and update commitments cannot be equal, re-using public keys is not allowed")
		}
	}

	uniqueSuffix, err := model.GetUniqueSuffix(schema.SuffixData, p.MultihashAlgorithms)
	if err != nil {
		return nil, err
	}

	return &model.Operation{
		OperationRequest: request,
		Type:             operation.TypeCreate,
		UniqueSuffix:     uniqueSuffix,
		Delta:            schema.Delta,
		SuffixData:       schema.SuffixData,
		AnchorOrigin:     schema.SuffixData.AnchorOrigin,
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

	if err := p.validateMultihash(delta.UpdateCommitment, "update commitment"); err != nil {
		return err
	}

	return p.validateDeltaSize(delta)
}

func (p *Parser) validateMultihash(mh, alias string) error {
	if len(mh) > int(p.MaxOperationHashLength) {
		return fmt.Errorf("%s length[%d] exceeds maximum hash length[%d]", alias, len(mh), p.MaxOperationHashLength)
	}

	if !hashing.IsComputedUsingMultihashAlgorithms(mh, p.MultihashAlgorithms) {
		return fmt.Errorf("%s is not computed with the required hash algorithms: %d", alias, p.MultihashAlgorithms)
	}

	return nil
}

func (p *Parser) validateDeltaSize(delta *model.DeltaModel) error {
	canonicalDelta, err := canonicalizer.MarshalCanonical(delta)
	if err != nil {
		return fmt.Errorf("marshal canonical for delta failed: %s", err.Error())
	}

	if len(canonicalDelta) > int(p.MaxDeltaSize) {
		return fmt.Errorf("delta size[%d] exceeds maximum delta size[%d]", len(canonicalDelta), p.MaxDeltaSize)
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

	if err := p.validateMultihash(suffixData.RecoveryCommitment, "recovery commitment"); err != nil {
		return err
	}

	return p.validateMultihash(suffixData.DeltaHash, "delta hash")
}

func (p *Parser) validateCreateRequest(create *model.CreateRequest) error {
	if create.SuffixData == nil {
		return errors.New("missing suffix data")
	}

	return nil
}
