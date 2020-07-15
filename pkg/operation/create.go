/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// ParseCreateOperation will parse create operation
func ParseCreateOperation(request []byte, protocol protocol.Protocol) (*batch.Operation, error) {
	schema, err := parseCreateRequest(request)
	if err != nil {
		return nil, err
	}

	code := protocol.HashAlgorithmInMultiHashCode

	suffixData, err := ParseSuffixData(schema.SuffixData, code)
	if err != nil {
		return nil, err
	}

	delta, err := ParseDelta(schema.Delta, code)
	if err != nil {
		return nil, err
	}

	// verify actual delta hash matches expected delta hash
	err = docutil.IsValidHash(schema.Delta, suffixData.DeltaHash)
	if err != nil {
		return nil, fmt.Errorf("parse create operation: delta doesn't match suffix data delta hash: %s", err.Error())
	}

	uniqueSuffix, err := docutil.CalculateUniqueSuffix(schema.SuffixData, code)
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		OperationBuffer:   request,
		Type:              batch.OperationTypeCreate,
		UniqueSuffix:      uniqueSuffix,
		Delta:             delta,
		EncodedDelta:      schema.Delta,
		SuffixData:        suffixData,
		EncodedSuffixData: schema.SuffixData,
	}, nil
}

func parseCreateRequest(payload []byte) (*model.CreateRequest, error) {
	schema := &model.CreateRequest{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, err
	}

	if err := validateCreateRequest(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

// ParseDelta parses encoded delta string into delta model
func ParseDelta(encoded string, code uint) (*model.DeltaModel, error) {
	bytes, err := docutil.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	schema := &model.DeltaModel{}
	err = json.Unmarshal(bytes, schema)
	if err != nil {
		return nil, err
	}

	if err := validateDelta(schema, code); err != nil {
		return nil, err
	}

	return schema, nil
}

// ParseSuffixData parses encoded suffix data into suffix data model
func ParseSuffixData(encoded string, code uint) (*model.SuffixDataModel, error) {
	bytes, err := docutil.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	schema := &model.SuffixDataModel{}
	err = json.Unmarshal(bytes, schema)
	if err != nil {
		return nil, err
	}

	if err := validateSuffixData(schema, code); err != nil {
		return nil, err
	}

	return schema, nil
}

func validateDelta(delta *model.DeltaModel, code uint) error {
	if len(delta.Patches) == 0 {
		return errors.New("missing patches")
	}

	for _, p := range delta.Patches {
		if err := p.Validate(); err != nil {
			return err
		}
	}

	if !docutil.IsComputedUsingHashAlgorithm(delta.UpdateCommitment, uint64(code)) {
		return errors.New("next update commitment hash is not computed with the latest supported hash algorithm")
	}

	return nil
}

func validateSuffixData(suffixData *model.SuffixDataModel, code uint) error {
	if !docutil.IsComputedUsingHashAlgorithm(suffixData.RecoveryCommitment, uint64(code)) {
		return errors.New("next recovery commitment hash is not computed with the latest supported hash algorithm")
	}

	if !docutil.IsComputedUsingHashAlgorithm(suffixData.DeltaHash, uint64(code)) {
		return errors.New("patch data hash is not computed with the latest supported hash algorithm")
	}

	return nil
}

func validateCreateRequest(create *model.CreateRequest) error {
	if create.Delta == "" {
		return errors.New("missing delta")
	}

	if create.SuffixData == "" {
		return errors.New("missing suffix data")
	}

	return nil
}
