/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"

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

	suffixData, err := parseSuffixData(schema.SuffixData, code)
	if err != nil {
		return nil, err
	}

	delta, err := parseCreateDelta(schema.Delta, code)
	if err != nil {
		return nil, err
	}

	uniqueSuffix, err := docutil.CalculateUniqueSuffix(schema.SuffixData, code)
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		OperationBuffer:              request,
		Type:                         batch.OperationTypeCreate,
		UniqueSuffix:                 uniqueSuffix,
		Delta:                        delta,
		EncodedDelta:                 schema.Delta,
		UpdateCommitment:             delta.UpdateCommitment,
		RecoveryCommitment:           suffixData.RecoveryCommitment,
		HashAlgorithmInMultiHashCode: code,
		SuffixData:                   suffixData,
	}, nil
}

func parseCreateRequest(payload []byte) (*model.CreateRequest, error) {
	schema := &model.CreateRequest{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, err
	}

	return schema, nil
}

func parseCreateDelta(encoded string, code uint) (*model.DeltaModel, error) {
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

func parseSuffixData(encoded string, code uint) (*model.SuffixDataModel, error) {
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

	if !docutil.IsComputedUsingHashAlgorithm(delta.UpdateCommitment, uint64(code)) {
		return errors.New("next update commitment hash is not computed with the latest supported hash algorithm")
	}

	return nil
}

func validateSuffixData(suffixData *model.SuffixDataModel, code uint) error {
	if suffixData.RecoveryKey == nil {
		return errors.New("missing recovery key")
	}

	if !docutil.IsComputedUsingHashAlgorithm(suffixData.RecoveryCommitment, uint64(code)) {
		return errors.New("next recovery commitment hash is not computed with the latest supported hash algorithm")
	}

	if !docutil.IsComputedUsingHashAlgorithm(suffixData.DeltaHash, uint64(code)) {
		return errors.New("patch data hash is not computed with the latest supported hash algorithm")
	}

	return nil
}
