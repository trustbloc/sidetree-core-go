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

	operationData, err := parseCreateOperationData(schema.OperationData, code)
	if err != nil {
		return nil, err
	}

	uniqueSuffix, err := docutil.CalculateUniqueSuffix(schema.SuffixData, code)
	if err != nil {
		return nil, err
	}

	// TODO: Handle recovery key

	return &batch.Operation{
		OperationBuffer:              request,
		Type:                         batch.OperationTypeCreate,
		UniqueSuffix:                 uniqueSuffix,
		Document:                     operationData.Document,
		NextUpdateOTPHash:            operationData.NextUpdateOTPHash,
		NextRecoveryOTPHash:          suffixData.NextRecoveryOTPHash,
		HashAlgorithmInMultiHashCode: code,
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

func parseCreateOperationData(encoded string, code uint) (*model.OperationDataSchema, error) {
	bytes, err := docutil.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	schema := &model.OperationDataSchema{}
	err = json.Unmarshal(bytes, schema)
	if err != nil {
		return nil, err
	}

	if err := validateOperationData(schema, code); err != nil {
		return nil, err
	}

	return schema, nil
}

func parseSuffixData(encoded string, code uint) (*model.SuffixDataSchema, error) {
	bytes, err := docutil.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	schema := &model.SuffixDataSchema{}
	err = json.Unmarshal(bytes, schema)
	if err != nil {
		return nil, err
	}

	if err := validateSuffixData(schema, code); err != nil {
		return nil, err
	}

	return schema, nil
}

func validateOperationData(opData *model.OperationDataSchema, code uint) error {
	if opData.Document == "" {
		return errors.New("missing opaque document")
	}

	if !docutil.IsComputedUsingHashAlgorithm(opData.NextUpdateOTPHash, uint64(code)) {
		return errors.New("next update OTP hash is not computed with the latest supported hash algorithm")
	}

	return nil
}

func validateSuffixData(suffixData *model.SuffixDataSchema, code uint) error {
	if suffixData.RecoveryKey.PublicKeyHex == "" {
		return errors.New("missing recovery key")
	}

	if !docutil.IsComputedUsingHashAlgorithm(suffixData.NextRecoveryOTPHash, uint64(code)) {
		return errors.New("next recovery OTP hash is not computed with the latest supported hash algorithm")
	}

	if !docutil.IsComputedUsingHashAlgorithm(suffixData.OperationDataHash, uint64(code)) {
		return errors.New("operation data hash is not computed with the latest supported hash algorithm")
	}

	return nil
}
