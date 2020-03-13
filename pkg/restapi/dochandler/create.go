/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dochandler

import (
	"encoding/json"

	"github.com/pkg/errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

func (h *UpdateHandler) parseCreateOperation(request []byte) (*batch.Operation, error) {
	schema, err := h.parseCreateRequest(request)
	if err != nil {
		return nil, err
	}

	suffixData, err := h.parseSuffixData(schema.SuffixData)
	if err != nil {
		return nil, err
	}

	operationData, err := h.parseCreateOperationData(schema.OperationData)
	if err != nil {
		return nil, err
	}

	code := h.processor.Protocol().Current().HashAlgorithmInMultiHashCode

	uniqueSuffix, err := docutil.CalculateUniqueSuffix(schema.SuffixData, code)
	if err != nil {
		return nil, err
	}

	id := h.processor.Namespace() + docutil.NamespaceDelimiter + uniqueSuffix

	return &batch.Operation{
		OperationBuffer:              request,
		Type:                         batch.OperationTypeCreate,
		ID:                           id,
		UniqueSuffix:                 uniqueSuffix,
		Document:                     operationData.Document,
		NextUpdateOTPHash:            operationData.NextUpdateOTPHash,
		NextRecoveryOTPHash:          suffixData.NextRecoveryOTPHash,
		HashAlgorithmInMultiHashCode: h.processor.Protocol().Current().HashAlgorithmInMultiHashCode,
	}, nil
}

func (h *UpdateHandler) parseCreateRequest(payload []byte) (*model.CreateRequest, error) {
	schema := &model.CreateRequest{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, err
	}

	return schema, nil
}

func (h *UpdateHandler) parseCreateOperationData(encoded string) (*model.CreateOperationData, error) {
	bytes, err := docutil.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	schema := &model.CreateOperationData{}
	err = json.Unmarshal(bytes, schema)
	if err != nil {
		return nil, err
	}

	if err := h.validateCreateOperationData(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

func (h *UpdateHandler) parseSuffixData(encoded string) (*model.SuffixDataSchema, error) {
	bytes, err := docutil.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	schema := &model.SuffixDataSchema{}
	err = json.Unmarshal(bytes, schema)
	if err != nil {
		return nil, err
	}

	if err := h.validateSuffixData(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

func (h *UpdateHandler) validateCreateOperationData(opData *model.CreateOperationData) error {
	if opData.Document == "" {
		return errors.New("missing opaque document")
	}

	code := h.processor.Protocol().Current().HashAlgorithmInMultiHashCode

	if !docutil.IsComputedUsingHashAlgorithm(opData.NextUpdateOTPHash, uint64(code)) {
		return errors.New("next update OTP hash is not computed with the latest supported hash algorithm")
	}

	return nil
}

func (h *UpdateHandler) validateSuffixData(suffixData *model.SuffixDataSchema) error {
	if suffixData.RecoveryKey.PublicKeyHex == "" {
		return errors.New("missing recovery key")
	}

	code := h.processor.Protocol().Current().HashAlgorithmInMultiHashCode

	if !docutil.IsComputedUsingHashAlgorithm(suffixData.NextRecoveryOTPHash, uint64(code)) {
		return errors.New("next recovery OTP hash is not computed with the latest supported hash algorithm")
	}

	if !docutil.IsComputedUsingHashAlgorithm(suffixData.OperationDataHash, uint64(code)) {
		return errors.New("operation data hash is not computed with the latest supported hash algorithm")
	}

	return nil
}
