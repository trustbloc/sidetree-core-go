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

// ParseRecoverOperation will parse recover operation
func ParseRecoverOperation(request []byte, protocol protocol.Protocol) (*batch.Operation, error) {
	schema, err := parseRecoverRequest(request)
	if err != nil {
		return nil, err
	}

	code := protocol.HashAlgorithmInMultiHashCode

	operationData, err := parseUnsignedOperationData(schema.OperationData, code)
	if err != nil {
		return nil, err
	}

	signedOperationData, err := parseSignedOperationData(schema.SignedOperationData.Payload, code)
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		OperationBuffer:              request,
		Type:                         batch.OperationTypeRecover,
		UniqueSuffix:                 schema.DidUniqueSuffix,
		Document:                     operationData.Document,
		NextUpdateOTPHash:            operationData.NextUpdateOTPHash,
		NextRecoveryOTPHash:          signedOperationData.NextRecoveryOTPHash,
		HashAlgorithmInMultiHashCode: code,
	}, nil
}

func parseRecoverRequest(payload []byte) (*model.RecoverRequest, error) {
	schema := &model.RecoverRequest{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, err
	}

	return schema, nil
}

func parseUnsignedOperationData(encoded string, code uint) (*model.OperationDataSchema, error) {
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

func parseSignedOperationData(encoded string, code uint) (*model.SignedOperationDataSchema, error) {
	bytes, err := docutil.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	schema := &model.SignedOperationDataSchema{}
	err = json.Unmarshal(bytes, schema)
	if err != nil {
		return nil, err
	}

	if err := validateSignedOperationData(schema, code); err != nil {
		return nil, err
	}

	return schema, nil
}

func validateSignedOperationData(signedOpData *model.SignedOperationDataSchema, code uint) error {
	if signedOpData.RecoveryKey.PublicKeyHex == "" {
		return errors.New("missing recovery key")
	}

	if !docutil.IsComputedUsingHashAlgorithm(signedOpData.NextRecoveryOTPHash, uint64(code)) {
		return errors.New("next recovery OTP hash is not computed with the latest supported hash algorithm")
	}

	if !docutil.IsComputedUsingHashAlgorithm(signedOpData.OperationDataHash, uint64(code)) {
		return errors.New("operation data hash is not computed with the latest supported hash algorithm")
	}

	return nil
}
