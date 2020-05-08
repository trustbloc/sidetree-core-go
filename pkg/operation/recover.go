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

	delta, err := parseDelta(schema.Delta, code)
	if err != nil {
		return nil, err
	}

	_, err = parseSignedDataForRecovery(schema.SignedData.Payload, code)
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		OperationBuffer:     request,
		Type:                batch.OperationTypeRecover,
		UniqueSuffix:        schema.DidSuffix,
		Delta:               delta,
		EncodedDelta:        schema.Delta,
		RecoveryRevealValue: schema.RecoveryRevealValue,
		SignedData:          schema.SignedData,
	}, nil
}

func parseRecoverRequest(payload []byte) (*model.RecoverRequest, error) {
	schema := &model.RecoverRequest{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, err
	}

	if err := validateRecoverRequest(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

func parseDelta(encoded string, code uint) (*model.DeltaModel, error) {
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

func parseSignedDataForRecovery(encoded string, code uint) (*model.RecoverSignedDataModel, error) {
	bytes, err := docutil.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	schema := &model.RecoverSignedDataModel{}
	err = json.Unmarshal(bytes, schema)
	if err != nil {
		return nil, err
	}

	if err := validateSignedDataForRecovery(schema, code); err != nil {
		return nil, err
	}

	return schema, nil
}

func validateSignedDataForRecovery(signedData *model.RecoverSignedDataModel, code uint) error {
	if err := validateRecoveryKey(signedData.RecoveryKey); err != nil {
		return err
	}

	if !docutil.IsComputedUsingHashAlgorithm(signedData.RecoveryCommitment, uint64(code)) {
		return errors.New("next recovery commitment hash is not computed with the latest supported hash algorithm")
	}

	if !docutil.IsComputedUsingHashAlgorithm(signedData.DeltaHash, uint64(code)) {
		return errors.New("patch data hash is not computed with the latest supported hash algorithm")
	}

	return nil
}

func validateSignedData(signedData *model.JWS) error {
	if signedData == nil {
		return errors.New("missing signed data")
	}

	if signedData.Payload == "" {
		return errors.New("signed data is missing payload")
	}

	if signedData.Signature == "" {
		return errors.New("signed data is missing signature")
	}

	if signedData.Protected == nil {
		return errors.New("signed data is missing protected headers")
	}

	if signedData.Protected.Alg == "" {
		return errors.New("signed data is missing algorithm in protected headers")
	}

	return nil
}

func validateRecoverRequest(recover *model.RecoverRequest) error {
	if err := validateSignedData(recover.SignedData); err != nil {
		return err
	}

	if recover.Delta == "" {
		return errors.New("missing delta")
	}

	if recover.DidSuffix == "" {
		return errors.New("missing did suffix")
	}

	return nil
}
