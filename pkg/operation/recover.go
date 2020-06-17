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
	internal "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

// ParseRecoverOperation will parse recover operation
func ParseRecoverOperation(request []byte, protocol protocol.Protocol) (*batch.Operation, error) {
	schema, err := parseRecoverRequest(request)
	if err != nil {
		return nil, err
	}

	code := protocol.HashAlgorithmInMultiHashCode

	delta, err := ParseDelta(schema.Delta, code)
	if err != nil {
		return nil, err
	}

	_, err = parseSignedDataForRecovery(schema.SignedData, code)
	if err != nil {
		return nil, err
	}

	return &batch.Operation{
		OperationBuffer: request,
		Type:            batch.OperationTypeRecover,
		UniqueSuffix:    schema.DidSuffix,
		Delta:           delta,
		EncodedDelta:    schema.Delta,
		SignedData:      schema.SignedData,
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

func parseSignedDataForRecovery(compactJWS string, code uint) (*model.RecoverSignedDataModel, error) {
	jws, err := parseSignedData(compactJWS)
	if err != nil {
		return nil, err
	}

	bytes, err := docutil.DecodeString(string(jws.Payload))
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
	if err := validateKey(signedData.RecoveryKey); err != nil {
		return fmt.Errorf("signed data for recovery: %s", err.Error())
	}

	if !docutil.IsComputedUsingHashAlgorithm(signedData.RecoveryCommitment, uint64(code)) {
		return errors.New("next recovery commitment hash is not computed with the latest supported hash algorithm")
	}

	if !docutil.IsComputedUsingHashAlgorithm(signedData.DeltaHash, uint64(code)) {
		return errors.New("patch data hash is not computed with the latest supported hash algorithm")
	}

	return nil
}

func parseSignedData(compactJWS string) (*internal.JSONWebSignature, error) {
	return internal.ParseJWS(compactJWS)
}

func validateRecoverRequest(recover *model.RecoverRequest) error {
	if recover.DidSuffix == "" {
		return errors.New("missing did suffix")
	}

	if recover.Delta == "" {
		return errors.New("missing delta")
	}

	if recover.SignedData == "" {
		return errors.New("missing signed data")
	}

	return nil
}

func validateKey(key *jws.JWK) error {
	if key == nil {
		return errors.New("missing key")
	}

	return key.Validate()
}
