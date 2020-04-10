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

	patchData, err := parsePatchData(schema.PatchData, code)
	if err != nil {
		return nil, err
	}

	signedData, err := parseSignedDataForRecovery(schema.SignedData.Payload, code)
	if err != nil {
		return nil, err
	}

	// TODO: Handle recovery key

	return &batch.Operation{
		OperationBuffer:              request,
		Type:                         batch.OperationTypeRecover,
		UniqueSuffix:                 schema.DidUniqueSuffix,
		PatchData:                    patchData,
		EncodedPatchData:             schema.PatchData,
		RecoveryRevealValue:          schema.RecoveryRevealValue,
		NextUpdateCommitmentHash:     patchData.NextUpdateCommitmentHash,
		NextRecoveryCommitmentHash:   signedData.NextRecoveryCommitmentHash,
		HashAlgorithmInMultiHashCode: code,
		SignedData:                   schema.SignedData,
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

func parsePatchData(encoded string, code uint) (*model.PatchDataModel, error) {
	bytes, err := docutil.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	schema := &model.PatchDataModel{}
	err = json.Unmarshal(bytes, schema)
	if err != nil {
		return nil, err
	}

	if err := validatePatchData(schema, code); err != nil {
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
	if signedData.RecoveryKey == nil {
		return errors.New("missing recovery key")
	}

	if !docutil.IsComputedUsingHashAlgorithm(signedData.NextRecoveryCommitmentHash, uint64(code)) {
		return errors.New("next recovery commitment hash is not computed with the latest supported hash algorithm")
	}

	if !docutil.IsComputedUsingHashAlgorithm(signedData.PatchDataHash, uint64(code)) {
		return errors.New("patch data hash is not computed with the latest supported hash algorithm")
	}

	return nil
}
