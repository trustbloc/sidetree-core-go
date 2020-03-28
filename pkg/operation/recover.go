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
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
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

	signedData, err := parseSignedData(schema.SignedData.Payload, code)
	if err != nil {
		return nil, err
	}

	document := patchData.Patches[0].GetStringValue(patch.DocumentKey)

	// TODO: Handle recovery key

	return &batch.Operation{
		OperationBuffer:              request,
		Type:                         batch.OperationTypeRecover,
		UniqueSuffix:                 schema.DidUniqueSuffix,
		Document:                     document,
		RecoveryOTP:                  schema.RecoveryOTP,
		NextUpdateOTPHash:            patchData.NextUpdateOTPHash,
		NextRecoveryOTPHash:          signedData.NextRecoveryOTPHash,
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

func parseSignedData(encoded string, code uint) (*model.SignedDataModel, error) {
	bytes, err := docutil.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	schema := &model.SignedDataModel{}
	err = json.Unmarshal(bytes, schema)
	if err != nil {
		return nil, err
	}

	if err := validateSignedData(schema, code); err != nil {
		return nil, err
	}

	return schema, nil
}

func validateSignedData(signedData *model.SignedDataModel, code uint) error {
	if signedData.RecoveryKey.PublicKeyHex == "" {
		return errors.New("missing recovery key")
	}

	if !docutil.IsComputedUsingHashAlgorithm(signedData.NextRecoveryOTPHash, uint64(code)) {
		return errors.New("next recovery OTP hash is not computed with the latest supported hash algorithm")
	}

	if !docutil.IsComputedUsingHashAlgorithm(signedData.PatchDataHash, uint64(code)) {
		return errors.New("patch data hash is not computed with the latest supported hash algorithm")
	}

	return nil
}
