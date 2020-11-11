/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationparser

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	internal "github.com/trustbloc/sidetree-core-go/pkg/internal/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
)

// ParseRecoverOperation will parse recover operation.
func (p *Parser) ParseRecoverOperation(request []byte, anchor bool) (*model.Operation, error) {
	schema, err := p.parseRecoverRequest(request)
	if err != nil {
		return nil, err
	}

	_, err = p.ParseSignedDataForRecover(schema.SignedData)
	if err != nil {
		return nil, err
	}

	if !anchor {
		err = p.ValidateDelta(schema.Delta)
		if err != nil {
			return nil, err
		}
	}

	return &model.Operation{
		OperationBuffer: request,
		Type:            operation.TypeRecover,
		UniqueSuffix:    schema.DidSuffix,
		Delta:           schema.Delta,
		SignedData:      schema.SignedData,
	}, nil
}

func (p *Parser) parseRecoverRequest(payload []byte) (*model.RecoverRequest, error) {
	schema := &model.RecoverRequest{}
	err := json.Unmarshal(payload, schema)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal recover request: %s", err.Error())
	}

	if err := p.validateRecoverRequest(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

// ParseSignedDataForRecover will parse and validate signed data for recover.
func (p *Parser) ParseSignedDataForRecover(compactJWS string) (*model.RecoverSignedDataModel, error) {
	jws, err := p.parseSignedData(compactJWS)
	if err != nil {
		return nil, fmt.Errorf("recover: %s", err.Error())
	}

	schema := &model.RecoverSignedDataModel{}
	err = json.Unmarshal(jws.Payload, schema)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed data model for recover: %s", err.Error())
	}

	if err := p.validateSignedDataForRecovery(schema); err != nil {
		return nil, err
	}

	return schema, nil
}

func (p *Parser) validateSignedDataForRecovery(signedData *model.RecoverSignedDataModel) error {
	if err := p.validateSigningKey(signedData.RecoveryKey, p.KeyAlgorithms); err != nil {
		return fmt.Errorf("signed data for recovery: %s", err.Error())
	}

	code := uint64(p.MultihashAlgorithm)
	if !hashing.IsComputedUsingMultihashAlgorithm(signedData.RecoveryCommitment, code) {
		return fmt.Errorf("next recovery commitment hash is not computed with the required hash algorithm: %d", code)
	}

	if !hashing.IsComputedUsingMultihashAlgorithm(signedData.DeltaHash, code) {
		return fmt.Errorf("patch data hash is not computed with the required hash algorithm: %d", code)
	}

	return nil
}

func (p *Parser) parseSignedData(compactJWS string) (*internal.JSONWebSignature, error) {
	if compactJWS == "" {
		return nil, errors.New("missing signed data")
	}

	jws, err := internal.ParseJWS(compactJWS)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed data: %s", err.Error())
	}

	err = p.validateProtectedHeaders(jws.ProtectedHeaders, p.SignatureAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed data: %s", err.Error())
	}

	return jws, nil
}

func (p *Parser) validateProtectedHeaders(headers jws.Headers, allowedAlgorithms []string) error {
	if headers == nil {
		return errors.New("missing protected headers")
	}

	// kid MUST be present in the protected header.
	// alg MUST be present in the protected header, its value MUST NOT be none.
	// no additional members may be present in the protected header.

	// TODO: There is discrepancy between spec "kid MUST be present in the protected header" (issue-365)
	// and reference implementation ('kid' is not present; only one 'alg' header expected)
	// so disable this check for now
	// _, ok := headers.KeyID()
	// if !ok {
	// return errors.New("kid must be present in the protected header")
	// }

	alg, ok := headers.Algorithm()
	if !ok {
		return errors.New("algorithm must be present in the protected header")
	}

	if alg == "" {
		return errors.New("algorithm cannot be empty in the protected header")
	}

	allowedHeaders := map[string]bool{
		jws.HeaderAlgorithm: true,
		jws.HeaderKeyID:     true,
	}

	for k := range headers {
		if _, ok := allowedHeaders[k]; !ok {
			return fmt.Errorf("invalid protected header: %s", k)
		}
	}

	if !contains(allowedAlgorithms, alg) {
		return errors.Errorf("algorithm '%s' is not in the allowed list %v", alg, allowedAlgorithms)
	}

	return nil
}

func (p *Parser) validateRecoverRequest(recover *model.RecoverRequest) error {
	if recover.DidSuffix == "" {
		return errors.New("missing did suffix")
	}

	if recover.SignedData == "" {
		return errors.New("missing signed data")
	}

	return nil
}

func (p *Parser) validateSigningKey(key *jws.JWK, allowedAlgorithms []string) error {
	if key == nil {
		return errors.New("missing signing key")
	}

	err := key.Validate()
	if err != nil {
		return fmt.Errorf("signing key validation failed: %s", err.Error())
	}

	if !contains(allowedAlgorithms, key.Crv) {
		return errors.Errorf("key algorithm '%s' is not in the allowed list %v", key.Crv, allowedAlgorithms)
	}

	return nil
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}

	return false
}
