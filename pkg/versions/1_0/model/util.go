/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import (
	"errors"
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
)

// GetAnchoredOperation is utility method for converting operation model into anchored operation.
func GetAnchoredOperation(op *Operation) (*operation.AnchoredOperation, error) {
	var request interface{}
	switch op.Type {
	case operation.TypeCreate:
		request = CreateRequest{
			Operation:  op.Type,
			SuffixData: op.SuffixData,
			Delta:      op.Delta,
		}

	case operation.TypeUpdate:
		request = UpdateRequest{
			Operation:   op.Type,
			DidSuffix:   op.UniqueSuffix,
			Delta:       op.Delta,
			SignedData:  op.SignedData,
			RevealValue: op.RevealValue,
		}

	case operation.TypeDeactivate:
		request = DeactivateRequest{
			Operation:   op.Type,
			DidSuffix:   op.UniqueSuffix,
			SignedData:  op.SignedData,
			RevealValue: op.RevealValue,
		}

	case operation.TypeRecover:
		request = RecoverRequest{
			Operation:   op.Type,
			DidSuffix:   op.UniqueSuffix,
			Delta:       op.Delta,
			SignedData:  op.SignedData,
			RevealValue: op.RevealValue,
		}

	default:
		return nil, fmt.Errorf("operation type %s not supported for anchored operation", op.Type)
	}

	operationBuffer, err := canonicalizer.MarshalCanonical(request)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize anchored operation[%v]: %s", op, err.Error())
	}

	return &operation.AnchoredOperation{
		Type:            op.Type,
		UniqueSuffix:    op.UniqueSuffix,
		OperationBuffer: operationBuffer,
		AnchorOrigin:    op.AnchorOrigin,
	}, nil
}

// GetUniqueSuffix calculates unique suffix from suffix data and multihash algorithms.
func GetUniqueSuffix(model *SuffixDataModel, algs []uint) (string, error) {
	if len(algs) == 0 {
		return "", errors.New("failed to calculate unique suffix: algorithm not provided")
	}

	// Even though protocol supports the list of multihashing algorithms in this protocol version (v1) we can have
	// only one multihashing algorithm. Later versions may have multiple values for backward compatibility.
	// At that point (version 2) the spec will hopefully better define how to handle this scenarios:
	// https://github.com/decentralized-identity/sidetree/issues/965
	encodedComputedMultihash, err := hashing.CalculateModelMultihash(model, algs[0])
	if err != nil {
		return "", fmt.Errorf("failed to calculate unique suffix: %s", err.Error())
	}

	return encodedComputedMultihash, nil
}
