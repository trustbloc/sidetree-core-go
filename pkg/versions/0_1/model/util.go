/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import (
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
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
			Operation:  op.Type,
			DidSuffix:  op.UniqueSuffix,
			Delta:      op.Delta,
			SignedData: op.SignedData,
		}

	case operation.TypeDeactivate:
		request = DeactivateRequest{
			Operation:  op.Type,
			DidSuffix:  op.UniqueSuffix,
			SignedData: op.SignedData,
		}

	case operation.TypeRecover:
		request = RecoverRequest{
			Operation:  op.Type,
			DidSuffix:  op.UniqueSuffix,
			Delta:      op.Delta,
			SignedData: op.SignedData,
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
	}, nil
}
