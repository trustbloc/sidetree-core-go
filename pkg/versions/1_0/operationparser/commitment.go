package operationparser

import (
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
)

// GetRevealValue returns this operation reveal value.
func (p *Parser) GetRevealValue(opBytes []byte) (string, error) {
	// namespace is irrelevant in this case
	op, err := p.ParseOperation("", opBytes, true)
	if err != nil {
		return "", fmt.Errorf("get reveal value - parse operation error: %s", err.Error())
	}

	if op.Type == operation.TypeCreate {
		return "", fmt.Errorf("operation type '%s' not supported for getting operation reveal value", op.Type)
	}

	return op.RevealValue, nil
}

// GetCommitment returns next operation commitment.
func (p *Parser) GetCommitment(opBytes []byte) (string, error) {
	// namespace is irrelevant in this case
	op, err := p.ParseOperation("", opBytes, true)
	if err != nil {
		return "", fmt.Errorf("get commitment - parse operation error: %s", err.Error())
	}

	switch op.Type { //nolint:exhaustive
	case operation.TypeUpdate:
		return op.Delta.UpdateCommitment, nil

	case operation.TypeDeactivate:
		return "", nil

	case operation.TypeRecover:
		signedDataModel, innerErr := p.ParseSignedDataForRecover(op.SignedData)
		if innerErr != nil {
			return "", fmt.Errorf("failed to parse signed data model for recover: %s", innerErr.Error())
		}

		return signedDataModel.RecoveryCommitment, nil
	}

	return "", fmt.Errorf("operation type '%s' not supported for getting next operation commitment", op.Type)
}
