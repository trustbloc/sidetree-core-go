package operationparser

import (
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

// GetRevealValue returns this operation reveal value.
func (p *Parser) GetRevealValue(opBytes []byte) (*jws.JWK, error) {
	// namespace is irrelevant in this case
	op, err := p.ParseOperation("", opBytes)
	if err != nil {
		return nil, fmt.Errorf("get reveal value - parse operation error: %s", err.Error())
	}

	switch op.Type { //nolint:exhaustive
	case operation.TypeUpdate:
		signedDataModel, innerErr := p.ParseSignedDataForUpdate(op.SignedData)
		if innerErr != nil {
			return nil, fmt.Errorf("failed to parse signed data model for update: %s", innerErr.Error())
		}

		return signedDataModel.UpdateKey, nil

	case operation.TypeDeactivate:
		signedDataModel, innerErr := p.ParseSignedDataForDeactivate(op.SignedData)
		if innerErr != nil {
			return nil, fmt.Errorf("failed to parse signed data model for deactivate: %s", innerErr.Error())
		}

		return signedDataModel.RecoveryKey, nil

	case operation.TypeRecover:
		signedDataModel, innerErr := p.ParseSignedDataForRecover(op.SignedData)
		if innerErr != nil {
			return nil, fmt.Errorf("failed to parse signed data model for recover: %s", innerErr.Error())
		}

		return signedDataModel.RecoveryKey, nil
	}

	return nil, fmt.Errorf("operation type '%s' not supported for getting operation reveal value", op.Type)
}

// GetCommitment returns next operation commitment.
func (p *Parser) GetCommitment(opBytes []byte) (string, error) {
	// namespace is irrelevant in this case
	op, err := p.ParseOperation("", opBytes)
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
