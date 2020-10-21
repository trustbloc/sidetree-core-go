package operationparser

import (
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

// GetRevealValue returns this operation reveal value.
func (p *Parser) GetRevealValue(operation []byte) (*jws.JWK, error) {
	// namespace is irrelevant in this case
	op, err := p.ParseOperation("", operation)
	if err != nil {
		return nil, fmt.Errorf("get reveal value - parse operation error: %s", err.Error())
	}

	switch op.Type { //nolint:exhaustive
	case batch.OperationTypeUpdate:
		signedDataModel, innerErr := p.ParseSignedDataForUpdate(op.SignedData)
		if innerErr != nil {
			return nil, fmt.Errorf("failed to parse signed data model for update: %s", innerErr.Error())
		}

		return signedDataModel.UpdateKey, nil

	case batch.OperationTypeDeactivate:
		signedDataModel, innerErr := p.ParseSignedDataForDeactivate(op.SignedData)
		if innerErr != nil {
			return nil, fmt.Errorf("failed to parse signed data model for deactivate: %s", innerErr.Error())
		}

		return signedDataModel.RecoveryKey, nil

	case batch.OperationTypeRecover:
		signedDataModel, innerErr := p.ParseSignedDataForRecover(op.SignedData)
		if innerErr != nil {
			return nil, fmt.Errorf("failed to parse signed data model for recover: %s", innerErr.Error())
		}

		return signedDataModel.RecoveryKey, nil
	}

	return nil, fmt.Errorf("operation type '%s' not supported for getting operation reveal value", op.Type)
}

// GetCommitment returns next operation commitment.
func (p *Parser) GetCommitment(operation []byte) (string, error) {
	// namespace is irrelevant in this case
	op, err := p.ParseOperation("", operation)
	if err != nil {
		return "", fmt.Errorf("get commitment - parse operation error: %s", err.Error())
	}

	switch op.Type { //nolint:exhaustive
	case batch.OperationTypeUpdate:
		return op.Delta.UpdateCommitment, nil

	case batch.OperationTypeDeactivate:
		return "", nil

	case batch.OperationTypeRecover:
		signedDataModel, innerErr := p.ParseSignedDataForRecover(op.SignedData)
		if innerErr != nil {
			return "", fmt.Errorf("failed to parse signed data model for recover: %s", innerErr.Error())
		}

		return signedDataModel.RecoveryCommitment, nil
	}

	return "", fmt.Errorf("operation type '%s' not supported for getting next operation commitment", op.Type)
}
