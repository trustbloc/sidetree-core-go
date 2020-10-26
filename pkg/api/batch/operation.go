/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package batch

// Operation defines minimum information.
// TODO: See if you can merge OperationInfo and Operation.
type Operation struct {

	// Type defines operation type.
	Type OperationType `json:"type"`

	// UniqueSuffix defines document unique suffix.
	UniqueSuffix string `json:"uniqueSuffix"`

	// ID defines ID
	ID string `json:"id"`

	// OperationBuffer is the original operation request
	OperationBuffer []byte `json:"operationBuffer"`
}

// AnchoredOperation defines an anchored operation (stored in document operation store).
type AnchoredOperation struct {

	// Type defines operation type.
	Type OperationType `json:"type"`

	// UniqueSuffix defines document unique suffix.
	UniqueSuffix string `json:"uniqueSuffix"`

	// OperationBuffer is the original operation request
	OperationBuffer []byte `json:"operationBuffer"`

	// TransactionTime is the logical blockchain time (block number) that this operation was anchored on the blockchain.
	TransactionTime uint64 `json:"transactionTime"`

	// TransactionNumber is the transaction number of the transaction this operation was batched within.
	TransactionNumber uint64 `json:"transactionNumber"`

	// ProtocolGenesisTime is the genesis time of the protocol that was used for this operation.
	ProtocolGenesisTime uint64 `json:"protocolGenesisTime"`
}

// OperationType defines valid values for operation type.
type OperationType string

const (

	// OperationTypeCreate captures "create" operation type.
	OperationTypeCreate OperationType = "create"

	// OperationTypeUpdate captures "update" operation type.
	OperationTypeUpdate OperationType = "update"

	// OperationTypeDeactivate captures "deactivate" operation type.
	OperationTypeDeactivate OperationType = "deactivate"

	// OperationTypeRecover captures "recover" operation type.
	OperationTypeRecover OperationType = "recover"
)

// OperationInfo contains the unique suffix and namespace as well as the operation buffer.
type OperationInfo struct {
	Data         []byte
	UniqueSuffix string
	Namespace    string
}

// OperationInfoAtTime contains OperationInfo at a given protocol genesis time.
type OperationInfoAtTime struct {
	OperationInfo
	ProtocolGenesisTime uint64
}
