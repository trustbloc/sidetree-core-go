/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package batch

// Operation defines minimum information.
type Operation struct {

	// Type defines operation type.
	Type OperationType `json:"type"`

	// UniqueSuffix defines document unique suffix.
	UniqueSuffix string `json:"unique_suffix"`

	// ID ...
	// TODO: See if you can get rid of this
	ID string `json:"id"`

	// OperationBuffer is the original operation request
	OperationBuffer []byte `json:"operation_buffer"`
}

// AnchoredOperation defines an anchored operation (stored in document operation store).
type AnchoredOperation struct {

	// Type defines operation type.
	Type OperationType `json:"type"`

	// UniqueSuffix defines document unique suffix.
	UniqueSuffix string `json:"unique_suffix"`

	// OperationBuffer is the original operation request
	OperationBuffer []byte `json:"operation_buffer"`

	// TransactionTime is the logical blockchain time (block number) that this operation was anchored on the blockchain.
	TransactionTime uint64 `json:"transaction_time"`

	// TransactionNumber is the transaction number of the transaction this operation was batched within.
	TransactionNumber uint64 `json:"transaction_number"`

	// ProtocolGenesisTime is the genesis time of the protocol that was used for this operation.
	ProtocolGenesisTime uint64 `json:"protocol_genesis_time"`
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
