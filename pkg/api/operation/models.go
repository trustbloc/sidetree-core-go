/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

// Operation holds minimum information required for parsing/validating client request.
type Operation struct {

	// Type defines operation type.
	Type Type

	// UniqueSuffix defines document unique suffix.
	UniqueSuffix string

	// ID defines ID
	ID string

	// OperationBuffer is the original operation request
	OperationBuffer []byte
}

// Reference holds minimum information about did operation (suffix and type).
type Reference struct {

	// UniqueSuffix defines document unique suffix.
	UniqueSuffix string

	// Type defines operation type.
	Type Type
}

// AnchoredOperation defines an anchored operation (stored in document operation store).
type AnchoredOperation struct {

	// Type defines operation type.
	Type Type `json:"type"`

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

// Type defines valid values for operation type.
type Type string

const (

	// TypeCreate captures "create" operation type.
	TypeCreate Type = "create"

	// TypeUpdate captures "update" operation type.
	TypeUpdate Type = "update"

	// TypeDeactivate captures "deactivate" operation type.
	TypeDeactivate Type = "deactivate"

	// TypeRecover captures "recover" operation type.
	TypeRecover Type = "recover"
)

// QueuedOperation stores minimum required operation info for operations queue.
type QueuedOperation struct {
	OperationBuffer []byte
	UniqueSuffix    string
	Namespace       string
}

// QueuedOperationAtTime contains queued operation info with protocol genesis time.
type QueuedOperationAtTime struct {
	QueuedOperation
	ProtocolGenesisTime uint64
}
