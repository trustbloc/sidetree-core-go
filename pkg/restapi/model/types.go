/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

// OperationType is the operation type
// swagger:model OperationType
type OperationType string

const (
	// OperationTypeCreate captures enum value "create"
	OperationTypeCreate OperationType = "create"

	// OperationTypeUpdate captures enum value "update"
	OperationTypeUpdate OperationType = "update"

	// OperationTypeDeactivate captures enum value "deactivate"
	OperationTypeDeactivate OperationType = "deactivate"

	// OperationTypeRecover captures enum value "recover"
	OperationTypeRecover OperationType = "recover"
)
