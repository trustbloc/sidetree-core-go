/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

// ResolutionResult describes resolution result
type ResolutionResult struct {
	Context        string
	DIDDocument    DIDDocument
	MethodMetadata MethodMetadata
}

// MethodMetadata contains document metadata
type MethodMetadata struct {
	OperationPublicKeys []PublicKey
	RecoveryKey         PublicKey
	Published           bool
}
