/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
)

const suffix = "suffix"

func TestGetAnchoredOperation(t *testing.T) {
	t.Run("success - create", func(t *testing.T) {
		op := &Operation{
			Type:         operation.TypeCreate,
			UniqueSuffix: suffix,
			SuffixData: &SuffixDataModel{
				RecoveryCommitment: "rc",
				DeltaHash:          "dh",
			},
			Delta: &DeltaModel{
				UpdateCommitment: "uc",
			},
		}

		opBuffer := `{"delta":{"updateCommitment":"uc"},"suffixData":{"deltaHash":"dh","recoveryCommitment":"rc"},"type":"create"}`

		anchored, err := GetAnchoredOperation(op)
		require.NoError(t, err)
		require.NotNil(t, anchored)

		require.Equal(t, op.Type, anchored.Type)
		require.Equal(t, opBuffer, string(anchored.OperationRequest))
		require.Equal(t, suffix, anchored.UniqueSuffix)
	})

	t.Run("success - deactivate", func(t *testing.T) {
		op := &Operation{
			Type:         operation.TypeDeactivate,
			UniqueSuffix: suffix,
			RevealValue:  "rv",
			SignedData:   "jws",
		}

		opBuffer := `{"didSuffix":"suffix","revealValue":"rv","signedData":"jws","type":"deactivate"}`

		anchored, err := GetAnchoredOperation(op)
		require.NoError(t, err)
		require.NotNil(t, anchored)

		require.Equal(t, op.Type, anchored.Type)
		require.Equal(t, opBuffer, string(anchored.OperationRequest))
		require.Equal(t, suffix, anchored.UniqueSuffix)
	})

	t.Run("success - recover", func(t *testing.T) {
		op := &Operation{
			Type:         operation.TypeRecover,
			UniqueSuffix: suffix,
			RevealValue:  "rv",
			SignedData:   "jws",
			Delta: &DeltaModel{
				UpdateCommitment: "uc",
			},
		}

		opBuffer := `{"delta":{"updateCommitment":"uc"},"didSuffix":"suffix","revealValue":"rv","signedData":"jws","type":"recover"}`

		anchored, err := GetAnchoredOperation(op)
		require.NoError(t, err)
		require.NotNil(t, anchored)
		require.Equal(t, op.Type, anchored.Type)

		require.Equal(t, opBuffer, string(anchored.OperationRequest))
		require.Equal(t, suffix, anchored.UniqueSuffix)
	})

	t.Run("success - update", func(t *testing.T) {
		op := &Operation{
			Type:         operation.TypeUpdate,
			UniqueSuffix: suffix,
			RevealValue:  "rv",
			SignedData:   "jws",
			Delta: &DeltaModel{
				UpdateCommitment: "uc",
			},
		}

		opBuffer := `{"delta":{"updateCommitment":"uc"},"didSuffix":"suffix","revealValue":"rv","signedData":"jws","type":"update"}`
		anchored, err := GetAnchoredOperation(op)
		require.NoError(t, err)
		require.NotNil(t, anchored)
		require.Equal(t, anchored.Type, op.Type)

		require.Equal(t, opBuffer, string(anchored.OperationRequest))
		require.Equal(t, suffix, anchored.UniqueSuffix)
	})

	t.Run("error - type not supported", func(t *testing.T) {
		op := &Operation{Type: "other"}

		anchored, err := GetAnchoredOperation(op)
		require.Error(t, err)
		require.Nil(t, anchored)
		require.Contains(t, err.Error(), "operation type other not supported for anchored operation")
	})
}

func TestGetUniqueSuffix(t *testing.T) {
	s := &SuffixDataModel{
		RecoveryCommitment: "rc",
		DeltaHash:          "dh",
	}

	t.Run("success", func(t *testing.T) {
		uniqueSuffix, err := GetUniqueSuffix(s, []uint{18})
		require.NoError(t, err)
		require.NotEmpty(t, uniqueSuffix)
	})

	t.Run("error - algorithm not provided", func(t *testing.T) {
		uniqueSuffix, err := GetUniqueSuffix(s, []uint{})
		require.Error(t, err)
		require.Empty(t, uniqueSuffix)
		require.Contains(t, err.Error(), "failed to calculate unique suffix: algorithm not provided")
	})

	t.Run("error - algorithm not supported", func(t *testing.T) {
		uniqueSuffix, err := GetUniqueSuffix(s, []uint{55})
		require.Error(t, err)
		require.Empty(t, uniqueSuffix)
		require.Contains(t, err.Error(), "failed to calculate unique suffix: algorithm not supported")
	})
}
