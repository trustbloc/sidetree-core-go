/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package processor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

func TestOperationFilter_Filter(t *testing.T) {
	t.Run("Store error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		errExpected := errors.New("injected store error")
		store := mocks.NewMockOperationStore(nil)
		store.Validate = false
		store.Err = errExpected

		createOp, err := getCreateOperation(privateKey)
		require.NoError(t, err)

		filter := NewOperationFilter("test", store)
		validOps, err := filter.Filter(createOp.UniqueSuffix, []*batch.Operation{createOp})
		require.EqualError(t, err, err.Error())
		require.Empty(t, validOps)
	})

	t.Run("No create operation error", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		store := mocks.NewMockOperationStore(nil)
		store.Validate = false

		createOp, err := getCreateOperation(privateKey)
		require.NoError(t, err)

		updateOp1, err := getUpdateOperation(privateKey, createOp.UniqueSuffix, 1)
		require.NoError(t, err)

		filter := NewOperationFilter("test", store)
		validOps, err := filter.Filter(createOp.UniqueSuffix, []*batch.Operation{updateOp1})
		require.EqualError(t, err, "missing create operation")
		require.Empty(t, validOps)
	})

	t.Run("Unique suffix not found in store", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		store := mocks.NewMockOperationStore(nil)
		store.Validate = false

		createOp, err := getCreateOperation(privateKey)
		require.NoError(t, err)

		updateOp1, err := getUpdateOperation(privateKey, createOp.UniqueSuffix, 1)
		require.NoError(t, err)
		updateOp2, err := getUpdateOperation(privateKey, createOp.UniqueSuffix, 3)
		require.NoError(t, err)

		// The second update should be discarded
		filter := NewOperationFilter("test", store)
		validOps, err := filter.Filter(createOp.UniqueSuffix, []*batch.Operation{createOp, updateOp1, updateOp2})
		require.NoError(t, err)
		require.Len(t, validOps, 2)
		require.True(t, validOps[0] == createOp)
		require.True(t, validOps[1] == updateOp1)
	})

	t.Run("Unique suffix exists in store", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		store := mocks.NewMockOperationStore(nil)
		store.Validate = false

		createOp1, err := getCreateOperation(privateKey)
		require.NoError(t, err)
		err = store.Put(createOp1)
		require.Nil(t, err)

		createOp2, err := getCreateOperation(privateKey)
		require.NoError(t, err)
		updateOp1, err := getUpdateOperation(privateKey, "123456", 1)
		require.NoError(t, err)
		updateOp2, err := getUpdateOperation(privateKey, createOp1.UniqueSuffix, 1)
		require.NoError(t, err)
		updateOp3, err := getUpdateOperation(privateKey, createOp1.UniqueSuffix, 3)
		require.NoError(t, err)

		// The create operation and first and third update should be discarded
		filter := NewOperationFilter("test", store)
		validOps, err := filter.Filter(createOp1.UniqueSuffix, []*batch.Operation{createOp2, updateOp1, updateOp2, updateOp3})
		require.NoError(t, err)
		require.Len(t, validOps, 1)
		require.True(t, validOps[0] == updateOp2)
	})

	t.Run("With deactivate operation", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		store := mocks.NewMockOperationStore(nil)
		store.Validate = false

		createOp1, err := getCreateOperation(privateKey)
		require.NoError(t, err)

		err = store.Put(createOp1)
		require.Nil(t, err)

		createOp2, err := getCreateOperation(privateKey)
		require.NoError(t, err)
		updateOp, err := getUpdateOperation(privateKey, createOp1.UniqueSuffix, 1)
		require.NoError(t, err)
		deactivateOp, err := getDeactivateOperation(privateKey, createOp1.UniqueSuffix, 2)
		require.NoError(t, err)

		// The create should be discarded (since there's already a create) and update should be discarded since the document was deactivated
		filter := NewOperationFilter("test", store)
		validOps, err := filter.Filter(createOp1.UniqueSuffix, []*batch.Operation{createOp2, updateOp, deactivateOp})
		require.NoError(t, err)
		require.Len(t, validOps, 1)
		require.True(t, validOps[0] == deactivateOp)
	})
}
