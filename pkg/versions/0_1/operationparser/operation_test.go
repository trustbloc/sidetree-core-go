/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationparser

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
)

const (
	namespace = "did:sidetree"

	maxOperationSize = 2000
	maxHashLength    = 100
	maxDeltaSize     = 1000
)

func TestNewParser(t *testing.T) {
	p := protocol.Protocol{}

	parser := New(p)
	require.NotNil(t, parser)
	require.NotNil(t, parser.anchorOriginValidator)

	// validator cannot be set to nil (default validator will kick in)
	parser = New(p, WithAnchorOriginValidator(nil))
	require.NotNil(t, parser)
	require.NotNil(t, parser.anchorOriginValidator)

	// supply custom validator
	ov := &mockObjectValidator{}

	parser = New(p, WithAnchorOriginValidator(ov))
	require.NotNil(t, parser)
	require.Equal(t, ov, parser.anchorOriginValidator)

	// custom anchor time validator
	tv := &mockTimeValidator{}

	parser = New(p, WithAnchorTimeValidator(tv))
	require.NotNil(t, parser)
	require.Equal(t, tv, parser.anchorTimeValidator)
}

func TestGetOperation(t *testing.T) {
	p := protocol.Protocol{
		MaxOperationSize:       maxOperationSize,
		MaxOperationHashLength: maxHashLength,
		MaxDeltaSize:           maxDeltaSize,
		MultihashAlgorithms:    []uint{sha2_256},
		SignatureAlgorithms:    []string{"alg"},
		KeyAlgorithms:          []string{"crv"},
		Patches:                []string{"add-public-keys", "remove-public-keys", "add-services", "remove-services", "ietf-json-patch"},
	}

	parser := New(p)

	t.Run("create", func(t *testing.T) {
		operation, err := getCreateRequestBytes()
		require.NoError(t, err)

		op, err := parser.Parse(namespace, operation)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("update", func(t *testing.T) {
		operation, err := getUpdateRequestBytes()
		require.NoError(t, err)

		op, err := parser.Parse(namespace, operation)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("deactivate", func(t *testing.T) {
		operation, err := getDeactivateRequestBytes()
		require.NoError(t, err)

		op, err := parser.Parse(namespace, operation)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("recover", func(t *testing.T) {
		operation, err := getRecoverRequestBytes()
		require.NoError(t, err)

		op, err := parser.Parse(namespace, operation)
		require.NoError(t, err)
		require.NotNil(t, op)
	})
	t.Run("operation parsing error - anchor origin validator error (create)", func(t *testing.T) {
		operation, err := getCreateRequestBytes()
		require.NoError(t, err)

		testErr := errors.New("validation error")
		parserWithErr := New(p, WithAnchorOriginValidator(&mockObjectValidator{Err: testErr}))

		op, err := parserWithErr.Parse(namespace, operation)
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(), testErr.Error())
	})
	t.Run("operation parsing error - anchor origin validator error (recover)", func(t *testing.T) {
		operation, err := getRecoverRequestBytes()
		require.NoError(t, err)

		testErr := errors.New("validation error")
		parserWithErr := New(p, WithAnchorOriginValidator(&mockObjectValidator{Err: testErr}))

		op, err := parserWithErr.Parse(namespace, operation)
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(), testErr.Error())
	})
	t.Run("operation parsing error - anchor time validator error (update)", func(t *testing.T) {
		operation, err := getUpdateRequestBytes()
		require.NoError(t, err)

		testErr := errors.New("anchor time validation error")
		parserWithErr := New(p, WithAnchorTimeValidator(&mockTimeValidator{Err: testErr}))

		op, err := parserWithErr.Parse(namespace, operation)
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(), testErr.Error())
	})
	t.Run("operation parsing error - anchor time validator error (deactivate)", func(t *testing.T) {
		operation, err := getDeactivateRequestBytes()
		require.NoError(t, err)

		testErr := errors.New("anchor time validation error")
		parserWithErr := New(p, WithAnchorTimeValidator(&mockTimeValidator{Err: testErr}))

		op, err := parserWithErr.Parse(namespace, operation)
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(), testErr.Error())
	})
	t.Run("operation parsing error - anchor time validator error (recover)", func(t *testing.T) {
		operation, err := getRecoverRequestBytes()
		require.NoError(t, err)

		testErr := errors.New("anchor time validation error")
		parserWithErr := New(p, WithAnchorTimeValidator(&mockTimeValidator{Err: testErr}))

		op, err := parserWithErr.Parse(namespace, operation)
		require.Error(t, err)
		require.Nil(t, op)
		require.Contains(t, err.Error(), testErr.Error())
	})

	t.Run("operation parsing error - exceeds max operation size", func(t *testing.T) {
		// set-up invalid hash algorithm in protocol configuration
		invalid := protocol.Protocol{
			MaxOperationSize: 20,
			MaxDeltaSize:     maxDeltaSize,
		}

		operation, err := getRecoverRequestBytes()
		require.NoError(t, err)

		op, err := New(invalid).Parse(namespace, operation)
		require.Error(t, err)
		require.Contains(t, err.Error(), "operation size[761] exceeds maximum operation size[20]")
		require.Nil(t, op)
	})
	t.Run("operation parsing error", func(t *testing.T) {
		// set-up invalid hash algorithm in protocol configuration
		invalid := protocol.Protocol{
			SignatureAlgorithms:    []string{"not-used"},
			MaxOperationSize:       maxOperationSize,
			MaxDeltaSize:           maxDeltaSize,
			MaxOperationHashLength: maxHashLength,
			MultihashAlgorithms:    []uint{sha2_256},
		}

		operation, err := getRecoverRequestBytes()
		require.NoError(t, err)

		op, err := New(invalid).Parse(namespace, operation)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse signed data: algorithm 'alg' is not in the allowed list [not-used]")
		require.Nil(t, op)
	})
	t.Run("unsupported operation type error", func(t *testing.T) {
		operation := getUnsupportedRequest()
		op, err := parser.Parse(namespace, operation)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse operation: operation type [unsupported] not supported")
		require.Nil(t, op)
	})
	t.Run("unmarshal request error - not JSON", func(t *testing.T) {
		op, err := parser.Parse(namespace, []byte("operation"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal operation buffer into operation schema")
		require.Nil(t, op)
	})
}

func getUnsupportedRequest() []byte {
	schema := &operationSchema{
		Operation: "unsupported",
	}

	payload, err := json.Marshal(schema)
	if err != nil {
		panic(err)
	}

	return payload
}

type mockObjectValidator struct {
	Err error
}

func (mov *mockObjectValidator) Validate(_ interface{}) error {
	return mov.Err
}

type mockTimeValidator struct {
	Err error
}

func (mtv *mockTimeValidator) Validate(from, until int64) error {
	if mtv.Err != nil {
		return mtv.Err
	}

	if from == 0 && until == 0 {
		// from and until are not specified - no error
		return nil
	}

	serverTime := time.Now().Unix()

	if from >= serverTime {
		return ErrOperationEarly
	}

	if until <= serverTime {
		return ErrOperationExpired
	}

	return nil
}
