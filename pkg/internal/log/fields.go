/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"encoding/json"
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Log Fields.
const (
	FieldURI                       = "uri"
	FieldServiceName               = "service"
	FieldData                      = "data"
	FieldRequestBody               = "requestBody"
	FieldSize                      = "size"
	FieldMaxSize                   = "maxSize"
	FieldParameter                 = "parameter"
	FieldTotal                     = "total"
	FieldSuffix                    = "suffix"
	FieldSuffixes                  = "suffixes"
	FieldOperationType             = "operationType"
	FieldOperation                 = "operation"
	FieldOperations                = "operations"
	FieldOperationID               = "operationID"
	FieldGenesisTime               = "genesisTime"
	FieldOperationGenesisTime      = "opGenesisTime"
	FieldSidetreeTxn               = "sidetreeTxn"
	FieldID                        = "id"
	FieldResolutionModel           = "resolutionModel"
	FieldVersion                   = "version"
	FieldNamespace                 = "namespace"
	FieldAnchorString              = "anchorString"
	FieldSource                    = "source"
	FieldTotalPending              = "totalPending"
	FieldTransactionTime           = "transactionTime"
	FieldTransactionNumber         = "transactionNumber"
	FieldCommitment                = "commitment"
	FieldRecoveryCommitment        = "recoveryCommitment"
	FieldUpdateCommitment          = "updateCommitment"
	FieldTotalCommitments          = "totalCommitments"
	FieldTotalOperations           = "totalOperations"
	FieldTotalCreateOperations     = "totalCreateOperations"
	FieldTotalUpdateOperations     = "totalUpdateOperations"
	FieldTotalRecoverOperations    = "totalRecoverOperations"
	FieldTotalDeactivateOperations = "totalDeactivateOperations"
	FieldDocument                  = "document"
	FieldDeactivated               = "deactivated"
	FieldVersionTime               = "versionTime"
	FieldPatch                     = "patch"
	FieldIsBatch                   = "isBatch"
	FieldContent                   = "content"
	FieldSources                   = "sources"
	FieldAlias                     = "alias"
)

// WithURIString sets the uri field.
func WithURIString(value string) zap.Field {
	return zap.String(FieldURI, value)
}

// WithData sets the data field.
func WithData(value []byte) zap.Field {
	return zap.String(FieldData, string(value))
}

// WithRequestBody sets the request-body field.
func WithRequestBody(value []byte) zap.Field {
	return zap.String(FieldRequestBody, string(value))
}

// WithServiceName sets the service field.
func WithServiceName(value string) zap.Field {
	return zap.String(FieldServiceName, value)
}

// WithSize sets the size field.
func WithSize(value int) zap.Field {
	return zap.Int(FieldSize, value)
}

// WithMaxSize sets the max-size field.
func WithMaxSize(value int) zap.Field {
	return zap.Int(FieldMaxSize, value)
}

// WithParameter sets the parameter field.
func WithParameter(value string) zap.Field {
	return zap.String(FieldParameter, value)
}

// WithTotal sets the total field.
func WithTotal(value int) zap.Field {
	return zap.Int(FieldTotal, value)
}

// WithSuffix sets the suffix field.
func WithSuffix(value string) zap.Field {
	return zap.String(FieldSuffix, value)
}

// WithSuffixes sets the suffixes field.
func WithSuffixes(value ...string) zap.Field {
	return zap.Array(FieldSuffixes, NewStringArrayMarshaller(value))
}

// WithOperationType sets the operation-type field.
func WithOperationType(value string) zap.Field {
	return zap.Any(FieldOperationType, value)
}

// WithOperation sets the operation field.
func WithOperation(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldOperation, value))
}

// WithOperationID sets the operation-id field.
func WithOperationID(value string) zap.Field {
	return zap.String(FieldOperationID, value)
}

// WithGenesisTime sets the genesis-time field.
func WithGenesisTime(value uint64) zap.Field {
	return zap.Uint64(FieldGenesisTime, value)
}

// WithOperationGenesisTime sets the op-genesis-time field.
func WithOperationGenesisTime(value uint64) zap.Field {
	return zap.Uint64(FieldOperationGenesisTime, value)
}

// WithSidetreeTxn sets the sidetree-txn field.
func WithSidetreeTxn(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldSidetreeTxn, value))
}

// WithID sets the id field.
func WithID(value string) zap.Field {
	return zap.String(FieldID, value)
}

// WithResolutionModel sets the resolution-model field.
func WithResolutionModel(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldResolutionModel, value))
}

// WithVersion sets the version field.
func WithVersion(value string) zap.Field {
	return zap.String(FieldVersion, value)
}

// WithNamespace sets the namespace field.
func WithNamespace(value string) zap.Field {
	return zap.String(FieldNamespace, value)
}

// WithAnchorString sets the anchor-string field.
func WithAnchorString(value string) zap.Field {
	return zap.String(FieldAnchorString, value)
}

// WithSource sets the source field.
func WithSource(value string) zap.Field {
	return zap.String(FieldSource, value)
}

// WithTotalPending sets the total-pending field.
func WithTotalPending(value uint) zap.Field {
	return zap.Uint(FieldTotalPending, value)
}

// WithTransactionTime sets the transaction-time field.
func WithTransactionTime(value uint64) zap.Field {
	return zap.Uint64(FieldTransactionTime, value)
}

// WithTransactionNumber sets the transaction-number field.
func WithTransactionNumber(value uint64) zap.Field {
	return zap.Uint64(FieldTransactionNumber, value)
}

// WithCommitment sets the commitment field.
func WithCommitment(value string) zap.Field {
	return zap.String(FieldCommitment, value)
}

// WithRecoveryCommitment sets the recovery-commitment field.
func WithRecoveryCommitment(value string) zap.Field {
	return zap.String(FieldRecoveryCommitment, value)
}

// WithUpdateCommitment sets the update-commitment field.
func WithUpdateCommitment(value string) zap.Field {
	return zap.String(FieldUpdateCommitment, value)
}

// WithTotalCommitments sets the total-commitments field.
func WithTotalCommitments(value int) zap.Field {
	return zap.Int(FieldTotalCommitments, value)
}

// WithTotalOperations sets the total-operations field.
func WithTotalOperations(value int) zap.Field {
	return zap.Int(FieldTotalOperations, value)
}

// WithTotalCreateOperations sets the total-create-operations field.
func WithTotalCreateOperations(value int) zap.Field {
	return zap.Int(FieldTotalCreateOperations, value)
}

// WithTotalUpdateOperations sets the total-update-operations field.
func WithTotalUpdateOperations(value int) zap.Field {
	return zap.Int(FieldTotalUpdateOperations, value)
}

// WithTotalRecoverOperations sets the total-recover-operations field.
func WithTotalRecoverOperations(value int) zap.Field {
	return zap.Int(FieldTotalRecoverOperations, value)
}

// WithTotalDeactivateOperations sets the total-deactivate-operations field.
func WithTotalDeactivateOperations(value int) zap.Field {
	return zap.Int(FieldTotalDeactivateOperations, value)
}

// WithDocument sets the document field.
func WithDocument(value map[string]interface{}) zap.Field {
	return zap.Inline(newJSONMarshaller(FieldDocument, value))
}

// WithDeactivated sets the deactivated field.
func WithDeactivated(value bool) zap.Field {
	return zap.Bool(FieldDeactivated, value)
}

// WithOperations sets the operation field.
func WithOperations(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldOperations, value))
}

// WithVersionTime sets the version-time field.
func WithVersionTime(value string) zap.Field {
	return zap.String(FieldVersionTime, value)
}

// WithPatch sets the patch field.
func WithPatch(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldPatch, value))
}

// WithIsBatch sets the is-batch field.
func WithIsBatch(value bool) zap.Field {
	return zap.Bool(FieldIsBatch, value)
}

// WithContent sets the content field.
func WithContent(value []byte) zap.Field {
	return zap.String(FieldContent, string(value))
}

// WithSources sets the sources field.
func WithSources(value ...string) zap.Field {
	return zap.Array(FieldSources, NewStringArrayMarshaller(value))
}

// WithAlias sets the alias field.
func WithAlias(value string) zap.Field {
	return zap.String(FieldAlias, value)
}

type jsonMarshaller struct {
	key string
	obj interface{}
}

func newJSONMarshaller(key string, value interface{}) *jsonMarshaller {
	return &jsonMarshaller{key: key, obj: value}
}

func (m *jsonMarshaller) MarshalLogObject(e zapcore.ObjectEncoder) error {
	b, err := json.Marshal(m.obj)
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	e.AddString(m.key, string(b))

	return nil
}

// ObjectMarshaller uses reflection to marshal an object's fields.
type ObjectMarshaller struct {
	key string
	obj interface{}
}

// NewObjectMarshaller returns a new ObjectMarshaller.
func NewObjectMarshaller(key string, obj interface{}) *ObjectMarshaller {
	return &ObjectMarshaller{key: key, obj: obj}
}

// MarshalLogObject marshals the object's fields.
func (m *ObjectMarshaller) MarshalLogObject(e zapcore.ObjectEncoder) error {
	return e.AddReflected(m.key, m.obj)
}

// StringArrayMarshaller marshals an array of strings into a log field.
type StringArrayMarshaller struct {
	values []string
}

// NewStringArrayMarshaller returns a new StringArrayMarshaller.
func NewStringArrayMarshaller(values []string) *StringArrayMarshaller {
	return &StringArrayMarshaller{values: values}
}

// MarshalLogArray marshals the array.
func (m *StringArrayMarshaller) MarshalLogArray(e zapcore.ArrayEncoder) error {
	for _, v := range m.values {
		e.AppendString(v)
	}

	return nil
}
