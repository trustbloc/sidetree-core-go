/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import "time"

// MetricsProvider implements a mock metrics provider.
type MetricsProvider struct{}

// ProcessOperation records the overall time to process operation.
func (m *MetricsProvider) ProcessOperation(value time.Duration) {
}

// GetProtocolVersionTime records the time to get protocol version.
func (m *MetricsProvider) GetProtocolVersionTime(value time.Duration) {
}

// ParseOperationTime records the time to parse operations.
func (m *MetricsProvider) ParseOperationTime(value time.Duration) {
}

// ValidateOperationTime records the time to validate operation.
func (m *MetricsProvider) ValidateOperationTime(value time.Duration) {
}

// DecorateOperationTime records the time to decorate operation.
func (m *MetricsProvider) DecorateOperationTime(value time.Duration) {
}

// AddUnpublishedOperationTime records the time to add unpublished operation.
func (m *MetricsProvider) AddUnpublishedOperationTime(value time.Duration) {
}

// AddOperationToBatchTime records the time to add operation to batch.
func (m *MetricsProvider) AddOperationToBatchTime(value time.Duration) {
}

// GetCreateOperationResultTime records the time to create operation result response.
func (m *MetricsProvider) GetCreateOperationResultTime(value time.Duration) {
}

// HTTPCreateUpdateTime records the time rest call for create or update.
func (m *MetricsProvider) HTTPCreateUpdateTime(value time.Duration) {
}

// HTTPResolveTime records the time rest call for resolve.
func (m *MetricsProvider) HTTPResolveTime(value time.Duration) {
}

// CASWriteSize records the size of the data written to CAS.
func (m *MetricsProvider) CASWriteSize(dataType string, size int) {
}
