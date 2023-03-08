/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"bytes"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/logutil-go/pkg/log"
)

func TestStandardFields(t *testing.T) {
	const module = "test_module"

	u1 := parseURL(t, "https://example1.com")

	t.Run("json fields 1", func(t *testing.T) {
		stdOut := newMockWriter()

		logger := log.New(module, log.WithStdOut(stdOut), log.WithEncoding(log.JSON))

		rm := &mockObject{Field1: "value33", Field2: 888}

		logger.Info("Some message",
			WithData([]byte(`{"field":"value"}`)), WithServiceName("service1"), WithSize(1234),
			WithParameter("param1"), WithRequestBody([]byte(`request body`)),
			WithTotal(12), WithSuffix("1234"), WithOperationType("Create"),
			WithURIString(u1.String()), WithOperationID("op1"), WithGenesisTime(1233),
			WithOperationGenesisTime(3321), WithID("id1"), WithResolutionModel(rm),
		)

		t.Logf(stdOut.String())
		l := unmarshalLogData(t, stdOut.Bytes())

		require.Equal(t, `Some message`, l.Msg)
		require.Equal(t, `{"field":"value"}`, l.Data)
		require.Equal(t, `service1`, l.Service)
		require.Equal(t, 1234, l.Size)
		require.Equal(t, `param1`, l.Parameter)
		require.Equal(t, `request body`, l.RequestBody)
		require.Equal(t, 12, l.Total)
		require.Equal(t, "1234", l.Suffix)
		require.Equal(t, "Create", l.OperationType)
		require.Equal(t, `Some message`, l.Msg)
		require.Equal(t, u1.String(), l.URI)
		require.Equal(t, u1.String(), l.URI)
		require.Equal(t, "op1", l.OperationID)
		require.Equal(t, 1233, l.GenesisTime)
		require.Equal(t, 3321, l.OperationGenesisTime)
		require.Equal(t, "id1", l.ID)
		require.Equal(t, rm, l.ResolutionModel)
	})

	t.Run("json fields 2", func(t *testing.T) {
		stdOut := newMockWriter()

		logger := log.New(module, log.WithStdOut(stdOut), log.WithEncoding(log.JSON))

		op := &mockObject{Field1: "op1", Field2: 9486}
		txn := &mockObject{Field1: "txn1", Field2: 5967}
		patch := &mockObject{Field1: "patch1", Field2: 3265}

		logger.Info("Some message",
			WithSuffixes("suffix1", "suffix2"), WithVersion("v1"), WithMaxSize(20),
			WithOperation(op), WithSidetreeTxn(txn), WithNamespace("ns1"), WithAnchorString("anchor1"),
			WithSource("inbox"), WithTotalPending(36), WithTransactionTime(989), WithTransactionNumber(778),
			WithCommitment("commit1"), WithRecoveryCommitment("recommit1"), WithUpdateCommitment("upcommit1"),
			WithTotalCommitments(32), WithTotalOperations(54), WithTotalCreateOperations(12),
			WithTotalUpdateOperations(87), WithTotalRecoverOperations(12), WithTotalDeactivateOperations(3),
			WithDocument(map[string]interface{}{"field1": 1234}), WithDeactivated(true), WithOperations([]*mockObject{op}),
			WithVersionTime("12"), WithPatch(patch), WithIsBatch(true), WithContent([]byte("content1")),
			WithSources("source1", "source2"), WithAlias("alias1"),
		)

		l := unmarshalLogData(t, stdOut.Bytes())

		require.Equal(t, []string{"suffix1", "suffix2"}, l.Suffixes)
		require.Equal(t, "v1", l.Version)
		require.Equal(t, 20, l.MaxSize)
		require.Equal(t, op, l.Operation)
		require.Equal(t, txn, l.SidetreeTxn)
		require.Equal(t, "ns1", l.Namespace)
		require.Equal(t, "anchor1", l.AnchorString)
		require.Equal(t, "inbox", l.Source)
		require.Equal(t, 36, l.TotalPending)
		require.Equal(t, 989, l.TransactionTime)
		require.Equal(t, 778, l.TransactionNumber)
		require.Equal(t, "commit1", l.Commitment)
		require.Equal(t, "recommit1", l.RecoveryCommitment)
		require.Equal(t, "upcommit1", l.UpdateCommitment)
		require.Equal(t, 32, l.TotalCommitments)
		require.Equal(t, 54, l.TotalOperations)
		require.Equal(t, 12, l.TotalCreateOperations)
		require.Equal(t, 87, l.TotalUpdateOperations)
		require.Equal(t, 12, l.TotalRecoverOperations)
		require.Equal(t, 3, l.TotalDeactivateOperations)
		require.Equal(t, `{"field1":1234}`, l.Document)
		require.Equal(t, true, l.Deactivated)
		require.Equal(t, []*mockObject{op}, l.Operations)
		require.Equal(t, "12", l.VersionTime)
		require.Equal(t, patch, l.Patch)
		require.Equal(t, true, l.IsBatch)
		require.Equal(t, "content1", l.Content)
		require.Equal(t, []string{"source1", "source2"}, l.Sources)
		require.Equal(t, "alias1", l.Alias)
	})
}

type mockObject struct {
	Field1 string
	Field2 int
}

type logData struct {
	Level  string `json:"level"`
	Time   string `json:"time"`
	Logger string `json:"logger"`
	Caller string `json:"caller"`
	Msg    string `json:"msg"`
	Error  string `json:"error"`

	Data                      string        `json:"data"`
	Service                   string        `json:"service"`
	Size                      int           `json:"size"`
	Parameter                 string        `json:"parameter"`
	URI                       string        `json:"uri"`
	RequestBody               string        `json:"requestBody"`
	Total                     int           `json:"total"`
	Suffix                    string        `json:"suffix"`
	OperationType             string        `json:"operationType"`
	OperationID               string        `json:"operationID"`
	GenesisTime               int           `json:"genesisTime"`
	ID                        string        `json:"id"`
	ResolutionModel           *mockObject   `json:"resolutionModel"`
	Suffixes                  []string      `json:"suffixes"`
	Version                   string        `json:"version"`
	MaxSize                   int           `json:"maxSize"`
	Operation                 *mockObject   `json:"operation"`
	SidetreeTxn               *mockObject   `json:"sidetreeTxn"`
	Namespace                 string        `json:"namespace"`
	AnchorString              string        `json:"anchorString"`
	Source                    string        `json:"source"`
	OperationGenesisTime      int           `json:"opGenesisTime"`
	TotalPending              int           `json:"totalPending"`
	TransactionTime           int           `json:"transactionTime"`
	TransactionNumber         int           `json:"transactionNumber"`
	Commitment                string        `json:"commitment"`
	RecoveryCommitment        string        `json:"recoveryCommitment"`
	UpdateCommitment          string        `json:"updateCommitment"`
	TotalCommitments          int           `json:"totalCommitments"`
	TotalOperations           int           `json:"totalOperations"`
	TotalCreateOperations     int           `json:"totalCreateOperations"`
	TotalUpdateOperations     int           `json:"totalUpdateOperations"`
	TotalRecoverOperations    int           `json:"totalRecoverOperations"`
	TotalDeactivateOperations int           `json:"totalDeactivateOperations"`
	Document                  string        `json:"document"`
	Deactivated               bool          `json:"deactivated"`
	Operations                []*mockObject `json:"operations"`
	VersionTime               string        `json:"versionTime"`
	Patch                     *mockObject   `json:"patch"`
	IsBatch                   bool          `json:"isBatch"`
	Content                   string        `json:"content"`
	Sources                   []string      `json:"sources"`
	Alias                     string        `json:"alias"`
}

func unmarshalLogData(t *testing.T, b []byte) *logData {
	t.Helper()

	l := &logData{}

	require.NoError(t, json.Unmarshal(b, l))

	return l
}

func parseURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	u, err := url.Parse(raw)
	require.NoError(t, err)

	return u
}

type mockWriter struct {
	*bytes.Buffer
}

func (m *mockWriter) Sync() error {
	return nil
}

func newMockWriter() *mockWriter {
	return &mockWriter{Buffer: bytes.NewBuffer(nil)}
}
