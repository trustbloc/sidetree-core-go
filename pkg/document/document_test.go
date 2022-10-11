/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package document

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFromBytes(t *testing.T) {
	r := reader(t, "testdata/pk-doc.json")

	data, err := io.ReadAll(r)
	require.Nil(t, err)

	doc, err := FromBytes(data)
	require.Nil(t, err)
	require.NotNil(t, doc)
	require.Equal(t, "", doc.ID())
	require.Equal(t, 1, len(doc.PublicKeys()))
	require.Equal(t, 0, len(doc.Context()))

	bytes, err := doc.Bytes()
	require.Nil(t, err)
	require.NotEmpty(t, bytes)

	jsonld := doc.JSONLdObject()
	require.NotNil(t, jsonld)

	new := FromJSONLDObject(jsonld)
	require.Equal(t, doc.ID(), new.ID())
}

func TestFromBytesError(t *testing.T) {
	doc, err := FromBytes([]byte("[test : 123]"))
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "invalid character")
}

func TestMarshalError(t *testing.T) {
	doc := Document{}
	doc["test"] = make(chan int)

	bytes, err := doc.Bytes()
	require.NotNil(t, err)
	require.Nil(t, bytes)
	require.Contains(t, err.Error(), "json: unsupported type: chan int")
}

func TestGetStringValue(t *testing.T) {
	const key = "key"
	const value = "value"

	doc := Document{}
	doc[key] = value

	require.Equal(t, value, doc.GetStringValue(key))

	doc[key] = []string{"hello"}
	require.Equal(t, "", doc.GetStringValue(key))
}

func TestStringEntry(t *testing.T) {
	// not a string
	str := stringEntry([]string{"hello"})
	require.Empty(t, str)

	str = stringEntry("hello")
	require.Equal(t, "hello", str)
}

func TestArrayStringEntry(t *testing.T) {
	arr := StringArray(nil)
	require.Nil(t, arr)

	// not a array
	arr = StringArray("hello")
	require.Nil(t, arr)
}

func reader(t *testing.T, filename string) io.Reader {
	f, err := os.Open(filename)
	require.Nil(t, err)

	return f
}
