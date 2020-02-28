/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diddochandler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

const (
	url       = "localhost:4656"
	clientURL = "http://" + url
	basePath  = "/Document"
)

func TestRESTAPI(t *testing.T) {
	didDocHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)

	s := newRESTService(
		url,
		NewUpdateHandler(basePath, didDocHandler),
		NewResolveHandler(basePath, didDocHandler),
	)
	s.start()
	defer s.stop()

	t.Run("Create DID doc", func(t *testing.T) {
		encodedPayload, err := getCreatePayload()
		require.NoError(t, err)
		createReq, err := getCreateRequest(encodedPayload)
		require.NoError(t, err)

		request := &model.Request{}
		err = json.Unmarshal(createReq, request)
		require.NoError(t, err)

		resp, err := httpPut(t, clientURL+basePath, request)
		require.NoError(t, err)
		require.NotEmpty(t, resp)

		didID, err := getID(encodedPayload)
		require.NoError(t, err)

		var doc document.Document
		require.NoError(t, json.Unmarshal(resp, &doc))
		require.Equal(t, didID, doc["id"])
	})
	t.Run("Resolve DID doc", func(t *testing.T) {
		encodedPayload, err := getCreatePayload()
		require.NoError(t, err)
		didID, err := getID(encodedPayload)
		require.NoError(t, err)

		resp, err := httpGet(t, clientURL+basePath+"/"+didID)
		require.NoError(t, err)
		require.NotEmpty(t, resp)

		var doc document.Document
		require.NoError(t, json.Unmarshal(resp, &doc))
		require.Equal(t, didID, doc["id"])
	})
}

// httpPut sends a regular POST request to the sidetree-node
// - If post request has operation "create" then return sidetree document else no response
func httpPut(t *testing.T, url string, req *model.Request) ([]byte, error) {
	client := &http.Client{}
	b, err := json.Marshal(req)
	require.NoError(t, err)

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(b))
	require.NoError(t, err)

	httpReq.Header.Set("Content-Type", "application/did+ld+json")
	resp, err := invokeWithRetry(
		func() (response *http.Response, e error) {
			return client.Do(httpReq)
		},
	)
	require.NoError(t, err)
	require.Equal(t, "application/did+ld+json", resp.Header.Get("content-type"))
	return handleHTTPResp(t, resp)
}

// httpGet send a regular GET request to the sidetree-node and expects 'side tree document' argument as a response
func httpGet(t *testing.T, url string) ([]byte, error) {
	client := &http.Client{}
	resp, err := invokeWithRetry(
		func() (response *http.Response, e error) {
			return client.Get(url)
		},
	)
	require.NoError(t, err)
	return handleHTTPResp(t, resp)
}

func handleHTTPResp(t *testing.T, resp *http.Response) ([]byte, error) {
	if status := resp.StatusCode; status != http.StatusOK {
		return nil, fmt.Errorf(string(read(t, resp)))
	}
	return read(t, resp), nil
}

func read(t *testing.T, response *http.Response) []byte {
	respBytes, err := ioutil.ReadAll(response.Body)
	require.NoError(t, err)
	return respBytes
}

func invokeWithRetry(invoke func() (*http.Response, error)) (*http.Response, error) {
	remainingAttempts := 20
	for {
		resp, err := invoke()
		if err == nil {
			return resp, err
		}
		remainingAttempts--
		if remainingAttempts == 0 {
			return nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type restService struct {
	httpServer *http.Server
}

func newRESTService(url string, handlers ...common.HTTPHandler) *restService {
	router := mux.NewRouter()
	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handler()).Methods(handler.Method())
	}
	return &restService{
		httpServer: &http.Server{
			Addr:    url,
			Handler: router,
		},
	}
}

func (s *restService) start() {
	go func() {
		err := s.httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			panic(fmt.Sprintf("failed to start Sidetree REST service on [%s]: %s", s.httpServer.Addr, err))
		}
	}()
}

func (s *restService) stop() {
	err := s.httpServer.Shutdown(context.Background())
	if err != nil {
		panic(fmt.Sprintf("failed to stop Sidetree REST service on [%s]: %s", s.httpServer.Addr, err))
	}
}
