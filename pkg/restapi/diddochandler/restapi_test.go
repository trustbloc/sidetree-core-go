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
)

const (
	url       = "localhost:4656"
	clientURL = "http://" + url
	basePath  = "/Document"
)

func TestRESTAPI(t *testing.T) {
	pc := newMockProtocolClient()
	didDocHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace).WithProtocolClient(pc)

	s := newRESTService(
		url,
		NewUpdateHandler(basePath, didDocHandler, pc),
		NewResolveHandler(basePath, didDocHandler),
	)
	s.start()
	defer s.stop()

	t.Run("Create DID doc", func(t *testing.T) {
		createRequest, err := getCreateRequest()
		require.NoError(t, err)
		request, err := json.Marshal(createRequest)
		require.NoError(t, err)

		resp, err := httpPut(t, clientURL+basePath+"/operations", request)
		require.NoError(t, err)
		require.NotEmpty(t, resp)

		didID, err := getID(createRequest.SuffixData)
		require.NoError(t, err)

		var result document.ResolutionResult
		require.NoError(t, json.Unmarshal(resp, &result))
		require.Equal(t, didID, result.Document["id"])
	})
	t.Run("Resolve DID doc", func(t *testing.T) {
		createRequest, err := getCreateRequest()
		require.NoError(t, err)

		didID, err := getID(createRequest.SuffixData)
		require.NoError(t, err)

		resp, err := httpGet(t, clientURL+basePath+"/identifiers/"+didID)
		require.NoError(t, err)
		require.NotEmpty(t, resp)

		var result document.ResolutionResult
		err = json.Unmarshal(resp, &result)
		require.NoError(t, err)

		require.Equal(t, didID, result.Document["id"])
	})
}

// httpPut sends a regular POST request to the sidetree-node
// - If post request has operation "create" then return sidetree document else no response
func httpPut(t *testing.T, url string, request []byte) ([]byte, error) {
	client := &http.Client{}

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(request))
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
