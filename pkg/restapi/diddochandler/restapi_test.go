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
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

const (
	url       = "localhost:4656"
	clientURL = "http://" + url
)

const (
	didID = namespace + "EiDOQXC2GnoVyHwIRbjhLx_cNc6vmZaS04SZjZdlLLAPRg=="
)

func TestRESTAPI(t *testing.T) {
	didDocHandler := mocks.NewMockDocumentHandler().WithNamespace(namespace)

	s := newRESTService(
		url,
		NewUpdateHandler(didDocHandler),
		NewResolveHandler(didDocHandler),
	)
	s.start()
	defer s.stop()

	t.Run("Create DID doc", func(t *testing.T) {
		request := &model.Request{}
		err := json.Unmarshal([]byte(createRequest), request)
		require.NoError(t, err)

		resp, err := httpPut(t, clientURL+Path, request)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Body)

		doc, ok := resp.Body.(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, didID, doc["id"])
	})
	t.Run("Resolve DID doc", func(t *testing.T) {
		resp, err := httpGet(t, clientURL+Path+"/"+didID)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Body)

		doc, ok := resp.Body.(map[string]interface{})
		require.True(t, ok)
		require.Equal(t, didID, doc["id"])
	})
}

// httpPut sends a regular POST request to the sidetree-node
// - If post request has operation "create" then return sidetree document else no response
func httpPut(t *testing.T, url string, req *model.Request) (*model.Response, error) {
	client := &http.Client{}
	b, err := json.Marshal(req)
	require.NoError(t, err)

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(b))
	require.NoError(t, err)

	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := invokeWithRetry(
		func() (response *http.Response, e error) {
			return client.Do(httpReq)
		},
	)
	require.NoError(t, err)
	return handleHttpResp(t, resp)
}

// httpGet send a regular GET request to the sidetree-node and expects 'side tree document' argument as a response
func httpGet(t *testing.T, url string) (*model.Response, error) {
	client := &http.Client{}
	resp, err := invokeWithRetry(
		func() (response *http.Response, e error) {
			return client.Get(url)
		},
	)
	require.NoError(t, err)
	return handleHttpResp(t, resp)
}

func handleHttpResp(t *testing.T, resp *http.Response) (*model.Response, error) {
	if status := resp.StatusCode; status != http.StatusOK {
		r := &model.Error{}
		decode(t, resp, r)
		return nil, fmt.Errorf(r.Message)
	}

	r := &model.Response{}
	decode(t, resp, r)
	return r, nil
}

func decode(t *testing.T, response *http.Response, v interface{}) {
	respBytes, err := ioutil.ReadAll(response.Body)
	require.NoError(t, err)
	err = json.NewDecoder(strings.NewReader(string(respBytes))).Decode(v)
	require.NoError(t, err)
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
