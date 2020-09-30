/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package request

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

const (
	methodParamTemplate   = "-%s-initial-state"
	minPartsInNamespace   = 2
	initialStateSeparator = "."
	longFormSeparator     = ":"
	didSeparator          = ":"
)

// GetInitialStateParam returns initial state parameter for namespace (more specifically method)
func GetInitialStateParam(namespace string) string {
	method := getMethod(namespace)
	return fmt.Sprintf(methodParamTemplate, method)
}

// getMethod returns method from namespace
func getMethod(namespace string) string {
	parts := strings.Split(namespace, ":")
	if len(parts) < minPartsInNamespace {
		return ""
	}

	return parts[1]
}

// GetParts inspects params string and returns did and optional initial state value
func GetParts(namespace, params string) (string, []byte, error) {
	var err error

	initialStateParam := GetInitialStateParam(namespace)
	initialMatch := "?" + initialStateParam + "="

	posInitialStateParam := strings.Index(params, initialMatch)

	paramsWithoutNamespace := strings.ReplaceAll(params, namespace+didSeparator, "")
	posLongFormSeparator := strings.Index(paramsWithoutNamespace, longFormSeparator)

	if posInitialStateParam == -1 && posLongFormSeparator == -1 {
		// there is short form did
		return params, nil, nil
	}

	var did string
	var createRequest interface{}
	if posInitialStateParam > 0 {
		// TODO: This part will be deprecated - issue-425
		did = params[0:posInitialStateParam]
		adjustedPos := posInitialStateParam + len(initialMatch)
		if adjustedPos >= len(params) {
			return "", nil, errors.New("initial state is present but empty")
		}

		longFormDID := params[adjustedPos:]

		initialStateParts := strings.Split(longFormDID, initialStateSeparator)

		const twoParts = 2
		if len(initialStateParts) != twoParts {
			return "", nil, errors.New("initial state should have two parts: suffix data and delta")
		}

		createRequest = &model.CreateRequest{
			Operation:  model.OperationTypeCreate,
			SuffixData: initialStateParts[0],
			Delta:      initialStateParts[1],
		}
	} else {
		// 'did:<methodName>:<unique-portion>:Base64url(JCS({suffix-data, delta}))'
		endOfDIDPos := strings.LastIndex(params, ":")

		did = params[0:endOfDIDPos]
		longFormDID := params[endOfDIDPos+1:]

		createRequest, err = getCreateRequestFromEncodedJCS(longFormDID)
		if err != nil {
			return "", nil, err
		}
	}

	createRequestBytes, err := canonicalizer.MarshalCanonical(createRequest)
	if err != nil {
		return "", nil, err
	}

	// return did and initial state
	return did, createRequestBytes, nil
}

func getCreateRequestFromEncodedJCS(initialStateJCS string) (*model.CreateRequestJCS, error) {
	decodedJCS, err := docutil.DecodeString(initialStateJCS)
	if err != nil {
		return nil, err
	}

	var createRequestJCS model.CreateRequestJCS
	err = json.Unmarshal(decodedJCS, &createRequestJCS)
	if err != nil {
		return nil, err
	}

	expectedJCS, err := canonicalizer.MarshalCanonical(createRequestJCS)
	if err != nil {
		return nil, err
	}

	if docutil.EncodeToString(expectedJCS) != initialStateJCS {
		return nil, errors.New("initial state JCS is not valid")
	}

	createRequestJCS.Operation = model.OperationTypeCreate

	return &createRequestJCS, nil
}

// GetInitialState return initial state string from create request
func GetInitialState(req *model.CreateRequest) string {
	return req.SuffixData + initialStateSeparator + req.Delta
}
