/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package request

import (
	"errors"
	"fmt"
	"strings"

	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

const (
	methodParamTemplate   = "-%s-initial-state"
	minPartsInNamespace   = 2
	initialStateSeparator = "."
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
func GetParts(namespace, params string) (string, *model.CreateRequest, error) {
	initialStateParam := GetInitialStateParam(namespace)
	initialMatch := "?" + initialStateParam + "="

	posInitialStateParam := strings.Index(params, initialMatch)
	posDot := strings.Index(params, initialStateSeparator)

	if posInitialStateParam == -1 && posDot == -1 {
		// there is short form did
		return params, nil, nil
	}

	var did, longFormDID string
	if posInitialStateParam > 0 {
		did = params[0:posInitialStateParam]
		adjustedPos := posInitialStateParam + len(initialMatch)
		if adjustedPos >= len(params) {
			return "", nil, errors.New("initial state is present but empty")
		}

		longFormDID = params[adjustedPos:]
	} else {
		endOfDIDPos := strings.LastIndex(params, ":")

		did = params[0:endOfDIDPos]
		longFormDID = params[endOfDIDPos+1:]
	}

	initialStateParts := strings.Split(longFormDID, initialStateSeparator)

	const twoParts = 2
	if len(initialStateParts) != twoParts {
		return "", nil, errors.New("initial state should have two parts: suffix data and delta")
	}

	initial := &model.CreateRequest{
		Operation:  model.OperationTypeCreate,
		SuffixData: initialStateParts[0],
		Delta:      initialStateParts[1],
	}

	// return did and initial state
	return did, initial, nil
}

// GetInitialState return initial state string from create request
func GetInitialState(req *model.CreateRequest) string {
	return req.SuffixData + initialStateSeparator + req.Delta
}
