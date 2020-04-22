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

const methodParamTemplate = "-%s-initial-state"

// GetInitialStateParam returns initial state parameter for namespace (more specifically method)
func GetInitialStateParam(namespace string) string {
	method := getMethod(namespace)
	return fmt.Sprintf(methodParamTemplate, method)
}

// getMethod returns method from namespace
func getMethod(namespace string) string {
	pos := strings.Index(namespace, ":")
	if pos == -1 || pos+1 == len(namespace) {
		return ""
	}

	return namespace[pos+1:]
}

// GetParts inspects params string and returns did and optional initial state value
func GetParts(namespace, params string) (string, *model.CreateRequest, error) {
	initialParam := GetInitialStateParam(namespace)
	initialMatch := "?" + initialParam + "="

	pos := strings.Index(params, initialMatch)
	if pos == -1 {
		// there is no initial-values so params contains only did
		return params, nil, nil
	}

	adjustedPos := pos + len(initialMatch)
	if adjustedPos >= len(params) {
		return "", nil, errors.New("initial values is present but empty")
	}

	did := params[0:pos]

	initialStateParts := strings.Split(params[adjustedPos:], ".")

	const twoParts = 2
	if len(initialStateParts) != twoParts {
		return "", nil, errors.New("initial state should have two parts: delta and suffix data")
	}

	initial := &model.CreateRequest{
		Operation:  model.OperationTypeCreate,
		Delta:      initialStateParts[0],
		SuffixData: initialStateParts[1],
	}

	// return did and initial state
	return did, initial, nil
}
