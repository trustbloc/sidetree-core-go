/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package request

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
)

const (
	longFormSeparator = ":"
	didSeparator      = ":"
)

// GetParts inspects params string and returns did and optional initial state value
func GetParts(namespace, shortOrLongFormDID string) (string, []byte, error) {
	var err error

	withoutNamespace := strings.ReplaceAll(shortOrLongFormDID, namespace+didSeparator, "")
	posLongFormSeparator := strings.Index(withoutNamespace, longFormSeparator)

	if posLongFormSeparator == -1 {
		// there is short form did
		return shortOrLongFormDID, nil, nil
	}

	// long form format: '<namespace>:<unique-portion>:Base64url(JCS({suffix-data, delta}))'
	endOfDIDPos := strings.LastIndex(shortOrLongFormDID, longFormSeparator)

	did := shortOrLongFormDID[0:endOfDIDPos]
	longFormDID := shortOrLongFormDID[endOfDIDPos+1:]

	createRequest, err := getCreateRequest(longFormDID)
	if err != nil {
		return "", nil, err
	}

	createRequestBytes, err := canonicalizer.MarshalCanonical(createRequest)
	if err != nil {
		return "", nil, err
	}

	// return did and initial state
	return did, createRequestBytes, nil
}

// get create request from encoded initial value JCS
func getCreateRequest(initialStateJCS string) (*model.CreateRequestJCS, error) {
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
