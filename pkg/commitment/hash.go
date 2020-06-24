/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commitment

import (
	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

//Calculate will calculate commitment hash from JWK
func Calculate(jwk *jws.JWK, multihashCode uint) (string, error) {
	data, err := canonicalizer.MarshalCanonical(jwk)
	if err != nil {
		return "", err
	}

	log.Debugf("calculating commitment from JWK: %s", string(data))

	multiHashBytes, err := docutil.ComputeMultihash(multihashCode, data)
	if err != nil {
		return "", err
	}

	return docutil.EncodeToString(multiHashBytes), nil
}
