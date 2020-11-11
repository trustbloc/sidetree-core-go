/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commitment

import (
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/encoder"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

var logger = log.New("sidetree-core-commitment")

// Calculate will calculate commitment hash from JWK.
func Calculate(jwk *jws.JWK, multihashCode uint) (string, error) {
	data, err := canonicalizer.MarshalCanonical(jwk)
	if err != nil {
		return "", err
	}

	logger.Debugf("calculating commitment from JWK: %s", string(data))

	hash, err := hashing.GetHashFromMultihash(multihashCode)
	if err != nil {
		return "", err
	}

	dataHash, err := hashing.GetHash(hash, data)
	if err != nil {
		return "", err
	}

	multiHash, err := hashing.ComputeMultihash(multihashCode, dataHash)
	if err != nil {
		return "", err
	}

	return encoder.EncodeToString(multiHash), nil
}
