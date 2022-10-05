/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commitment

import (
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/encoder"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	"github.com/trustbloc/sidetree-core-go/pkg/internal/log"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
)

var logger = log.New("sidetree-core-commitment")

// GetCommitment will calculate commitment from JWK.
func GetCommitment(jwk *jws.JWK, multihashCode uint) (string, error) {
	data, err := canonicalizer.MarshalCanonical(jwk)
	if err != nil {
		return "", err
	}

	logger.Debug("Calculating commitment from JWK", log.WithData(data))

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

// GetRevealValue will calculate reveal value from JWK.
func GetRevealValue(jwk *jws.JWK, multihashCode uint) (string, error) {
	rv, err := hashing.CalculateModelMultihash(jwk, multihashCode)
	if err != nil {
		return "", fmt.Errorf("failed to get reveal value: %s", err.Error())
	}

	return rv, nil
}

// GetCommitmentFromRevealValue will calculate commitment from reveal value.
func GetCommitmentFromRevealValue(rv string) (string, error) {
	mh, err := hashing.GetMultihash(rv)
	if err != nil {
		return "", fmt.Errorf("failed to get commitment from reveal value (get multihash): %s", err.Error())
	}

	multiHash, err := hashing.ComputeMultihash(uint(mh.Code), mh.Digest)
	if err != nil {
		return "", fmt.Errorf("failed to get commitment from reveal value (compute multihash): %s", err.Error())
	}

	return encoder.EncodeToString(multiHash), nil
}
