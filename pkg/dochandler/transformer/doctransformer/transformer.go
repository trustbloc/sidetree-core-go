/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package doctransformer

import (
	"github.com/trustbloc/sidetree-core-go/pkg/document"
)

// Transformer is responsible for transforming internal to external document
type Transformer struct {
}

// New creates a new document transformer
func New() *Transformer {
	return &Transformer{}
}

// TransformDocument takes internal representation of document and transforms it to required representation
func (v *Transformer) TransformDocument(internal document.Document) (*document.ResolutionResult, error) {
	resolutionResult := &document.ResolutionResult{
		Document:       internal,
		MethodMetadata: document.MethodMetadata{},
	}

	processKeys(internal)

	return resolutionResult, nil
}

// generic documents will most likely not contain keys
func processKeys(internal document.Document) {
	var pubKeysKeys []document.PublicKey

	for _, pk := range internal.PublicKeys() {
		relativeID := "#" + pk.ID()

		externalPK := make(document.PublicKey)
		externalPK[document.IDProperty] = internal.ID() + relativeID
		externalPK[document.TypeProperty] = pk.Type()
		externalPK[document.ControllerProperty] = internal[document.IDProperty]
		externalPK[document.PublicKeyJwkProperty] = pk.JWK()

		pubKeysKeys = append(pubKeysKeys, externalPK)
	}

	if len(pubKeysKeys) > 0 {
		internal[document.PublicKeyProperty] = pubKeysKeys
	} else {
		delete(internal, document.PublicKeyProperty)
	}
}
