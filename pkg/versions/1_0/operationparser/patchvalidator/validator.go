package patchvalidator

import (
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

// Validate validates patch.
func Validate(p patch.Patch) error {
	action, err := p.GetAction()
	if err != nil {
		return err
	}

	switch action {
	case patch.Replace:
		return NewReplaceValidator().Validate(p)
	case patch.JSONPatch:
		return NewJSONValidator().Validate(p)
	case patch.AddPublicKeys:
		return NewAddPublicKeysValidator().Validate(p)
	case patch.RemovePublicKeys:
		return NewRemovePublicKeysValidator().Validate(p)
	case patch.AddServiceEndpoints:
		return NewAddServicesValidator().Validate(p)
	case patch.RemoveServiceEndpoints:
		return NewRemoveServicesValidator().Validate(p)
	case patch.AddAlsoKnownAs, patch.RemoveAlsoKnownAs:
		return NewAlsoKnownAsValidator().Validate(p)
	}

	return fmt.Errorf(" validation for action '%s' is not supported", action)
}
