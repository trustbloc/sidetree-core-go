package patchvalidator

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/patch"
)

func TestAddServiceEndpointsPatch(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(addServiceEndpoints))
		require.NoError(t, err)

		err = NewAddServicesValidator().Validate(p)
		require.NoError(t, err)
	})
	t.Run("missing service endpoints", func(t *testing.T) {
		p, err := patch.FromBytes([]byte(addServiceEndpoints))
		require.NoError(t, err)

		delete(p, patch.ServicesKey)
		err = NewAddServicesValidator().Validate(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "add-services patch is missing key: services")
	})
	t.Run("error - service is missing id", func(t *testing.T) {
		p, err := patch.NewAddServiceEndpointsPatch(testAddServiceEndpointsMissingID)
		require.NoError(t, err)

		err = NewAddServicesValidator().Validate(p)
		require.Error(t, err)
		require.Contains(t, err.Error(), "service id is missing")
	})
}

const addServiceEndpoints = `{
  "action": "add-services",
  "services": [
    {
      "id": "sds1",
      "type": "SecureDataStore",
      "serviceEndpoint": "http://hub.my-personal-server.com"
    },
    {
      "id": "sds2",
      "type": "SecureDataStore",
      "serviceEndpoint": "http://some-cloud.com/hub"
    }
  ]
}`

const testAddServiceEndpointsMissingID = `[
    {
      "id": "",
      "type": "SecureDataStore",
      "serviceEndpoint": "http://some-cloud.com/hub"
    }
  ]`
