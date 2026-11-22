package zerotrust

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompileUserAndDevicePolicy(t *testing.T) {
	t.Parallel()

	compiled, err := CompileYAML(strings.NewReader(`
allow:
  and:
    - user:
        is: user-1
    - email:
        in:
          - alice@example.com
          - bob@example.com
    - domain:
        is: example.com
    - groups:
        has: admins
    - device:
        type: hardware-key
        approved: true
`))
	require.NoError(t, err)
	require.NotEmpty(t, compiled.Rego)
	assert.Contains(t, compiled.Rego, "package pomerium.policy")

	assert.Equal(t, UserRequirements{
		Required: true,
		UserIDs:  []string{"user-1"},
		Emails:   []string{"alice@example.com", "bob@example.com"},
		Domains:  []string{"example.com"},
		Groups:   []string{"admins"},
	}, compiled.UserRequirements)
	assert.Equal(t, DeviceRequirements{
		Required:         true,
		TypeIDs:          []string{"hardware-key"},
		RequiresApproval: true,
	}, compiled.DeviceRequirements)
}
