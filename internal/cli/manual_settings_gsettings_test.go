//go:build linux && cgo && gsettings

package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManualRecoverGSettingsBuildUsesSettingsBackend(t *testing.T) {
	source := manualGNOMESettings()
	require.NotNil(t, source)
	store, _, backend := manualRecoveryFixture(t)
	settings := &manualRecoverySettings{source: source, backend: backend}
	output := runManualRecoverForTest(t, store, settings)
	assert.Equal(t, 1, settings.backendRequests)
	assert.Equal(t, 1, backend.observations)
	assert.Contains(t, output, "failed")
}
