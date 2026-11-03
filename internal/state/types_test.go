package state

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSettingFingerprint(t *testing.T) {
	identity := model.EntryKey{TargetID: "settings", Source: model.SourceGNOME, SchemaID: "org.example.Settings", SettingsPath: "/", SettingKey: "enabled"}

	t.Run("present", func(t *testing.T) {
		payload := []byte("b\x00true")
		digest := sha256.Sum256(payload)
		fingerprint := NewSettingFingerprint(model.SettingPresent, "b", "true")
		assert.Equal(t, string(model.SettingPresent), fingerprint.State)
		assert.Equal(t, "b", fingerprint.ValueType)
		assert.Equal(t, "true", fingerprint.ValueText)
		assert.Equal(t, int64(len(payload)), fingerprint.Size)
		assert.Equal(t, hex.EncodeToString(digest[:]), fingerprint.Digest)
		assert.NoError(t, fingerprint.Validate(identity))
	})

	t.Run("reset", func(t *testing.T) {
		digest := sha256.Sum256(nil)
		fingerprint := NewSettingFingerprint(model.SettingReset, "ignored", "ignored")
		assert.Equal(t, string(model.SettingReset), fingerprint.State)
		assert.Empty(t, fingerprint.ValueType)
		assert.Empty(t, fingerprint.ValueText)
		assert.Zero(t, fingerprint.Size)
		assert.Equal(t, hex.EncodeToString(digest[:]), fingerprint.Digest)
		assert.NoError(t, fingerprint.Validate(identity))
	})

	invalid := NewSettingFingerprint(model.SettingState("invalid"), "", "")
	require.Error(t, invalid.Validate(identity))
}
