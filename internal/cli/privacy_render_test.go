package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/stretchr/testify/assert"
)

func TestPrivacyRenderersRespectPerSurfaceDisclosure(t *testing.T) {
	const targetID = "render-target-label-canary"
	const relativeFilePath = "prefs/private-profile-canary.toml"
	const settingLocator = "org.example.private@/org/example/private//private-key"
	const fileContent = "CONFIDENTIAL_FILE_CONTENT_CANARY_6a37b4f1"
	const settingValue = "CONFIDENTIAL_SETTING_VALUE_CANARY_42d901bc"

	homeRoot := "/dottie-canary/home-root"
	configRoot := "/dottie-canary/config-root"
	cacheRoot := "/dottie-canary/cache-root"
	dataRoot := "/dottie-canary/data-root"
	tempRoot := "/dottie-canary/temporary-root"
	signingPrivateBytes := bytes.Repeat([]byte{0x42}, 64)
	recipientPrivateBytes := bytes.Repeat([]byte{0x35}, 32)
	sessionToken := "eyJ.synthetic.session-token-canary.credential"
	forbiddenRepresentations := []string{fileContent, settingValue, homeRoot, configRoot, cacheRoot, dataRoot, tempRoot}
	for _, raw := range [][]byte{signingPrivateBytes, recipientPrivateBytes, []byte(sessionToken), []byte(fileContent), []byte(settingValue)} {
		forbiddenRepresentations = append(forbiddenRepresentations, string(raw), hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw), base64.RawStdEncoding.EncodeToString(raw), base64.URLEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(raw))
	}

	manualStatus := service.Status{Targets: []service.TargetStatus{{ID: targetID, Source: string(model.SourceFiles), Mode: config.Review, State: service.StatusApplied, Reason: "journal-applied", Items: 1}}}
	finalize := service.FinalizeResult{
		Checkpoint:         state.VaultCheckpoint{Vault: [32]byte{0x01}, Anchor: [32]byte{0x02}, Epoch: 1},
		CheckpointPosition: []byte(fileContent + "|" + settingValue + "|" + homeRoot),
	}

	table := []struct {
		name                string
		output              string
		requireTargetID     bool
		requireItemStatus   []string
		checkAbsoluteTokens bool
	}{
		{name: "push", output: renderPush(service.StatusCommitted), requireItemStatus: []string{"committed"}, checkAbsoluteTokens: true},
		{name: "pull-apply-report", output: renderPullApplyReport(service.PublicationApplyReport{Applied: 1, Unchanged: 2, BytesWritten: 3}), checkAbsoluteTokens: true},
		{name: "position-inspection", output: renderInspection(publicationstate.Inspection{Present: true, Floor: publicationstate.Floor{Revision: 1, Generation: 2, Sequence: 3}}), checkAbsoluteTokens: true},
		{name: "manual-status", output: renderManualStatus(manualStatus), requireTargetID: true, checkAbsoluteTokens: true},
		{name: "finalize", output: renderFinalizeResult(finalize), checkAbsoluteTokens: true},
	}

	for _, surface := range table {
		t.Run(surface.name, func(t *testing.T) {
			for _, forbidden := range forbiddenRepresentations {
				assert.NotContains(t, surface.output, forbidden, "surface %s exposed a confidential value, credential, or forbidden root", surface.name)
			}
			if surface.requireTargetID {
				assert.Contains(t, surface.output, targetID)
			}
			for _, status := range surface.requireItemStatus {
				assert.Contains(t, surface.output, status)
			}
			assert.NotContains(t, surface.output, relativeFilePath, "renderer %s exposed a relative entry path", surface.name)
			assert.NotContains(t, surface.output, settingLocator, "renderer %s exposed a setting locator", surface.name)
			if surface.checkAbsoluteTokens {
				for _, token := range strings.Fields(surface.output) {
					assert.False(t, strings.HasPrefix(token, "/"), "surface %s emitted an absolute token %q", surface.name, token)
				}
			}
		})
	}
}
