package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrivacyRenderersRespectPerSurfaceDisclosure(t *testing.T) {
	const targetID = "render-target-label-canary"
	const deviceID = "render-device-label-public"
	const relativeFilePath = "prefs/private-profile-canary.toml"
	const schemaID = "org.example.private"
	const settingsPath = "/org/example/private/"
	const settingKey = "private-key"
	const settingLocator = "org.example.private@/org/example/private//private-key"
	const fileContent = "CONFIDENTIAL_FILE_CONTENT_CANARY_6a37b4f1"
	const settingValue = "CONFIDENTIAL_SETTING_VALUE_CANARY_42d901bc"

	homeRoot := "/dottie-canary/home-root"
	configRoot := "/dottie-canary/config-root"
	cacheRoot := "/dottie-canary/cache-root"
	dataRoot := "/dottie-canary/data-root"
	tempRoot := "/dottie-canary/temporary-root"
	stateRoot := filepath.Join(t.TempDir(), "state")
	kitBytes := bytes.Repeat([]byte{0x71}, 32)
	signingPrivateBytes := bytes.Repeat([]byte{0x42}, 64)
	recipientPrivateBytes := bytes.Repeat([]byte{0x35}, 32)
	sessionToken := "eyJ.synthetic.session-token-canary.credential"
	kitHex := hex.EncodeToString(kitBytes)
	forbiddenRepresentations := []string{fileContent, settingValue, homeRoot, configRoot, cacheRoot, dataRoot, tempRoot}
	for _, raw := range [][]byte{kitBytes, signingPrivateBytes, recipientPrivateBytes, []byte(sessionToken), []byte(fileContent), []byte(settingValue)} {
		forbiddenRepresentations = append(forbiddenRepresentations, string(raw), hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw), base64.RawStdEncoding.EncodeToString(raw), base64.URLEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(raw))
	}

	fileEntry := model.Entry{TargetID: targetID, File: &model.FileEntry{Path: relativeFilePath, State: model.FilePresent, Kind: model.FileRegular, Content: []byte(fileContent), Mode: 0o600}}
	settingEntry := model.Entry{TargetID: targetID, Setting: &model.SettingEntry{
		SchemaID: schemaID, Path: settingsPath, Key: settingKey, State: model.SettingPresent,
		Value: &model.VariantValue{Type: "s", Text: settingValue},
	}}
	canaryPayload := strings.Join([]string{
		fileContent, settingValue, string(kitBytes), kitHex, string(signingPrivateBytes),
		string(recipientPrivateBytes), sessionToken, homeRoot, configRoot, cacheRoot, dataRoot, tempRoot,
	}, "|")
	readOutcome := service.ReadOutcome{
		Snapshot: model.Snapshot{Entries: []model.Entry{fileEntry, settingEntry}},
		Read: atproto.ReadResult{
			Plaintext: []byte(canaryPayload), Ciphertext: bytes.Clone(kitBytes),
			Policy: atproto.PolicyRecord{
				Roles:      []atproto.PolicyRoleRecord{{DeviceID: deviceID, Role: uint8(vault.RoleRoot)}},
				Recipients: []atproto.PolicyRecipientRecord{{DeviceID: deviceID, KeyID: []byte("recipient-key-id"), PublicKey: bytes.Repeat([]byte{0x19}, 32)}},
			},
			Control: atproto.ControlRecord{Revoked: []atproto.RevokedDeviceRecord{{DeviceID: "revoked-device-label", CertEpoch: 1}}},
		},
		Untracked: []model.EntryKey{fileEntry.Identity(), settingEntry.Identity()},
	}

	candidate := service.Candidate{
		Digest: "candidate-digest", TargetID: targetID,
		Preview: syncengine.Preview{Complete: true, Targets: []syncengine.PreviewTarget{{ID: targetID, Entries: []syncengine.PreviewEntry{
			{Key: fileEntry.Identity(), Action: syncengine.PreviewAction("download"), Reason: syncengine.PreviewReasonEqual, Size: int64(len(fileContent)), Detail: canaryPayload},
			{Key: settingEntry.Identity(), Action: syncengine.PreviewAction("download"), Reason: syncengine.PreviewReasonEqual, Size: int64(len(settingValue)), Detail: canaryPayload},
		}}}},
	}
	restore := service.RestoreReport{
		CandidateDigest: "candidate-digest",
		Items:           []service.RestoreItem{{Key: fileEntry.Identity(), Status: "file-applied"}, {Key: settingEntry.Identity(), Status: "setting-applied"}},
		Applied:         []syncengine.JournalResult{{FilePath: relativeFilePath, Reason: canaryPayload}},
	}

	retentionReferences := []string{
		filepath.Join(stateRoot, "payloads", "synthetic-payload-reference"),
		filepath.Join(stateRoot, "backups", "synthetic-backup-reference"),
	}
	retention := service.RetentionPruneResult{
		Status: service.RetentionPruneApplied,
		Plan: state.RetentionPrunePlan{Candidates: []state.RetentionPruneCandidate{
			{Kind: state.RetentionPruneCandidatePayload, Reference: retentionReferences[0], RecoveryPointEpochKnown: true, RecoveryPointEpochs: []uint64{1}, Eligible: true},
			{Kind: state.RetentionPruneCandidateBackup, Reference: retentionReferences[1], JournalID: "synthetic-backup", RecoveryPointEpochKnown: true, RecoveryPointEpochs: []uint64{1}, Eligible: true},
		}},
		Report: state.RetentionPruneReport{DeletedPayloads: []string{retentionReferences[0]}, PrunedBackupIDs: []string{"synthetic-backup"}},
	}
	administrative := service.AdministrativeResult{EncodedBundle: []byte(canaryPayload), Bundle: vault.OnboardingBundle{Checkpoint: []byte(canaryPayload)}}
	revokeTranscript := service.RevokeApprovalTranscript{
		DeviceID: deviceID, Role: vault.RolePublisher, SigningKeyFingerprint: [32]byte{0x10},
		RecipientKeyFingerprint: [32]byte{0x20}, KitSigningKeyFingerprint: [32]byte{0x30}, ApprovalFingerprint: [32]byte{0x40},
	}
	history := service.HistoryReport{Targets: []service.HistoryTargetSummary{{ID: targetID, JournalCount: 1, LatestJournalState: "applied", LatestJournalReason: "journal-applied"}}}
	exportReport := service.ExportReport{Current: service.ExportPositionReport{Epoch: 1, SnapshotCID: "bafysynthetic-snapshot", PublicationCount: 1}}
	recovery := syncengine.RecoveryReport{Entries: []syncengine.JournalResult{{
		JournalID: "synthetic-journal", Key: fileEntry.Identity(), TargetID: targetID, FilePath: relativeFilePath, Outcome: "recovered", Reason: "safe-recovery-state",
	}}}
	manualStatus := service.Status{Targets: []service.TargetStatus{{ID: targetID, Source: string(model.SourceFiles), Mode: config.Review, State: service.StatusApplied, Reason: "journal-applied", Items: 1}}}
	deviceRead := readOutcome

	table := []struct {
		name                 string
		output               string
		relativeLocators     []string
		requireTargetID      bool
		targetIDPolicy       string
		requireDeviceID      bool
		requireItemStatus    []string
		allowedStateRefs     []string
		isRetentionPruneView bool
		checkAbsoluteTokens  bool
	}{
		{name: "push", output: renderPush(service.StatusCommitted), targetIDPolicy: "not-rendered", requireItemStatus: []string{"committed"}, checkAbsoluteTokens: true},
		{name: "retention-prune", output: renderRetentionPrune(retention), targetIDPolicy: "not-rendered", allowedStateRefs: retentionReferences, isRetentionPruneView: true, checkAbsoluteTokens: true},
		{name: "devices", output: renderDevices(deviceRead), targetIDPolicy: "not-rendered", requireDeviceID: true, checkAbsoluteTokens: true},
		{name: "administrative", output: renderAdministrative("enroll", service.StatusCommitted, [32]byte{0x9a}, deviceID, vault.RolePublisher, [32]byte{0x40}, administrative), targetIDPolicy: "not-rendered", requireDeviceID: true, checkAbsoluteTokens: true},
		{name: "revoke-approval-transcript", output: renderRevokeApprovalTranscript(revokeTranscript), targetIDPolicy: "not-rendered", requireDeviceID: true, checkAbsoluteTokens: true},
		{name: "history", output: renderHistory(history), targetIDPolicy: "visible-local-target-summary", requireTargetID: true, checkAbsoluteTokens: true},
		{name: "export-report", output: renderExportReport(exportReport), targetIDPolicy: "not-rendered", checkAbsoluteTokens: true},
		{name: "candidate-consent", output: renderCandidate(candidate), relativeLocators: []string{relativeFilePath, settingLocator}, requireTargetID: true, targetIDPolicy: "each-preview-target"},
		{name: "restore-consent", output: renderRestore(restore), relativeLocators: []string{relativeFilePath, settingLocator}, targetIDPolicy: "single-target-fixed-by-invocation", requireItemStatus: []string{"file-applied", "setting-applied"}},
		{name: "pull", output: renderPull(readOutcome), targetIDPolicy: "not-rendered", checkAbsoluteTokens: true},
		{name: "manual-status", output: renderManualStatus(manualStatus), targetIDPolicy: "visible-local-target-summary", requireTargetID: true, checkAbsoluteTokens: true},
		{name: "recovery", output: renderRecovery(recovery), targetIDPolicy: "not-rendered", checkAbsoluteTokens: true},
	}

	for _, surface := range table {
		t.Run(surface.name, func(t *testing.T) {
			assert.NotEmpty(t, surface.targetIDPolicy)
			for _, forbidden := range forbiddenRepresentations {
				assert.NotContains(t, surface.output, forbidden, "surface %s exposed a confidential value, credential, or forbidden root", surface.name)
			}
			if surface.requireTargetID {
				assert.Contains(t, surface.output, targetID)
			}
			if surface.requireDeviceID {
				assert.Contains(t, surface.output, deviceID)
			}
			for _, status := range surface.requireItemStatus {
				assert.Contains(t, surface.output, status)
			}
			if len(surface.relativeLocators) != 0 {
				for _, locator := range surface.relativeLocators {
					assert.Contains(t, strings.Fields(surface.output), locator, "consent surface %s did not show the exact relative locator", surface.name)
				}
			} else {
				assert.NotContains(t, surface.output, relativeFilePath, "routine renderer %s exposed a relative entry path", surface.name)
				assert.NotContains(t, surface.output, settingLocator, "routine renderer %s exposed a setting locator", surface.name)
			}
			if surface.checkAbsoluteTokens {
				allowedAbsoluteTokens := make(map[string]bool, len(surface.allowedStateRefs))
				for _, reference := range surface.allowedStateRefs {
					allowedAbsoluteTokens[reference] = true
				}
				for _, token := range strings.Fields(surface.output) {
					if strings.HasPrefix(token, "/") {
						assert.True(t, allowedAbsoluteTokens[token], "surface %s emitted an unapproved absolute token %q", surface.name, token)
					}
				}
			}
			if surface.isRetentionPruneView {
				for _, reference := range surface.allowedStateRefs {
					assert.Contains(t, surface.output, reference)
					assert.Contains(t, strings.Fields(surface.output), reference, "retention reference must be the exact allowed absolute token")
					relative, err := filepath.Rel(stateRoot, reference)
					require.NoError(t, err)
					assert.False(t, relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)), "retention reference escaped state directory")
				}
			}
		})
	}
}
