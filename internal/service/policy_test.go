package service

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type policySettings struct{}

func (policySettings) Resolve(_ context.Context, _, schemaID, _ string) (string, error) {
	if schemaID == "org.gnome.desktop.interface" {
		return "/org/gnome/desktop/interface/", nil
	}
	return "/org/gnome/desktop/calendar/", nil
}

func (policySettings) Capture(context.Context, string, []SettingRef) (SettingsCapture, error) {
	return SettingsCapture{}, nil
}

func (policySettings) Backend() syncengine.SettingsBackend { return nil }

func approvedGNOMETarget(t *testing.T) config.Target {
	t.Helper()
	categories := []string{"appearance"}
	keys, err := matrix.SelectCategories(categories)
	require.NoError(t, err)
	digest, err := matrix.KeySetDigest(keys)
	require.NoError(t, err)
	return config.Target{ID: "desktop", Source: model.SourceGNOME, GNOMEPolicy: &config.GNOMEPolicy{
		Approval: config.GNOMEApprovalApproved, Categories: categories, MatrixVersion: matrix.Version, KeyDigest: hex.EncodeToString(digest[:]),
	}}
}

func TestFilterSnapshotKeepsUnapprovedOrWrongPathGNOMEEntriesUntracked(t *testing.T) {
	target := approvedGNOMETarget(t)
	configuration := config.Config{Version: config.Version, Targets: []config.Target{target}}
	approved := model.Entry{TargetID: target.ID, Setting: &model.SettingEntry{
		SchemaID: "org.gnome.desktop.interface", Path: "/org/gnome/desktop/interface/", Key: "gtk-theme",
		State: model.SettingPresent, Value: &model.VariantValue{Type: "s", Text: "Adwaita"},
	}}
	unapproved := model.Entry{TargetID: target.ID, Setting: &model.SettingEntry{
		SchemaID: "org.gnome.desktop.interface", Path: "/org/gnome/desktop/interface/", Key: "unsafe-key",
		State: model.SettingPresent, Value: &model.VariantValue{Type: "s", Text: "sentinel"},
	}}
	wrongPath := approved
	wrongPath.Setting = &model.SettingEntry{
		SchemaID: approved.Setting.SchemaID, Path: "/wrong/path/", Key: approved.Setting.Key,
		State: model.SettingPresent, Value: &model.VariantValue{Type: "s", Text: "different"},
	}
	filtered, untracked, err := filterSnapshot(context.Background(), configuration, policySettings{}, model.Snapshot{
		Version: model.SnapshotVersion, Targets: []model.Target{{ID: target.ID, Source: model.SourceGNOME, SourceVersion: model.SourceVersion}},
		Entries: []model.Entry{approved, unapproved, wrongPath},
	})
	require.NoError(t, err)
	require.Len(t, filtered.Entries, 1)
	assert.Equal(t, approved.Identity(), filtered.Entries[0].Identity())
	require.Len(t, untracked, 2)
	assert.Contains(t, untracked, unapproved.Identity())
	assert.Contains(t, untracked, wrongPath.Identity())
}

func TestApprovedSettingsRefusesPendingMatrixDriftAndDigestDrift(t *testing.T) {
	target := approvedGNOMETarget(t)
	refs, err := approvedSettings(context.Background(), policySettings{}, target)
	require.NoError(t, err)
	assert.NotEmpty(t, refs)
	assert.Equal(t, "/org/gnome/desktop/interface/", refs[0].Path)

	pending := target
	pending.GNOMEPolicy = &config.GNOMEPolicy{Approval: config.GNOMEApprovalPending}
	_, err = approvedSettings(context.Background(), policySettings{}, pending)
	assert.ErrorIs(t, err, ErrGNOMEReapproval)

	matrixDrift := target
	policyCopy := *target.GNOMEPolicy
	policyCopy.MatrixVersion++
	matrixDrift.GNOMEPolicy = &policyCopy
	_, err = approvedSettings(context.Background(), policySettings{}, matrixDrift)
	assert.ErrorIs(t, err, ErrGNOMEReapproval)

	digestDrift := target
	policyCopy = *target.GNOMEPolicy
	policyCopy.KeyDigest = "0000000000000000000000000000000000000000000000000000000000000000"
	digestDrift.GNOMEPolicy = &policyCopy
	_, err = approvedSettings(context.Background(), policySettings{}, digestDrift)
	assert.ErrorIs(t, err, ErrGNOMEReapproval)
}

func TestCandidateDigestBindsSameSizeVerifiedRemoteContent(t *testing.T) {
	target := config.Target{ID: "files", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "prefs", Kind: model.SelectionDirectory}}
	portable, err := target.Model()
	require.NoError(t, err)
	remote := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: []model.Entry{{
		TargetID: target.ID, File: &model.FileEntry{Path: "settings.ini", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("aaaa"), Mode: 0o600},
	}}}
	preview := syncengine.Preview{Targets: []syncengine.PreviewTarget{{ID: target.ID}}}
	first, err := candidateDigest(remote, target, config.Review, syncengine.Plan{}, nil, preview)
	require.NoError(t, err)
	remote.Entries[0].File.Content = []byte("bbbb")
	second, err := candidateDigest(remote, target, config.Review, syncengine.Plan{}, nil, preview)
	require.NoError(t, err)
	assert.NotEqual(t, first, second)
	assert.Len(t, first, 64)
	assert.Len(t, second, 64)
}
