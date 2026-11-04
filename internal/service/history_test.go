package service

import (
	"context"
	"errors"
	"testing"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type historyErrorRemote struct {
	err error
}

func (remote historyErrorRemote) Read(context.Context, atproto.ReadRequest) (atproto.ReadResult, error) {
	return atproto.ReadResult{}, remote.err
}

func TestCoordinatorHistoryLocalOnlyIsRedactedAndDoesNotReadRemote(t *testing.T) {
	fixture := newExportFixture(t)
	ctx := context.Background()
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	pushed, err := fixture.coordinator.Push(ctx, selection)
	require.NoError(t, err)
	require.Equal(t, StatusCommitted, pushed.Status)
	callsBefore := len(fixture.pds.Calls())

	report, err := fixture.coordinator.History(ctx, selection, false)
	require.NoError(t, err)
	assert.Equal(t, HistoryRemoteNotRequested, report.Remote.Status)
	assert.Equal(t, callsBefore, len(fixture.pds.Calls()))
	require.Len(t, report.Targets, 1)
	target := report.Targets[0]
	assert.Equal(t, "files", target.ID)
	assert.Equal(t, int64(1), target.AppliedBaseCount)
	assert.NotEmpty(t, target.AppliedBaseDigest)
	assert.NotContains(t, target.AppliedBaseDigest, "theme")
	assert.NotContains(t, target.ID, fixture.paths.Home)
	require.Len(t, report.Checkpoints, 1)
	assert.Equal(t, fixture.genesis.Vault, report.Checkpoints[0].Vault)
	assert.Equal(t, fixture.genesis.Anchor, report.Checkpoints[0].Anchor)
	assert.Equal(t, uint64(0), report.Checkpoints[0].Epoch)
}

func TestCoordinatorHistoryReportsRemoteUnavailableAndAuthExpired(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status HistoryRemoteStatus
	}{
		{name: "unavailable", err: errors.New("synthetic network outage"), status: HistoryRemoteUnavailable},
		{name: "auth expired", err: atproto.ErrAuthMethodSession, status: HistoryRemoteAuthExpired},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newExportFixture(t)
			selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
			fixture.coordinator.deps.Remote = historyErrorRemote{err: test.err}
			report, err := fixture.coordinator.History(context.Background(), selection, true)
			require.NoError(t, err)
			assert.Equal(t, test.status, report.Remote.Status)
			assert.Empty(t, report.Remote.HeadCID)
			assert.Zero(t, report.Remote.PublicationCount)
		})
	}
}

func TestCoordinatorHistoryReportsVerifiedRemoteSummary(t *testing.T) {
	fixture := newExportFixture(t)
	ctx := context.Background()
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	pushed, err := fixture.coordinator.Push(ctx, selection)
	require.NoError(t, err)
	require.Equal(t, StatusCommitted, pushed.Status)

	report, err := fixture.coordinator.History(ctx, selection, true)
	require.NoError(t, err)
	assert.Equal(t, HistoryRemoteVerified, report.Remote.Status)
	assert.Equal(t, pushed.PublicationCount, report.Remote.PublicationCount)
	assert.NotEmpty(t, report.Remote.HeadCID)
	assert.NotEqual(t, [32]byte{}, report.Remote.PolicyDigest)
	assert.Equal(t, atproto.FreshnessUnverified, report.Remote.Freshness)
	assert.Equal(t, "current", string(report.Remote.Currency))
	assert.NotContains(t, report.Remote.HeadCID, fixture.paths.Home)
	assert.NotContains(t, report.Remote.HeadCID, "theme")
}

func TestCoordinatorHistoryIncludesJournalStateWithoutIdentityPayload(t *testing.T) {
	fixture := newExportFixture(t)
	ctx := context.Background()
	identity := model.EntryKey{TargetID: "files", Source: model.SourceFiles, FilePath: "prefs.toml"}
	before, after := []byte("synthetic old bytes"), []byte("synthetic new bytes")
	_, err := fixture.store.AppendJournal(ctx, state.JournalEntry{
		ID: "history-row", Operation: "replace", State: "pending", Stage: state.JournalStagePending,
		Identity: identity, Preimage: state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", before),
		Postimage: state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", after), CreatedAt: 10,
	}, before)
	require.NoError(t, err)
	err = fixture.store.TransitionJournalEntry(ctx, "history-row", "pending", "applied", state.JournalStageVerified)
	require.NoError(t, err)

	report, err := fixture.coordinator.History(ctx, VaultSelection{}, false)
	require.NoError(t, err)
	require.Len(t, report.Targets, 1)
	assert.Equal(t, int64(1), report.Targets[0].JournalCount)
	assert.Equal(t, "applied", report.Targets[0].LatestJournalState)
	assert.Equal(t, state.JournalStageVerified, report.Targets[0].LatestJournalReason)
	assert.Equal(t, []state.JournalHistoryCount{{State: "applied", Stage: state.JournalStageVerified, Count: 1}}, report.Targets[0].JournalCounts)
	assert.NotContains(t, report.Targets[0].ID, fixture.paths.Home)
	assert.NotContains(t, report.Targets[0].AppliedBaseDigest, string(after))
}
