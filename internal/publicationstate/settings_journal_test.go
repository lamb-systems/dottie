package publicationstate

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func settingsJournalFixture(t *testing.T) (*Journal, [32]byte) {
	t.Helper()
	journal, _ := newJournal(t)
	var vault [32]byte
	vault[0] = 0x62
	return journal, vault
}

func settingsJournalIntent(vault [32]byte, written SettingsValue) SettingsJournalIntent {
	return SettingsJournalIntent{
		Vault: vault,
		Anchor: SettingsJournalAnchor{
			TargetID: "desktop", SchemaID: "org.gnome.desktop.interface",
			Path: "/org/gnome/desktop/interface/", Key: "color-scheme",
		},
		Prior:             SettingsValue{Present: true, Type: "s", Text: "'default'"},
		Written:           written,
		SeenFloorRevision: 1,
	}
}

func TestSettingsJournalRecordsAndCompletesAnIntent(t *testing.T) {
	ctx := context.Background()
	journal, vault := settingsJournalFixture(t)
	written := SettingsValue{Present: true, Type: "s", Text: "'prefer-dark'"}
	entry, err := journal.BeginSettingsJournal(ctx, settingsJournalIntent(vault, written))
	require.NoError(t, err)
	assert.Equal(t, JournalStatePending, entry.State)

	live, err := journal.LiveSettingsEntries(ctx)
	require.NoError(t, err)
	require.Len(t, live, 1)
	assert.Equal(t, entry.Anchor, live[0].Anchor)
	assert.Equal(t, written, live[0].Written)

	require.NoError(t, journal.CompleteSettingsJournal(ctx, entry, written))
	live, err = journal.LiveSettingsEntries(ctx)
	require.NoError(t, err)
	assert.Empty(t, live)
	require.NoError(t, journal.CheckSettingsAdmission(ctx, 1))
}

func TestSettingsJournalRefusesACompletionThatDoesNotMatchTheWrittenImage(t *testing.T) {
	ctx := context.Background()
	journal, vault := settingsJournalFixture(t)
	entry, err := journal.BeginSettingsJournal(
		ctx, settingsJournalIntent(vault, SettingsValue{Present: true, Type: "s", Text: "'prefer-dark'"}),
	)
	require.NoError(t, err)
	err = journal.CompleteSettingsJournal(ctx, entry, SettingsValue{Present: true, Type: "s", Text: "'other'"})
	require.Error(t, err)
	live, liveErr := journal.LiveSettingsEntries(ctx)
	require.NoError(t, liveErr)
	assert.Len(t, live, 1)
}

func TestSettingsJournalResolvesAnInterruptedIntentFromObservation(t *testing.T) {
	ctx := context.Background()
	journal, vault := settingsJournalFixture(t)
	written := SettingsValue{Present: true, Type: "s", Text: "'prefer-dark'"}
	_, err := journal.BeginSettingsJournal(ctx, settingsJournalIntent(vault, written))
	require.NoError(t, err)

	resolutions, err := journal.ResolveInterruptedSettings(
		ctx,
		func(SettingsJournalAnchor) (SettingsValue, error) { return written, nil },
	)
	require.NoError(t, err)
	require.Len(t, resolutions, 1)
	assert.Equal(t, JournalOutcomeApplied, resolutions[0].Outcome)

	resolutions, err = journal.ResolveInterruptedSettings(
		ctx,
		func(SettingsJournalAnchor) (SettingsValue, error) {
			return SettingsValue{}, errors.New("backend unavailable")
		},
	)
	require.NoError(t, err)
	assert.Empty(t, resolutions)
}

func TestSettingsJournalResolvesAPriorImageAsFailedAndAnythingElseAsIndeterminate(t *testing.T) {
	ctx := context.Background()
	journal, vault := settingsJournalFixture(t)
	intent := settingsJournalIntent(vault, SettingsValue{Present: true, Type: "s", Text: "'prefer-dark'"})

	_, err := journal.BeginSettingsJournal(ctx, intent)
	require.NoError(t, err)
	resolutions, err := journal.ResolveInterruptedSettings(
		ctx,
		func(SettingsJournalAnchor) (SettingsValue, error) { return intent.Prior, nil },
	)
	require.NoError(t, err)
	require.Len(t, resolutions, 1)
	assert.Equal(t, JournalOutcomeFailed, resolutions[0].Outcome)

	_, err = journal.BeginSettingsJournal(ctx, intent)
	require.NoError(t, err)
	resolutions, err = journal.ResolveInterruptedSettings(
		ctx,
		func(SettingsJournalAnchor) (SettingsValue, error) {
			return SettingsValue{Present: true, Type: "s", Text: "'third-party'"}, nil
		},
	)
	require.NoError(t, err)
	require.Len(t, resolutions, 1)
	assert.Equal(t, JournalOutcomeIndeterminate, resolutions[0].Outcome)

	err = journal.CheckSettingsAdmission(ctx, 1)
	var blocked *JournalBlockedError
	require.ErrorAs(t, err, &blocked)
}

func TestSettingsJournalBlocksAdmissionForALiveRow(t *testing.T) {
	ctx := context.Background()
	journal, vault := settingsJournalFixture(t)
	_, err := journal.BeginSettingsJournal(ctx, settingsJournalIntent(vault, SettingsValue{}))
	require.NoError(t, err)

	err = journal.CheckSettingsAdmission(ctx, 0)
	var blocked *JournalBlockedError
	require.ErrorAs(t, err, &blocked)
	assert.Equal(t, JournalStatePending, blocked.State)
}

func TestSettingsJournalRefusesAResetIntentThatCarriesAValue(t *testing.T) {
	ctx := context.Background()
	journal, vault := settingsJournalFixture(t)
	intent := settingsJournalIntent(vault, SettingsValue{Present: false, Type: "s", Text: "'value'"})
	_, err := journal.BeginSettingsJournal(ctx, intent)
	require.Error(t, err)
}

func TestLiveJournalRowsCountsSettingsIntents(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	journal, err := OpenJournal(directory)
	require.NoError(t, err)
	var vault [32]byte
	vault[0] = 0x62
	_, err = journal.BeginSettingsJournal(ctx, settingsJournalIntent(vault, SettingsValue{}))
	require.NoError(t, err)
	require.NoError(t, journal.Close())

	live, err := LiveJournalRows(directory)
	require.NoError(t, err)
	assert.Equal(t, int64(1), live)
}
