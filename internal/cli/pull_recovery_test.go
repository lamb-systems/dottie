package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/service"
)

func interruptedApplyRow(
	t *testing.T,
	directory string,
	content, disk string,
) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "interrupted")
	require.NoError(t, os.Mkdir(root, 0o700))
	destination := filepath.Join(root, "note.ini")
	require.NoError(t, os.WriteFile(destination, []byte(disk), 0o600))
	info, err := os.Lstat(root)
	require.NoError(t, err)
	anchor, ok := publicationstate.NewJournalAnchor(root, info)
	require.True(t, ok)

	require.NoError(t, os.MkdirAll(directory, 0o700))
	require.NoError(t, os.Chmod(directory, 0o700))
	journal, err := publicationstate.OpenJournal(directory)
	require.NoError(t, err)
	preimage := publicationstate.ObservedJournalFile([]byte("before"))
	preimage.Mode = 0o600
	postimage := publicationstate.ObservedJournalFile([]byte(content))
	postimage.Mode = 0o600
	_, err = journal.BeginJournal(context.Background(), publicationstate.JournalIntent{
		Vault: [32]byte{0x62}, Operation: "apply",
		DestinationDir: root, DestinationPath: "note.ini",
		Anchor: anchor, Preimage: &preimage, PreimageBytes: []byte("before"), Postimage: postimage,
	})
	require.NoError(t, err)
	require.NoError(t, journal.Close())
	return root
}

func matchingLocalPublication(t *testing.T, fixture *pullTestFixture) {
	t.Helper()
	require.NoError(t, os.WriteFile(
		fixture.targetPath("init.lua"), []byte(pullTestBaseContent), 0o600,
	))
}

func TestPullAcceptanceOnlyRefusesToAdvanceOverAnIndeterminateApply(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.configure(t, config.Review)
	matchingLocalPublication(t, fixture)
	interruptedApplyRow(t, fixture.paths.PublicationStateDir(), "done", "third")
	reader := &pullTestReader{view: fixture.view(), payloads: fixture.payloads()}

	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	require.Contains(t, stdout.String(), "acceptance only")
	token := pullTestConfirmation(t, stdout.String())

	stdout.Reset()
	stderr.Reset()
	code = 0
	command = newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(
		command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token,
	)
	assert.Equal(t, 4, code, stderr.String())
	assert.Contains(t, stderr.String(), "unresolved")

	inspection, err := publicationstate.Inspect(
		context.Background(), fixture.paths.PublicationStateDir(), fixture.binding,
	)
	require.NoError(t, err)
	assert.False(t, inspection.Present, "the floor advanced over an unresolved apply")
	live, err := publicationstate.LiveJournalRows(fixture.paths.PublicationStateDir())
	require.NoError(t, err)
	assert.Equal(t, int64(1), live, "the unresolved journal row was retired")
}

func TestPullAcceptanceOnlySettlesAnApplyOutsideTheConfiguredTargets(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.configure(t, config.Review)
	matchingLocalPublication(t, fixture)
	root := interruptedApplyRow(t, fixture.paths.PublicationStateDir(), "done", "done")
	require.NotEqual(
		t, filepath.Join(fixture.paths.Home, "config"), root,
		"the interrupted apply was written inside the configured target",
	)
	reader := &pullTestReader{view: fixture.view(), payloads: fixture.payloads()}

	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	require.Contains(t, stdout.String(), "acceptance only")
	token := pullTestConfirmation(t, stdout.String())

	stdout.Reset()
	stderr.Reset()
	code = 0
	command = newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(
		command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token,
	)
	require.Equal(t, 0, code, stderr.String())

	inspection, err := publicationstate.Inspect(
		context.Background(), fixture.paths.PublicationStateDir(), fixture.binding,
	)
	require.NoError(t, err)
	assert.True(t, inspection.Present, "the settled apply did not let the floor advance")
	live, err := publicationstate.LiveJournalRows(fixture.paths.PublicationStateDir())
	require.NoError(t, err)
	assert.Zero(t, live, "the settled apply left a live journal row")
}

func TestPullWithoutAConfiguredTargetRefusesToIgnoreALiveApply(t *testing.T) {
	fixture := newPullTestFixture(t)
	interruptedApplyRow(t, fixture.paths.PublicationStateDir(), "done", "done")
	reader := &pullTestReader{view: fixture.view(), payloads: fixture.payloads()}

	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	assert.Equal(t, 3, code, stderr.String())
	assert.Contains(t, stderr.String(), "interrupted apply")

	inspection, err := publicationstate.Inspect(
		context.Background(), fixture.paths.PublicationStateDir(), fixture.binding,
	)
	require.NoError(t, err)
	assert.False(t, inspection.Present, "a pull without a configured target advanced the floor")
	live, err := publicationstate.LiveJournalRows(fixture.paths.PublicationStateDir())
	require.NoError(t, err)
	assert.Equal(t, int64(1), live, "a pull without a configured target discarded a live row")
}

func TestPullWithAnExistingFloorAndNoConfiguredTargetReportsALiveApply(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.configure(t, config.Review)
	reader := &pullTestReader{view: fixture.view(), payloads: fixture.payloads()}

	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	token := pullTestConfirmation(t, stdout.String())
	stdout.Reset()
	stderr.Reset()
	code = 0
	command = newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(
		command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token,
	)
	require.Equal(t, 0, code, stderr.String())

	snapshot, err := service.FileConfigPort{Paths: fixture.paths}.Snapshot(t.Context())
	require.NoError(t, err)
	_, err = service.FileConfigPort{Paths: fixture.paths}.Update(
		t.Context(), snapshot.Token,
		func(current config.Config) (config.Config, error) {
			current.Targets = nil
			return current, nil
		},
	)
	require.NoError(t, err)
	interruptedApplyRow(t, fixture.paths.PublicationStateDir(), "done", "done")

	stdout.Reset()
	stderr.Reset()
	code = 0
	command = newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	assert.Equal(t, 4, code, stderr.String())
	assert.Contains(t, stderr.String(), "interrupted apply")

	live, liveErr := publicationstate.LiveJournalRows(fixture.paths.PublicationStateDir())
	require.NoError(t, liveErr)
	assert.Equal(t, int64(1), live, "the live row was discarded")
}
