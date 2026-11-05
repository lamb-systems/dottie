//go:build linux && cgo && gsettings

package local_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/source/gnome"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	manualVaultDID   = "did:plc:abcdefghijklmnopqrstuvwx"
	manualSchemaID   = "org.gnome.desktop.interface"
	manualSchemaPath = "/org/gnome/desktop/interface/"
)

type manualRepository struct {
	vault     [32]byte
	anchor    [32]byte
	root      vault.DeviceMaterial
	genesis   vault.Genesis
	published vault.Publication
	revision  atprototest.SignedRevision
	blobs     map[string][]byte
	records   []atprototest.Record
	repoKey   *atcrypto.PrivateKeyP256
}

type manualTransport struct {
	revision atprototest.SignedRevision
	blobs    map[string][]byte
}

type manualCapturingRemote struct {
	delegate service.RemoteReadPort
	result   atproto.ReadResult
}

type manualReplayRemote struct {
	result atproto.ReadResult
}

type manualFixedTrustSource struct {
	material service.TrustMaterial
}

type manualKeyring struct {
	device vault.DeviceMaterial
}

type manualSession struct {
	method atproto.VerificationMethod
	did    string
}

type manualSettings struct{}

type manualFailApplyFileSystem struct {
	delegate files.ApplyFileSystem
	failAt   int
	writes   int
}

type manualFailApplyRoot struct {
	files.ApplyRoot
	filesystem *manualFailApplyFileSystem
}

func (filesystem *manualFailApplyFileSystem) Lstat(path string) (os.FileInfo, error) {
	return filesystem.delegate.Lstat(path)
}

func (filesystem *manualFailApplyFileSystem) OpenRoot(path string) (files.ApplyRoot, error) {
	root, err := filesystem.delegate.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &manualFailApplyRoot{ApplyRoot: root, filesystem: filesystem}, nil
}

func (root *manualFailApplyRoot) OpenFile(path string, flags int, mode os.FileMode) (files.ApplyFile, error) {
	if flags&os.O_WRONLY != 0 {
		root.filesystem.writes++
		if root.filesystem.writes == root.filesystem.failAt {
			return nil, errors.New("synthetic second file apply failure")
		}
	}
	return root.ApplyRoot.OpenFile(path, flags, mode)
}

func TestManualRestoreCoordinatorGate(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	configHome := filepath.Join(root, "config")
	stateHome := filepath.Join(root, "state")
	dataHome := filepath.Join(root, "data")
	schemaDir := filepath.Join(dataHome, "glib-2.0", "schemas")
	for _, path := range []string{home, configHome, stateHome, dataHome, schemaDir, filepath.Join(root, "cache"), filepath.Join(root, "runtime")} {
		require.NoError(t, os.MkdirAll(path, 0o700))
	}
	require.NoError(t, os.Chmod(filepath.Join(root, "runtime"), 0o700))
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("XDG_STATE_HOME", stateHome)
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "cache"))
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(root, "runtime"))
	t.Setenv("GSETTINGS_SCHEMA_DIR", schemaDir)
	t.Setenv("GSETTINGS_BACKEND", "keyfile")
	compileManualSchema(t, schemaDir)

	paths, err := platform.Resolve(os.Getenv)
	require.NoError(t, err)
	destination := filepath.Join(home, "preferences")
	require.NoError(t, os.MkdirAll(destination, 0o700))
	sourceFile := filepath.Join(root, "synthetic-source", "settings.ini")
	require.NoError(t, os.MkdirAll(filepath.Dir(sourceFile), 0o700))
	sourceBytes := []byte("source-side synthetic bytes\n")
	require.NoError(t, os.WriteFile(sourceFile, sourceBytes, 0o640))

	fileTarget := config.Target{ID: "files", Source: model.SourceFiles, Mode: config.Review,
		Root: &config.Root{Base: model.RootHome, Path: "preferences", Kind: model.SelectionDirectory}}
	categoryKeys, err := matrix.SelectCategories([]string{"appearance"})
	require.NoError(t, err)
	keyDigest, err := matrix.KeySetDigest(categoryKeys)
	require.NoError(t, err)
	settingsTarget := config.Target{ID: "desktop", Source: model.SourceGNOME, Mode: config.Review,
		GNOMEPolicy: &config.GNOMEPolicy{Approval: config.GNOMEApprovalApproved, Categories: []string{"appearance"}, MatrixVersion: matrix.Version, KeyDigest: fmt.Sprintf("%x", keyDigest[:])}}
	portableFileTarget, err := fileTarget.Model()
	require.NoError(t, err)
	portableSettingsTarget, err := settingsTarget.Model()
	require.NoError(t, err)
	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portableFileTarget, portableSettingsTarget}, Entries: []model.Entry{
		{TargetID: fileTarget.ID, File: &model.FileEntry{Path: "settings.ini", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("remote preference bytes\n"), Mode: 0o640}},
		{TargetID: settingsTarget.ID, Setting: &model.SettingEntry{SchemaID: manualSchemaID, Path: manualSchemaPath, Key: "gtk-theme", State: model.SettingPresent, Value: &model.VariantValue{Type: "s", Text: "'Synthetic-Theme'"}}},
		{TargetID: settingsTarget.ID, Setting: &model.SettingEntry{SchemaID: manualSchemaID, Path: manualSchemaPath, Key: "icon-theme", State: model.SettingReset}},
		{TargetID: settingsTarget.ID, Setting: &model.SettingEntry{SchemaID: manualSchemaID, Path: manualSchemaPath, Key: "cursor-theme", State: model.SettingReset}},
		{TargetID: settingsTarget.ID, Setting: &model.SettingEntry{SchemaID: manualSchemaID, Path: manualSchemaPath, Key: "color-scheme", State: model.SettingReset}},
		{TargetID: settingsTarget.ID, Setting: &model.SettingEntry{SchemaID: manualSchemaID, Path: manualSchemaPath, Key: "accent-color", State: model.SettingReset}},
	}}
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)

	repository := buildManualRepository(t, packed.Payload)
	sourceRevision := bytes.Clone(repository.revision.CAR)
	sourceSnapshot := bytes.Clone(repository.published.Snapshot)
	store, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	configuration := config.Default()
	configuration.Targets = []config.Target{fileTarget, settingsTarget}
	require.NoError(t, config.Save(paths, configuration))
	require.NoError(t, store.PutVaultSelection(context.Background(), state.VaultSelection{Vault: repository.vault, DeviceID: repository.root.DeviceID, RecordedAt: time.Now().Unix()}))
	checkpoint, err := vault.DecodeCheckpoint(repository.genesis.Checkpoint)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(context.Background(), state.VaultCheckpoint{
		Vault: repository.vault, Anchor: repository.anchor, ControlCID: bytes.Clone(repository.genesis.ControlCID),
		ControlBytes: bytes.Clone(repository.genesis.Control), SnapshotCID: bytes.Clone(checkpoint.SnapshotCID), Epoch: 0,
		PolicyDigest: repository.genesis.PolicyDigest, RecordedAt: time.Now().Unix(),
	}))
	require.NoError(t, store.PutAuthenticatedPositionEvidence(context.Background(), state.AuthenticatedPositionEvidence{
		Vault: repository.vault, Epoch: 0, PolicyDigest: repository.genesis.PolicyDigest,
		Policy: bytes.Clone(repository.genesis.Policy), Control: bytes.Clone(repository.genesis.Control),
		Head:         bytes.Clone(repository.genesis.Head),
		Certificates: [][]byte{bytes.Clone(repository.genesis.Certificate)}, CheckpointPosition: bytes.Clone(repository.genesis.Checkpoint),
	}))

	seedManualDestinationSettings(t)
	transport := &manualTransport{revision: repository.revision, blobs: repository.blobs}
	coordinator, err := service.NewCoordinator(service.Dependencies{
		Config: service.FileConfigPort{Paths: paths}, State: store, Settings: manualSettings{},
		Trust: service.StateTrustSource{State: store, Keyring: manualKeyring{device: repository.root}},
		Session: manualSession{did: manualVaultDID, method: atproto.VerificationMethod{
			ID: repository.revision.VerificationMethod.ID, Type: repository.revision.VerificationMethod.Type,
			Controller: repository.revision.VerificationMethod.Controller, PublicKeyMultibase: repository.revision.VerificationMethod.PublicKeyMultibase,
		}},
		Remote: service.VaultReader{Reader: atproto.VaultReader{Transport: transport, ObservationStore: store}},
		Paths:  paths,
	})
	require.NoError(t, err)

	beforeSettings := readManualSettings(t)
	require.NoError(t, store.PutTarget(context.Background(), state.TargetDescriptor{ID: fileTarget.ID, Version: 1, Source: model.SourceFiles, SourceVersion: model.SourceVersion, LogicalBase: model.RootHome, LogicalPath: "preferences", Kind: model.SelectionDirectory, Mode: string(config.Review), CreatedAt: 1}))
	require.NoError(t, store.PutTarget(context.Background(), state.TargetDescriptor{ID: settingsTarget.ID, Version: 1, Source: model.SourceGNOME, SourceVersion: model.SourceVersion, Mode: string(config.Review), CreatedAt: 1}))
	require.NoError(t, coordinator.RecordBase(context.Background(), settingsTarget.ID, []model.Entry{
		{TargetID: settingsTarget.ID, Setting: &model.SettingEntry{SchemaID: manualSchemaID, Path: manualSchemaPath, Key: "gtk-theme", State: model.SettingPresent, Value: &model.VariantValue{Type: "s", Text: "'Local-Theme'"}}},
		{TargetID: settingsTarget.ID, Setting: &model.SettingEntry{SchemaID: manualSchemaID, Path: manualSchemaPath, Key: "icon-theme", State: model.SettingPresent, Value: &model.VariantValue{Type: "s", Text: "'Local-Icons'"}}},
	}))
	beforeSource, err := os.ReadFile(sourceFile)
	require.NoError(t, err)
	fileCandidate, err := coordinator.Preview(context.Background(), service.VaultSelection{Vault: repository.vault}, fileTarget.ID)
	require.NoError(t, err)
	require.True(t, fileCandidate.Preview.Complete)
	assert.Equal(t, vault.CheckpointCurrent, fileCandidate.Currency)
	assert.False(t, fileCandidate.InspectOnly)
	require.Equal(t, []string{"settings.ini"}, manualActionNames(fileCandidate.Actions))
	initialJournal, err := store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	assert.Empty(t, initialJournal)
	fileBases, err := store.AppliedBase(context.Background(), fileTarget.ID)
	require.NoError(t, err)
	assert.Empty(t, fileBases)
	settingsBases, err := store.AppliedBase(context.Background(), settingsTarget.ID)
	require.NoError(t, err)
	require.Len(t, settingsBases, 2)
	_, err = coordinator.Restore(context.Background(), service.RestoreRequest{Selection: service.VaultSelection{Vault: repository.vault}, TargetID: fileTarget.ID})
	require.ErrorIs(t, err, service.ErrCandidateChanged)
	_, err = coordinator.Restore(context.Background(), service.RestoreRequest{Selection: service.VaultSelection{Vault: repository.vault}, TargetID: fileTarget.ID, Confirm: "wrong-candidate-digest"})
	require.ErrorIs(t, err, service.ErrCandidateChanged)
	_, err = coordinator.UpdateConfig(context.Background(), func(current config.Config) (config.Config, error) {
		for index := range current.Targets {
			if current.Targets[index].ID == fileTarget.ID {
				current.Targets[index].Mode = config.BackupOnly
			}
		}
		return current, nil
	})
	require.NoError(t, err)
	_, err = coordinator.Restore(context.Background(), service.RestoreRequest{Selection: service.VaultSelection{Vault: repository.vault}, TargetID: fileTarget.ID, Confirm: fileCandidate.Digest})
	require.ErrorIs(t, err, service.ErrApplyNotPermitted)
	_, err = coordinator.UpdateConfig(context.Background(), func(current config.Config) (config.Config, error) {
		for index := range current.Targets {
			if current.Targets[index].ID == fileTarget.ID {
				current.Targets[index].Mode = config.Review
			}
		}
		return current, nil
	})
	require.NoError(t, err)
	for _, missingRoot := range []string{"missing-selection", filepath.Join("missing-parent", "preferences")} {
		_, err = coordinator.UpdateConfig(context.Background(), func(current config.Config) (config.Config, error) {
			for index := range current.Targets {
				if current.Targets[index].ID == fileTarget.ID {
					current.Targets[index].Root.Path = missingRoot
				}
			}
			return current, nil
		})
		require.NoError(t, err)
		candidate, previewErr := coordinator.Preview(context.Background(), service.VaultSelection{Vault: repository.vault}, fileTarget.ID)
		if previewErr == nil {
			assert.False(t, candidate.Preview.Complete)
		}
		_, restoreErr := coordinator.Restore(context.Background(), service.RestoreRequest{Selection: service.VaultSelection{Vault: repository.vault}, TargetID: fileTarget.ID, Confirm: fileCandidate.Digest})
		assert.Error(t, restoreErr)
		_, err = coordinator.UpdateConfig(context.Background(), func(current config.Config) (config.Config, error) {
			for index := range current.Targets {
				if current.Targets[index].ID == fileTarget.ID {
					current.Targets[index].Root.Path = "preferences"
				}
			}
			return current, nil
		})
		require.NoError(t, err)
	}
	_, err = coordinator.UpdateConfig(context.Background(), func(current config.Config) (config.Config, error) {
		for index := range current.Targets {
			if current.Targets[index].ID == settingsTarget.ID {
				current.Targets[index].GNOMEPolicy = &config.GNOMEPolicy{Approval: config.GNOMEApprovalPending}
			}
		}
		return current, nil
	})
	require.NoError(t, err)
	_, err = coordinator.Preview(context.Background(), service.VaultSelection{Vault: repository.vault}, settingsTarget.ID)
	require.ErrorIs(t, err, service.ErrGNOMEReapproval)
	_, err = coordinator.UpdateConfig(context.Background(), func(current config.Config) (config.Config, error) {
		for index := range current.Targets {
			if current.Targets[index].ID == settingsTarget.ID {
				current.Targets[index].GNOMEPolicy = settingsTarget.GNOMEPolicy
			}
		}
		return current, nil
	})
	require.NoError(t, err)
	_, err = coordinator.UpdateConfig(context.Background(), func(current config.Config) (config.Config, error) {
		for index := range current.Targets {
			if current.Targets[index].ID == settingsTarget.ID {
				copy := *current.Targets[index].GNOMEPolicy
				copy.MatrixVersion++
				current.Targets[index].GNOMEPolicy = &copy
			}
		}
		return current, nil
	})
	require.NoError(t, err)
	_, err = coordinator.Preview(context.Background(), service.VaultSelection{Vault: repository.vault}, settingsTarget.ID)
	require.ErrorIs(t, err, service.ErrGNOMEReapproval)
	_, err = coordinator.UpdateConfig(context.Background(), func(current config.Config) (config.Config, error) {
		for index := range current.Targets {
			if current.Targets[index].ID == settingsTarget.ID {
				current.Targets[index].GNOMEPolicy = settingsTarget.GNOMEPolicy
			}
		}
		return current, nil
	})
	require.NoError(t, err)
	assert.NoFileExists(t, filepath.Join(destination, "settings.ini"))
	assert.Equal(t, beforeSettings, readManualSettings(t))
	stillJournal, err := store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	assert.Empty(t, stillJournal)
	stillFileBases, err := store.AppliedBase(context.Background(), fileTarget.ID)
	require.NoError(t, err)
	assert.Empty(t, stillFileBases)
	stillSettingsBases, err := store.AppliedBase(context.Background(), settingsTarget.ID)
	require.NoError(t, err)
	assert.Equal(t, settingsBases, stillSettingsBases)
	settingsCandidate, err := coordinator.Preview(context.Background(), service.VaultSelection{Vault: repository.vault}, settingsTarget.ID)
	require.NoError(t, err)
	require.True(t, settingsCandidate.Preview.Complete, "%+v actions=%+v untracked=%+v", settingsCandidate.Preview, settingsCandidate.Actions, settingsCandidate.Untracked)
	assert.Equal(t, atproto.FreshnessUnverified, settingsCandidate.Freshness)
	assert.Equal(t, vault.CheckpointCurrent, settingsCandidate.Currency)
	assert.Contains(t, manualActionKeys(settingsCandidate.Actions), "gtk-theme")
	assert.Contains(t, manualActionKeys(settingsCandidate.Actions), "icon-theme")

	fileReport, err := coordinator.Restore(context.Background(), service.RestoreRequest{Selection: service.VaultSelection{Vault: repository.vault}, TargetID: fileTarget.ID, Confirm: fileCandidate.Digest})
	require.NoError(t, err)
	assert.Len(t, fileReport.Applied, 1)
	settingsReport, err := coordinator.Restore(context.Background(), service.RestoreRequest{Selection: service.VaultSelection{Vault: repository.vault}, TargetID: settingsTarget.ID, Confirm: settingsCandidate.Digest})
	require.NoError(t, err)
	assert.Len(t, settingsReport.Applied, 2)
	appliedFile, err := os.ReadFile(filepath.Join(destination, "settings.ini"))
	require.NoError(t, err)
	assert.Equal(t, []byte("remote preference bytes\n"), appliedFile)
	fileInfo, err := os.Stat(filepath.Join(destination, "settings.ini"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), fileInfo.Mode().Perm())
	afterSettings := readManualSettings(t)
	assert.Equal(t, "'Synthetic-Theme'", afterSettings["gtk-theme"].Text)
	assert.False(t, afterSettings["icon-theme"].Present)
	assert.Equal(t, "'Local-Theme'", beforeSettings["gtk-theme"].Text)
	assert.Equal(t, "'Local-Icons'", beforeSettings["icon-theme"].Text)
	assert.Equal(t, sourceBytes, beforeSource)
	assert.Equal(t, sourceBytes, mustManualRead(t, sourceFile))

	journal, err := store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	require.Len(t, journal, 3)
	journalSources := map[model.SourceKind]int{}
	for _, entry := range journal {
		assert.Equal(t, "applied", entry.State)
		journalSources[entry.Identity.Source]++
	}
	assert.Equal(t, map[model.SourceKind]int{model.SourceFiles: 1, model.SourceGNOME: 2}, journalSources)
	fileBase, err := store.AppliedBase(context.Background(), fileTarget.ID)
	require.NoError(t, err)
	settingsBase, err := store.AppliedBase(context.Background(), settingsTarget.ID)
	require.NoError(t, err)
	assert.Len(t, fileBase, 1)
	assert.Len(t, settingsBase, 2)
	statuses, err := coordinator.Status(context.Background())
	require.NoError(t, err)
	require.Len(t, statuses.Targets, 2)
	assert.Equal(t, service.TargetStatus{ID: "desktop", Source: string(model.SourceGNOME), Mode: config.Review, State: service.StatusApplied, Reason: "journal-applied", Items: 2}, statuses.Targets[0])
	assert.Equal(t, service.TargetStatus{ID: "files", Source: string(model.SourceFiles), Mode: config.Review, State: service.StatusApplied, Reason: "journal-applied", Items: 1}, statuses.Targets[1])

	for _, targetID := range []string{fileTarget.ID, settingsTarget.ID} {
		candidate, previewErr := coordinator.Preview(context.Background(), service.VaultSelection{Vault: repository.vault}, targetID)
		require.NoError(t, previewErr)
		assert.True(t, candidate.Preview.Complete)
		assert.Empty(t, candidate.Actions)
		report, restoreErr := coordinator.Restore(context.Background(), service.RestoreRequest{Selection: service.VaultSelection{Vault: repository.vault}, TargetID: targetID, Confirm: candidate.Digest})
		require.NoError(t, restoreErr)
		assert.True(t, report.NoActions)
	}
	journalAfter, err := store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	assert.Len(t, journalAfter, 3)
	fileBaseAfter, err := store.AppliedBase(context.Background(), fileTarget.ID)
	require.NoError(t, err)
	settingsBaseAfter, err := store.AppliedBase(context.Background(), settingsTarget.ID)
	require.NoError(t, err)
	assert.Len(t, fileBaseAfter, 1)
	assert.Len(t, settingsBaseAfter, 2)

	changedSnapshot, err := vault.UnpackWithLimits(packed, vault.DefaultLimits())
	require.NoError(t, err)
	changedContent := []byte("remote preference other\n")
	require.Len(t, changedContent, len("remote preference bytes\n"))
	for index := range changedSnapshot.Entries {
		if changedSnapshot.Entries[index].File != nil {
			changedSnapshot.Entries[index].File.Content = changedContent
		}
	}
	changedPacked, err := vault.Pack(changedSnapshot)
	require.NoError(t, err)
	advanced := advanceManualRepository(t, repository, changedPacked.Payload)
	transport.revision = advanced.revision
	transport.blobs = advanced.blobs
	readOutcome, err := coordinator.Pull(context.Background(), service.VaultSelection{Vault: repository.vault})
	require.NoError(t, err)
	var verifiedChanged []byte
	for _, entry := range readOutcome.Snapshot.Entries {
		if entry.File != nil && entry.TargetID == fileTarget.ID {
			verifiedChanged = entry.File.Content
		}
	}
	assert.Equal(t, changedContent, verifiedChanged)
	changedCandidate, err := coordinator.Preview(context.Background(), service.VaultSelection{Vault: repository.vault}, fileTarget.ID)
	require.NoError(t, err)
	assert.NotEqual(t, fileCandidate.Digest, changedCandidate.Digest)
	_, err = coordinator.Restore(context.Background(), service.RestoreRequest{Selection: service.VaultSelection{Vault: repository.vault}, TargetID: fileTarget.ID, Confirm: fileCandidate.Digest})
	require.ErrorIs(t, err, service.ErrCandidateChanged)
	assert.Equal(t, []byte("remote preference bytes\n"), mustManualRead(t, filepath.Join(destination, "settings.ini")))
	lastJournal, err := store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	assert.Len(t, lastJournal, 3)
	lastFileBase, err := store.AppliedBase(context.Background(), fileTarget.ID)
	require.NoError(t, err)
	assert.Len(t, lastFileBase, 1)
	lastSettingsBase, err := store.AppliedBase(context.Background(), settingsTarget.ID)
	require.NoError(t, err)
	assert.Len(t, lastSettingsBase, 2)

	partialSnapshot := changedSnapshot
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		partialSnapshot.Entries = append(partialSnapshot.Entries, model.Entry{TargetID: fileTarget.ID, File: &model.FileEntry{
			Path: name, State: model.FilePresent, Kind: model.FileRegular, Content: []byte("remote " + name + "\n"), Mode: 0o640,
		}})
	}
	partialPacked, err := vault.Pack(partialSnapshot)
	require.NoError(t, err)
	partialRepository := advanceManualRepository(t, advanced, partialPacked.Payload)
	transport.revision = partialRepository.revision
	transport.blobs = partialRepository.blobs
	failureFS := &manualFailApplyFileSystem{delegate: files.DefaultApplyFileSystem(), failAt: 2}
	partialCoordinator, err := service.NewCoordinator(service.Dependencies{
		Config: service.FileConfigPort{Paths: paths}, State: store, Settings: manualSettings{},
		Trust: service.StateTrustSource{State: store, Keyring: manualKeyring{device: repository.root}},
		Session: manualSession{did: manualVaultDID, method: atproto.VerificationMethod{
			ID: repository.revision.VerificationMethod.ID, Type: repository.revision.VerificationMethod.Type,
			Controller: repository.revision.VerificationMethod.Controller, PublicKeyMultibase: repository.revision.VerificationMethod.PublicKeyMultibase,
		}},
		Remote: service.VaultReader{Reader: atproto.VaultReader{Transport: transport, ObservationStore: store}}, Paths: paths, Filesystem: failureFS,
	})
	require.NoError(t, err)
	partialCandidate, err := partialCoordinator.Preview(context.Background(), service.VaultSelection{Vault: repository.vault}, fileTarget.ID)
	require.NoError(t, err)
	require.True(t, partialCandidate.Preview.Complete, "%+v", partialCandidate.Preview)
	assert.Equal(t, []string{"a.txt", "b.txt", "c.txt", "settings.ini"}, manualActionNames(partialCandidate.Actions))
	partialReport, err := partialCoordinator.Restore(context.Background(), service.RestoreRequest{Selection: service.VaultSelection{Vault: repository.vault}, TargetID: fileTarget.ID, Confirm: partialCandidate.Digest})
	require.Error(t, err)
	var partialErr *syncengine.PartialApplyError
	require.ErrorAs(t, err, &partialErr)
	require.Len(t, partialReport.Applied, 1)
	assert.Equal(t, "a.txt", partialReport.Applied[0].Key.FilePath)
	require.NotNil(t, partialReport.Failed)
	assert.Equal(t, "b.txt", partialReport.Failed.Key.FilePath)
	untouched := make([]string, 0, len(partialReport.Untouched))
	for _, entry := range partialReport.Untouched {
		untouched = append(untouched, entry.Key.FilePath)
	}
	assert.Equal(t, []string{"c.txt", "settings.ini"}, untouched)
	assert.Equal(t, []byte("remote a.txt\n"), mustManualRead(t, filepath.Join(destination, "a.txt")))
	assert.NoFileExists(t, filepath.Join(destination, "b.txt"))
	assert.NoFileExists(t, filepath.Join(destination, "c.txt"))

	raw, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: filepath.Join(paths.AppStateDir(), "state.db")}).String())
	require.NoError(t, err)
	raw.SetMaxOpenConns(1)
	_, err = raw.Exec(`CREATE TRIGGER reject_manual_file_base BEFORE INSERT ON applied_base WHEN NEW.target_id = 'files' AND NEW.file_path = 'b.txt' BEGIN SELECT RAISE(FAIL, 'injected base failure'); END`)
	require.NoError(t, err)
	baseFailCoordinator, err := service.NewCoordinator(service.Dependencies{
		Config: service.FileConfigPort{Paths: paths}, State: store, Settings: manualSettings{},
		Trust: service.StateTrustSource{State: store, Keyring: manualKeyring{device: repository.root}},
		Session: manualSession{did: manualVaultDID, method: atproto.VerificationMethod{
			ID: repository.revision.VerificationMethod.ID, Type: repository.revision.VerificationMethod.Type,
			Controller: repository.revision.VerificationMethod.Controller, PublicKeyMultibase: repository.revision.VerificationMethod.PublicKeyMultibase,
		}},
		Remote: service.VaultReader{Reader: atproto.VaultReader{Transport: transport, ObservationStore: store}}, Paths: paths,
	})
	require.NoError(t, err)
	baseFailCandidate, err := baseFailCoordinator.Preview(context.Background(), service.VaultSelection{Vault: repository.vault}, fileTarget.ID)
	require.NoError(t, err)
	baseFailReport, err := baseFailCoordinator.Restore(context.Background(), service.RestoreRequest{Selection: service.VaultSelection{Vault: repository.vault}, TargetID: fileTarget.ID, Confirm: baseFailCandidate.Digest})
	require.ErrorIs(t, err, service.ErrBaseRecordingFailed)
	assert.True(t, baseFailReport.BaseRecordingFailed)
	assert.NotEmpty(t, baseFailReport.Applied)
	_, dropErr := raw.Exec("DROP TRIGGER reject_manual_file_base")
	assert.NoError(t, dropErr)
	assert.NoError(t, raw.Close())
	baseAfterFailure, err := store.AppliedBase(context.Background(), fileTarget.ID)
	require.NoError(t, err)
	for _, base := range baseAfterFailure {
		assert.NotEqual(t, "b.txt", base.Identity.FilePath)
	}
	assert.Equal(t, sourceRevision, repository.revision.CAR)
	assert.Equal(t, sourceSnapshot, repository.published.Snapshot)
	assert.Equal(t, sourceBytes, mustManualRead(t, sourceFile))
}

func TestManualRestoreRefusesStaleCheckpointRelation(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	configHome := filepath.Join(root, "config")
	stateHome := filepath.Join(root, "state")
	cacheHome := filepath.Join(root, "cache")
	for _, path := range []string{home, configHome, stateHome, cacheHome} {
		require.NoError(t, os.MkdirAll(path, 0o700))
	}
	paths := platform.Paths{Home: home, ConfigHome: configHome, StateHome: stateHome, CacheHome: cacheHome}
	destination := filepath.Join(home, "preferences")
	require.NoError(t, os.MkdirAll(destination, 0o700))
	target := config.Target{ID: "files", Source: model.SourceFiles, Mode: config.Review,
		Root: &config.Root{Base: model.RootHome, Path: "preferences", Kind: model.SelectionDirectory}}
	portableTarget, err := target.Model()
	require.NoError(t, err)
	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portableTarget}, Entries: []model.Entry{
		{TargetID: target.ID, File: &model.FileEntry{Path: "settings.ini", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("remote preference bytes\n"), Mode: 0o640}},
	}}
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	repository := buildManualRepository(t, packed.Payload)
	store, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	require.NoError(t, config.Save(paths, configuration))
	require.NoError(t, store.PutVaultSelection(context.Background(), state.VaultSelection{Vault: repository.vault, DeviceID: repository.root.DeviceID, RecordedAt: 1}))
	checkpoint, err := vault.DecodeCheckpoint(repository.genesis.Checkpoint)
	require.NoError(t, err)
	require.NoError(t, store.PutVaultCheckpoint(context.Background(), state.VaultCheckpoint{
		Vault: repository.vault, Anchor: repository.anchor, ControlCID: bytes.Clone(repository.genesis.ControlCID),
		ControlBytes: bytes.Clone(repository.genesis.Control), SnapshotCID: bytes.Clone(checkpoint.SnapshotCID), Epoch: 0,
		PolicyDigest: repository.genesis.PolicyDigest, RecordedAt: 1,
	}))
	require.NoError(t, store.PutAuthenticatedPositionEvidence(context.Background(), state.AuthenticatedPositionEvidence{
		Vault: repository.vault, Epoch: 0, PolicyDigest: repository.genesis.PolicyDigest,
		Policy: bytes.Clone(repository.genesis.Policy), Control: bytes.Clone(repository.genesis.Control),
		Head:         bytes.Clone(repository.genesis.Head),
		Certificates: [][]byte{bytes.Clone(repository.genesis.Certificate)}, CheckpointPosition: bytes.Clone(repository.genesis.Checkpoint),
	}))
	require.NoError(t, store.PutTarget(context.Background(), state.TargetDescriptor{
		ID: target.ID, Version: 1, Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		LogicalBase: model.RootHome, LogicalPath: "preferences", Kind: model.SelectionDirectory, Mode: string(config.Review), CreatedAt: 1,
	}))
	transport := &manualTransport{revision: repository.revision, blobs: repository.blobs}
	remote := &manualCapturingRemote{delegate: service.VaultReader{Reader: atproto.VaultReader{Transport: transport, ObservationStore: store}}}
	coordinator, err := service.NewCoordinator(service.Dependencies{
		Config: service.FileConfigPort{Paths: paths}, State: store,
		Trust: service.StateTrustSource{State: store, Keyring: manualKeyring{device: repository.root}},
		Session: manualSession{did: manualVaultDID, method: atproto.VerificationMethod{
			ID: repository.revision.VerificationMethod.ID, Type: repository.revision.VerificationMethod.Type,
			Controller: repository.revision.VerificationMethod.Controller, PublicKeyMultibase: repository.revision.VerificationMethod.PublicKeyMultibase,
		}},
		Remote: remote, Paths: paths,
	})
	require.NoError(t, err)
	selection := service.VaultSelection{Vault: repository.vault}
	currentCandidate, err := coordinator.Preview(context.Background(), selection, target.ID)
	require.NoError(t, err)
	assert.Equal(t, vault.CheckpointCurrent, currentCandidate.Currency)
	assert.False(t, currentCandidate.InspectOnly)
	assert.True(t, currentCandidate.Preview.Complete)
	require.NotNil(t, remote.result.Revision)
	beforeJournal, err := store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	beforeBases, err := store.AppliedBase(context.Background(), target.ID)
	require.NoError(t, err)

	staleCoordinator, err := service.NewCoordinator(service.Dependencies{
		Config: service.FileConfigPort{Paths: paths}, State: store,
		Trust: manualFixedTrustSource{material: manualSuccessorTrust(t, repository)},
		Session: manualSession{did: manualVaultDID, method: atproto.VerificationMethod{
			ID: repository.revision.VerificationMethod.ID, Type: repository.revision.VerificationMethod.Type,
			Controller: repository.revision.VerificationMethod.Controller, PublicKeyMultibase: repository.revision.VerificationMethod.PublicKeyMultibase,
		}},
		Remote: manualReplayRemote{result: remote.result}, Paths: paths,
	})
	require.NoError(t, err)
	staleCandidate, err := staleCoordinator.Preview(context.Background(), selection, target.ID)
	require.NoError(t, err)
	assert.Equal(t, vault.CheckpointStale, staleCandidate.Currency)
	assert.True(t, staleCandidate.InspectOnly)
	assert.True(t, staleCandidate.Preview.Complete)
	_, err = staleCoordinator.Restore(context.Background(), service.RestoreRequest{Selection: selection, TargetID: target.ID, Confirm: staleCandidate.Digest})
	require.ErrorIs(t, err, service.ErrFreshnessUnverified)
	assert.Equal(t, service.ErrFreshnessUnverified.Error(), err.Error())
	_, err = os.Lstat(filepath.Join(destination, "settings.ini"))
	assert.ErrorIs(t, err, os.ErrNotExist)
	afterStaleJournal, err := store.JournalEntriesAll(context.Background())
	require.NoError(t, err)
	assert.Equal(t, beforeJournal, afterStaleJournal)
	afterStaleBases, err := store.AppliedBase(context.Background(), target.ID)
	require.NoError(t, err)
	assert.Equal(t, beforeBases, afterStaleBases)

	report, err := coordinator.Restore(context.Background(), service.RestoreRequest{Selection: selection, TargetID: target.ID, Confirm: currentCandidate.Digest})
	require.NoError(t, err)
	require.Len(t, report.Applied, 1)
	assert.Equal(t, []byte("remote preference bytes\n"), mustManualRead(t, filepath.Join(destination, "settings.ini")))
}

func buildManualRepository(t *testing.T, plaintext []byte) manualRepository {
	t.Helper()
	kit := bytes.Repeat([]byte{0x17}, 32)
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	root := vault.DeviceMaterial{DeviceID: "manual-root", KeyID: []byte("manual-root-key"), Signing: signing, Recipient: recipient}
	ephemeral, err := ecdh.X25519().GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x2a}, 64)))
	require.NoError(t, err)
	genesis, err := vault.ComposeGenesis(vault.GenesisIntent{
		Kit: kit, VaultName: "manual sync synthetic fixture", RootDevice: root,
		ContentKey:    bytes.Repeat([]byte{0x31}, 32),
		Wraps:         []vault.RecipientWrapInput{{KeyID: bytes.Clone(root.KeyID), EphemeralPrivate: [32]byte(ephemeral.Bytes()), WrapNonce: [24]byte(bytes.Repeat([]byte{0x41}, 24))}},
		PublicationID: [16]byte(bytes.Repeat([]byte{0x51}, 16)), Nonce: [24]byte(bytes.Repeat([]byte{0x61}, 24)),
	})
	require.NoError(t, err)
	genesisCheckpoint, err := vault.DecodeCheckpoint(genesis.Checkpoint)
	require.NoError(t, err)
	predecessor := vault.Predecessor{
		ControlCID: bytes.Clone(genesis.ControlCID), PolicyDigest: genesis.PolicyDigest, EpochSeq: 0,
		HeadCID: bytes.Clone(genesisCheckpoint.SnapshotCID), Head: bytes.Clone(genesis.Head),
		Control: bytes.Clone(genesis.Control), Policy: bytes.Clone(genesis.Policy),
		Certificates: [][]byte{bytes.Clone(genesis.Certificate)}, TrustAnchor: genesis.Anchor,
	}
	publicationEphemeral, err := ecdh.X25519().GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x2b}, 64)))
	require.NoError(t, err)
	publication, err := vault.PreparePublication(predecessor, vault.PublicationIntent{
		Vault: genesis.Vault, Signer: root, ContentKey: bytes.Repeat([]byte{0x32}, 32),
		Wraps:     []vault.RecipientWrapInput{{KeyID: bytes.Clone(root.KeyID), EphemeralPrivate: [32]byte(publicationEphemeral.Bytes()), WrapNonce: [24]byte(bytes.Repeat([]byte{0x42}, 24))}},
		Plaintext: bytes.Clone(plaintext), PublicationID: [16]byte(bytes.Repeat([]byte{0x52}, 16)), Nonce: [24]byte(bytes.Repeat([]byte{0x62}, 24)),
	})
	require.NoError(t, err)
	repositoryKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	records := []atprototest.Record{
		manualVaultRecord(t, atproto.VaultPolicyNSID, "self", manualPolicyRecord(t, genesis.Policy)),
		manualVaultRecord(t, atproto.VaultControlNSID, "self", manualControlRecord(t, genesis.Control)),
		manualVaultRecord(t, atproto.VaultHeadNSID, "self", manualHeadRecord(t, publication.Head)),
		manualVaultRecord(t, atproto.VaultCheckpointNSID, "self", manualCheckpointRecord(t, genesis.Checkpoint)),
		manualVaultRecord(t, atproto.VaultCertificateNSID, "root-cert", manualCertificateRecord(t, genesis.Certificate)),
		manualVaultRecord(t, atproto.VaultSnapshotNSID, "genesis", manualSnapshotRecord(t, genesis.Snapshot, root.Signing)),
		manualVaultRecord(t, atproto.VaultSnapshotNSID, "published", manualSnapshotRecord(t, publication.Snapshot, root.Signing)),
	}
	revision, err := atprototest.BuildSignedRevision(manualVaultDID, repositoryKey, records)
	require.NoError(t, err)
	blobs := map[string][]byte{
		cid.NewCidV1(cid.Raw, mustManualMultihash(t, genesis.Snapshot)).String():     bytes.Clone(genesis.Snapshot),
		cid.NewCidV1(cid.Raw, mustManualMultihash(t, publication.Snapshot)).String(): bytes.Clone(publication.Snapshot),
	}
	return manualRepository{vault: genesis.Vault, anchor: genesis.Anchor, root: root, genesis: genesis, published: publication, revision: revision, blobs: blobs, records: records, repoKey: repositoryKey}
}

func advanceManualRepository(t *testing.T, repository manualRepository, plaintext []byte) manualRepository {
	t.Helper()
	ephemeral, err := ecdh.X25519().GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x2c}, 64)))
	require.NoError(t, err)
	predecessor := vault.Predecessor{
		ControlCID: bytes.Clone(repository.genesis.ControlCID), PolicyDigest: repository.genesis.PolicyDigest, EpochSeq: 0,
		HeadCID: bytes.Clone(repository.published.SnapshotCID), Head: bytes.Clone(repository.published.Head),
		Control: bytes.Clone(repository.genesis.Control), Policy: bytes.Clone(repository.genesis.Policy),
		Certificates: [][]byte{bytes.Clone(repository.genesis.Certificate)}, TrustAnchor: repository.anchor,
	}
	publication, err := vault.PreparePublication(predecessor, vault.PublicationIntent{
		Vault: repository.vault, Signer: repository.root, ContentKey: bytes.Repeat([]byte{0x34}, 32),
		Wraps:     []vault.RecipientWrapInput{{KeyID: bytes.Clone(repository.root.KeyID), EphemeralPrivate: [32]byte(ephemeral.Bytes()), WrapNonce: [24]byte(bytes.Repeat([]byte{0x44}, 24))}},
		Plaintext: bytes.Clone(plaintext), PublicationID: [16]byte(bytes.Repeat([]byte{0x54}, 16)), Nonce: [24]byte(bytes.Repeat([]byte{0x64}, 24)),
	})
	require.NoError(t, err)
	records := make([]atprototest.Record, 0, len(repository.records)+1)
	for _, record := range repository.records {
		if record.Collection == atproto.VaultHeadNSID && record.RKey == "self" {
			continue
		}
		records = append(records, record)
	}
	nextHead, err := vault.DecodeHead(publication.Head)
	require.NoError(t, err)
	records = append(records,
		manualVaultRecord(t, atproto.VaultHeadNSID, "self", manualHeadRecord(t, publication.Head)),
		manualVaultRecord(t, atproto.VaultSnapshotNSID, fmt.Sprintf("published-%d", nextHead.PublicationCount), manualSnapshotRecord(t, publication.Snapshot, repository.root.Signing)),
	)
	revision, err := atprototest.BuildSignedRevision(manualVaultDID, repository.repoKey, records)
	require.NoError(t, err)
	blobs := make(map[string][]byte, len(repository.blobs)+1)
	for key, value := range repository.blobs {
		blobs[key] = bytes.Clone(value)
	}
	blobs[cid.NewCidV1(cid.Raw, mustManualMultihash(t, publication.Snapshot)).String()] = bytes.Clone(publication.Snapshot)
	repository.published = publication
	repository.revision = revision
	repository.blobs = blobs
	repository.records = records
	return repository
}

func manualVaultRecord(t *testing.T, collection, rkey string, record atproto.Record) atprototest.Record {
	t.Helper()
	encoded, err := atproto.EncodeRecord(record)
	require.NoError(t, err)
	return atprototest.Record{Collection: collection, RKey: rkey, Data: encoded}
}

func manualPolicyRecord(t *testing.T, encoded []byte) atproto.PolicyRecord {
	t.Helper()
	policy, err := vault.DecodePolicy(encoded)
	require.NoError(t, err)
	record := atproto.PolicyRecord{
		SchemaVersion: 1, Vault: bytes.Clone(policy.Vault[:]), EpochSeq: policy.EpochSeq,
		PolicyRetentionFloor: policy.PolicyRetentionFloor, RetainedRecoveryPoints: policy.RetainedRecoveryPoints,
		MaxPublications: policy.MaxPublications, MaxEpochAge: policy.MaxEpochAge,
		RecoveryAnchor: bytes.Clone(policy.RecoveryAnchor[:]), PrevPolicyDigest: bytes.Clone(policy.PrevPolicyDigest[:]),
		SignerDeviceID: policy.Signer.DeviceID, SignerKeyID: bytes.Clone(policy.Signer.KeyID), Signature: bytes.Clone(policy.Signature[:]),
	}
	for _, role := range policy.Roles {
		record.Roles = append(record.Roles, atproto.PolicyRoleRecord{DeviceID: role.DeviceID, Role: uint8(role.Role)})
	}
	for _, recipient := range policy.Recipients {
		record.Recipients = append(record.Recipients, atproto.PolicyRecipientRecord{DeviceID: recipient.DeviceID, KeyID: bytes.Clone(recipient.KeyID), PublicKey: bytes.Clone(recipient.PublicKey[:])})
	}
	return record
}

func manualControlRecord(t *testing.T, encoded []byte) atproto.ControlRecord {
	t.Helper()
	control, err := vault.DecodeControl(encoded)
	require.NoError(t, err)
	record := atproto.ControlRecord{
		SchemaVersion: 1, Vault: bytes.Clone(control.Vault[:]), EpochSeq: control.EpochSeq,
		PolicyDigest: bytes.Clone(control.PolicyDigest[:]), HeadSnapshotCID: bytes.Clone(control.HeadSnapshotCID),
		PrevControlCID: bytes.Clone(control.PrevControlCID), SignerDeviceID: control.Signer.DeviceID,
		SignerKeyID: bytes.Clone(control.Signer.KeyID), Signature: bytes.Clone(control.Signature[:]),
	}
	for _, revoked := range control.Revoked {
		record.Revoked = append(record.Revoked, atproto.RevokedDeviceRecord{DeviceID: revoked.DeviceID, CertEpoch: revoked.CertEpoch})
	}
	return record
}

func manualHeadRecord(t *testing.T, encoded []byte) atproto.HeadRecord {
	t.Helper()
	head, err := vault.DecodeHead(encoded)
	require.NoError(t, err)
	return atproto.HeadRecord{
		SchemaVersion: 1, Vault: bytes.Clone(head.Vault[:]), EpochSeq: head.EpochSeq,
		PolicyDigest: bytes.Clone(head.PolicyDigest[:]), SnapshotCID: bytes.Clone(head.SnapshotCID),
		BlobCID: bytes.Clone(head.BlobCID), PublicationCount: head.PublicationCount, PrevHeadCID: bytes.Clone(head.PrevHeadCID),
		SignerDeviceID: head.Signer.DeviceID, SignerKeyID: bytes.Clone(head.Signer.KeyID), Signature: bytes.Clone(head.Signature[:]),
	}
}

func manualCheckpointRecord(t *testing.T, encoded []byte) atproto.CheckpointRecord {
	t.Helper()
	checkpoint, err := vault.DecodeCheckpoint(encoded)
	require.NoError(t, err)
	return atproto.CheckpointRecord{
		SchemaVersion: 1, Vault: bytes.Clone(checkpoint.Vault[:]), SnapshotCID: bytes.Clone(checkpoint.SnapshotCID),
		EpochSeq: checkpoint.EpochSeq, PolicyDigest: bytes.Clone(checkpoint.PolicyDigest[:]),
		Anchor: bytes.Clone(checkpoint.Anchor[:]), ControlCID: bytes.Clone(checkpoint.ControlCID),
		SignerDeviceID: checkpoint.Signer.DeviceID, SignerKeyID: bytes.Clone(checkpoint.Signer.KeyID), Signature: bytes.Clone(checkpoint.Signature[:]),
	}
}

func manualCertificateRecord(t *testing.T, encoded []byte) atproto.CertificateRecord {
	t.Helper()
	certificate, err := vault.DecodeCertificate(encoded)
	require.NoError(t, err)
	return atproto.CertificateRecord{
		SchemaVersion: 1, Vault: bytes.Clone(certificate.Vault[:]), DeviceID: certificate.DeviceID,
		KeyID: bytes.Clone(certificate.KeyID), SigningPublicKey: bytes.Clone(certificate.SigningPublicKey[:]),
		EncryptionPublicKey: bytes.Clone(certificate.EncryptionPublicKey[:]), Role: uint8(certificate.Role),
		CertEpoch: certificate.CertEpoch, Issuer: certificate.Issuer, RevocationRef: bytes.Clone(certificate.RevocationRef),
		SignerDeviceID: certificate.Signer.DeviceID, SignerKeyID: bytes.Clone(certificate.Signer.KeyID),
		Signature: bytes.Clone(certificate.Signature[:]),
	}
}

func manualSnapshotRecord(t *testing.T, encoded []byte, signer []byte) atproto.SnapshotRecord {
	t.Helper()
	envelope, err := vault.DecodeEnvelope(encoded)
	require.NoError(t, err)
	blobCID := cid.NewCidV1(cid.Raw, mustManualMultihash(t, encoded))
	blob := atdata.Blob{Ref: atdata.CIDLink(blobCID), MimeType: "application/octet-stream", Size: int64(len(encoded))}
	digest := sha256.Sum256(envelope.Signature[:])
	record, err := atproto.SignSnapshotRecord(atproto.SnapshotRecord{
		SchemaVersion: 1, Vault: bytes.Clone(envelope.Vault[:]), PublicationID: bytes.Clone(envelope.PublicationID[:]),
		EpochSeq: envelope.EpochSeq, PolicyDigest: bytes.Clone(envelope.PolicyDigest[:]), Parent: bytes.Clone(envelope.Parent),
		Blob: blob, SignerDeviceID: envelope.DeviceID, SignerKeyID: bytes.Clone(envelope.KeyID),
		EnvelopeSignatureDigest: bytes.Clone(digest[:]), Signature: make([]byte, ed25519.SignatureSize),
	}, signer)
	require.NoError(t, err)
	return record
}

func mustManualMultihash(t *testing.T, encoded []byte) []byte {
	t.Helper()
	identifier, err := cid.Prefix{Version: 1, Codec: cid.Raw, MhType: 0x12, MhLength: 32}.Sum(encoded)
	require.NoError(t, err)
	return identifier.Hash()
}

func compileManualSchema(t *testing.T, directory string) {
	t.Helper()
	schema := `<schemalist><schema id="org.gnome.desktop.interface" path="/org/gnome/desktop/interface/">` +
		`<key name="gtk-theme" type="s"><default>'Default-Theme'</default></key>` +
		`<key name="icon-theme" type="s"><default>'Default-Icons'</default></key>` +
		`<key name="cursor-theme" type="s"><default>'Default-Cursor'</default></key>` +
		`<key name="color-scheme" type="s"><default>'default'</default></key>` +
		`<key name="accent-color" type="s"><default>'blue'</default></key></schema></schemalist>`
	file := filepath.Join(directory, "org.gnome.desktop.interface.gschema.xml")
	require.NoError(t, os.WriteFile(file, []byte(schema), 0o600))
	command := exec.Command("glib-compile-schemas", directory)
	output, err := command.CombinedOutput()
	require.NoError(t, err, string(output))
}

func seedManualDestinationSettings(t *testing.T) {
	t.Helper()
	settings, err := gnome.OpenDefault(manualSchemaID, manualSchemaPath)
	require.NoError(t, err)
	require.NoError(t, settings.Set("gtk-theme", "s", "'Local-Theme'"))
	require.NoError(t, settings.Set("icon-theme", "s", "'Local-Icons'"))
	require.NoError(t, settings.Sync())
	require.NoError(t, settings.Close())
}

func readManualSettings(t *testing.T) map[string]gnome.UserValue {
	t.Helper()
	settings, err := gnome.OpenDefault(manualSchemaID, manualSchemaPath)
	require.NoError(t, err)
	defer func() { assert.NoError(t, settings.Close()) }()
	values := make(map[string]gnome.UserValue)
	for _, key := range []string{"gtk-theme", "icon-theme"} {
		value, readErr := settings.ReadUser(key)
		require.NoError(t, readErr)
		values[key] = value
	}
	return values
}

func (keyring manualKeyring) LoadDeviceKeys(_ context.Context, vaultID [32]byte, deviceID string) (vault.DeviceMaterial, error) {
	if vaultID == ([32]byte{}) || deviceID != keyring.device.DeviceID {
		return vault.DeviceMaterial{}, errors.New("synthetic fixture key is unavailable")
	}
	return keyring.device, nil
}

func (manualSettings) Resolve(_ context.Context, _, schemaID, path string) (string, error) {
	if schemaID != manualSchemaID {
		return "", gnome.ErrSchemaNotFound
	}
	if path == "" {
		path = manualSchemaPath
	}
	settings, err := gnome.OpenDefault(schemaID, path)
	if err != nil {
		return "", err
	}
	defer settings.Close()
	return settings.Path(), nil
}

func (manualSettings) Capture(ctx context.Context, targetID string, refs []service.SettingRef) (service.SettingsCapture, error) {
	keys := make([]matrix.KeyRef, 0, len(refs))
	for _, ref := range refs {
		keys = append(keys, matrix.KeyRef{SchemaID: ref.SchemaID, Path: ref.Path, Key: ref.Key})
	}
	captured, err := gnome.Capture(ctx, gnome.CaptureRequest{TargetID: targetID, Keys: keys})
	if err != nil {
		return service.SettingsCapture{}, err
	}
	result := service.SettingsCapture{Entries: captured.Entries}
	for _, key := range captured.Unknown {
		result.Unknown = append(result.Unknown, model.EntryKey{TargetID: targetID, Source: model.SourceGNOME, SchemaID: key.SchemaID, SettingsPath: key.Path, SettingKey: key.Key})
	}
	return result, nil
}

func (manualSettings) Backend() syncengine.SettingsBackend {
	backend, err := gnome.NewSettingsBackend()
	if err != nil {
		return nil
	}
	return backend
}

func (transport manualTransport) Do(_ context.Context, method, endpoint string, _ url.Values, _ []byte, _ string) (int, []byte, error) {
	if method != "GET" || endpoint != "com.atproto.sync.getLatestCommit" {
		return 404, []byte(`{"error":"NotFound"}`), nil
	}
	body, err := json.Marshal(map[string]string{"cid": transport.revision.CommitCID.String(), "rev": atprototest.RepositoryRevision})
	return 200, body, err
}

func (transport manualTransport) OpenStream(_ context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	switch endpoint {
	case "com.atproto.sync.getRepo":
		return 200, io.NopCloser(bytes.NewReader(bytes.Clone(transport.revision.CAR))), nil
	case "com.atproto.sync.getBlob":
		data, ok := transport.blobs[query.Get("cid")]
		if !ok {
			return 404, nil, nil
		}
		return 200, io.NopCloser(bytes.NewReader(bytes.Clone(data))), nil
	default:
		return 404, nil, nil
	}
}

func (remote *manualCapturingRemote) Read(ctx context.Context, request atproto.ReadRequest) (atproto.ReadResult, error) {
	result, err := remote.delegate.Read(ctx, request)
	if err == nil {
		remote.result = result
	}
	return result, err
}

func (remote manualReplayRemote) Read(context.Context, atproto.ReadRequest) (atproto.ReadResult, error) {
	return remote.result, nil
}

func (source manualFixedTrustSource) Resolve(_ context.Context, selection service.VaultSelection) (service.TrustMaterial, error) {
	material := source.material
	material.Selection = selection
	return material, nil
}

func manualSuccessorTrust(t *testing.T, repository manualRepository) service.TrustMaterial {
	t.Helper()
	publisherSigning, publisherRecipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	publisherPublic := publisherSigning.Public().(ed25519.PublicKey)
	publisher := vault.DeviceMaterial{DeviceID: "manual-successor", KeyID: bytes.Clone(publisherPublic), Signing: publisherSigning, Recipient: publisherRecipient}
	predecessor := vault.Predecessor{
		ControlCID: bytes.Clone(repository.genesis.ControlCID), PolicyDigest: repository.genesis.PolicyDigest, EpochSeq: 0,
		HeadCID: bytes.Clone(repository.genesis.SnapshotCID), Head: bytes.Clone(repository.genesis.Head),
		Control: bytes.Clone(repository.genesis.Control), Policy: bytes.Clone(repository.genesis.Policy),
		Certificates: [][]byte{bytes.Clone(repository.genesis.Certificate)}, TrustAnchor: repository.anchor,
	}
	transition, err := vault.PrepareTransition(predecessor, vault.TransitionIntent{
		Kind: vault.TransitionEnroll, Vault: repository.vault, Signer: repository.root, NewDevice: &publisher,
		RequestedRole: vault.RolePublisher, ContentKey: bytes.Repeat([]byte{0x71}, 32),
		Recipients: [][]byte{bytes.Clone(repository.genesis.Certificate)},
		Wraps: []vault.RecipientWrapInput{
			{KeyID: bytes.Clone(repository.root.KeyID), EphemeralPrivate: [32]byte(bytes.Repeat([]byte{0x72}, 32)), WrapNonce: [24]byte(bytes.Repeat([]byte{0x73}, 24))},
			{KeyID: bytes.Clone(publisher.KeyID), EphemeralPrivate: [32]byte(bytes.Repeat([]byte{0x74}, 32)), WrapNonce: [24]byte(bytes.Repeat([]byte{0x75}, 24))},
		},
		Plaintext: []byte("synthetic successor checkpoint fixture"), PublicationID: [16]byte(bytes.Repeat([]byte{0x76}, 16)), Nonce: [24]byte(bytes.Repeat([]byte{0x77}, 24)),
	})
	require.NoError(t, err)
	policyDigest, err := vault.ComputePolicyDigest(transition.Policy)
	require.NoError(t, err)
	control, err := vault.DecodeControl(transition.Control)
	require.NoError(t, err)
	controlCID, err := (cid.Prefix{Version: 1, Codec: cid.Raw, MhType: 0x12, MhLength: 32}).Sum(transition.Control)
	require.NoError(t, err)
	return service.TrustMaterial{
		Selection: service.VaultSelection{Vault: repository.vault, DeviceID: repository.root.DeviceID}, Anchor: repository.anchor,
		Checkpoint: state.VaultCheckpoint{
			Vault: repository.vault, Anchor: repository.anchor, ControlCID: controlCID.Bytes(), ControlBytes: bytes.Clone(transition.Control),
			SnapshotCID: bytes.Clone(control.HeadSnapshotCID), Epoch: 1, PolicyDigest: policyDigest, RecordedAt: 2,
		},
		Held:              vault.ControlEvidence{Policy: bytes.Clone(transition.Policy), Control: bytes.Clone(transition.Control), Certificates: transition.Recipients},
		PredecessorPolicy: bytes.Clone(repository.genesis.Policy), PredecessorControl: bytes.Clone(repository.genesis.Control), Device: repository.root,
	}
}

func (session manualSession) ReadRequest(_ context.Context, selection service.VaultSelection, device vault.DeviceMaterial, anchor [32]byte, previousPolicy, previousControl []byte) (atproto.ReadRequest, error) {
	return atproto.ReadRequest{
		DID: session.did, DIDDocumentID: session.did, VerificationMethods: []atproto.VerificationMethod{session.method},
		Vault: selection.Vault, TrustAnchor: anchor, DeviceKeyID: bytes.Clone(device.KeyID), DeviceKey: device.Recipient,
		PreviousPolicy: bytes.Clone(previousPolicy), PreviousControl: bytes.Clone(previousControl),
	}, nil
}

func manualActionNames(entries []syncengine.PreviewEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Key.Source == model.SourceFiles {
			names = append(names, entry.Key.FilePath)
		}
	}
	return names
}

func manualActionKeys(entries []syncengine.PreviewEntry) []string {
	keys := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Key.Source == model.SourceGNOME {
			keys = append(keys, entry.Key.SettingKey)
		}
	}
	return keys
}
func mustManualRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}
