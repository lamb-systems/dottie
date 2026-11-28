package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/vault"
)

func configurePullTestSettingsTarget(t *testing.T, fixture *pullTestFixture) config.Target {
	t.Helper()
	policy, err := config.ApprovedGNOMEPolicy([]string{"appearance"})
	require.NoError(t, err)
	target := config.Target{
		ID: "desktop", Source: model.SourceGNOME, Mode: config.Review, GNOMEPolicy: &policy,
	}
	snapshot, err := service.FileConfigPort{Paths: fixture.paths}.Snapshot(t.Context())
	require.NoError(t, err)
	_, err = service.FileConfigPort{Paths: fixture.paths}.Update(
		t.Context(),
		snapshot.Token,
		func(current config.Config) (config.Config, error) {
			current.Targets = append(current.Targets, target)
			return current, nil
		},
	)
	require.NoError(t, err)
	return target
}

func TestPullAppliesFilesWhileASettingsTargetIsConfigured(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.configure(t, config.Review)
	configurePullTestSettingsTarget(t, fixture)
	reader := &pullTestReader{view: fixture.view(), payloads: fixture.payloads()}

	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	require.Contains(t, stdout.String(), "pull: first-use\n")
	token := pullTestConfirmation(t, stdout.String())

	stdout.Reset()
	stderr.Reset()
	code = 0
	command = newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token)
	require.Equal(t, 0, code, stderr.String())
	assert.Contains(t, stdout.String(), "pull: applied changes=1")
	content, err := os.ReadFile(fixture.targetPath("init.lua"))
	require.NoError(t, err, "a configured settings target blocked the files half")
	assert.Equal(t, pullTestBaseContent, string(content))
	assert.Equal(t, uint64(1), fixture.acceptedFloor(t).Revision)
}

func TestPullReportsAConfiguredTargetThePositionDoesNotName(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.configure(t, config.Review)
	configurePullTestSettingsTarget(t, fixture)
	reader := &pullTestReader{view: fixture.view(), payloads: fixture.payloads()}

	var stdout, stderr bytes.Buffer
	code := 0
	command := newPullTestCommand(t, fixture, &stdout, &stderr, &code, pullTestSession(), nil, reader, nil)
	code = runPullForTest(command, &code, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr.String())
	assert.Contains(t, stdout.String(), "target desktop is configured but the published position does not name it")
	assert.Contains(t, stdout.String(), "apply: changes=1")
}

func TestPullAppliesASingleEntriesHeadBesideAConfiguredSettingsTarget(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.configure(t, config.Review)
	configurePullTestSettingsTarget(t, fixture)
	content := []byte("synthetic single entries content")
	entries := []publication.SnapshotEntry{fixtureEntryForCLI(t, "init.lua", content, 0o600)}
	record := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: fixture.binding.Vault,
		PublicationID: [16]byte{0x62, 0x51},
		Segments: []publication.SnapshotSegment{{
			Target: model.Target{
				ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
				Root: &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
			},
			Form: publication.SegmentFormEntries, Entries: entries,
		}},
	}
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(raw)
	require.NoError(t, err)
	key, err := publication.SequenceKey(0)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: fixture.binding.Vault,
		PublicationSeq: 0, SnapshotCID: recordCID,
	})
	require.NoError(t, err)
	reader := &pullTestReader{
		view: publicationstate.SuppliedRepositoryView{
			Origin: fixture.binding, Scope: publicationstate.ViewScopeWholeRepository,
			SuppliedContext: fixture.context, Head: head,
			Snapshots: []publicationstate.SnapshotBlock{{Key: key, Raw: raw}},
		},
		entries: map[string][]byte{string(entries[0].Blob.CID): content},
	}

	code, stdout, stderr := runPullFileSetStep(t, fixture, reader, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "target desktop is configured but the published position does not name it")
	assert.NotContains(t, stdout, "pull: adoption only", "a settings target was offered an adoption token")
	token := pullTestConfirmation(t, stdout)
	code, _, stderr = runPullFileSetStep(
		t, fixture, reader, "--did", pullTestDID, "--vault", pullTestVaultHex(), "--confirm", token,
	)
	require.Equal(t, 0, code, stderr)
	written, err := os.ReadFile(fixture.targetPath("init.lua"))
	require.NoError(t, err)
	assert.Equal(t, content, written)
}

func TestPullAdoptionRefusesARootThatWouldRepublishADifferentDescriptor(t *testing.T) {
	paths, _ := cliEnvironment(t)
	publishedRoot := filepath.Join(paths.Home, ".config", "nvim")
	require.NoError(t, os.MkdirAll(publishedRoot, 0o700))
	paths.ConfigHome = filepath.Join(paths.Home, ".config")
	sources := pullApplySources{Paths: paths, Configuration: config.Default()}
	published := model.Target{
		ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: ".config/nvim", Kind: model.SelectionDirectory},
	}

	_, err := pullAdoptFilesTarget(sources, published)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "republished under a different root")

	paths.ConfigHome = filepath.Join(paths.ConfigHome, "unrelated")
	require.NoError(t, os.MkdirAll(paths.ConfigHome, 0o700))
	sources.Paths = paths
	adopted, err := pullAdoptFilesTarget(sources, published)
	require.NoError(t, err, "a round-tripping descriptor was refused")
	require.NotNil(t, adopted.Root)
	assert.Equal(t, model.RootHome, adopted.Root.Base)
	assert.Equal(t, ".config/nvim", adopted.Root.Path)
}

func TestPullRefusesAConfiguredTargetThePositionPublishedAtAnotherRoot(t *testing.T) {
	fixture := newPullTestFixture(t)
	fixture.configure(t, config.Review)
	published := model.Target{
		ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: "other", Kind: model.SelectionDirectory},
	}
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{published},
		Entries: []model.Entry{{
			TargetID: "files",
			File: &model.FileEntry{
				Path: "kept.conf", State: model.FilePresent, Kind: model.FileRegular,
				Content: []byte("kept"), Mode: 0o600,
			},
		}},
	}
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	cid, err := publication.RawPayloadCID(packed.Payload)
	require.NoError(t, err)
	record := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: fixture.binding.Vault,
		PublicationID: [16]byte{0x7a, 0x01},
		Segments: []publication.SnapshotSegment{{
			Target: published, Form: publication.SegmentFormPacked,
			Blob: publication.BlobReference{
				CID: cid, Size: uint64(len(packed.Payload)), MIMEType: publication.SnapshotBlobMIMEType,
			},
		}},
	}
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(raw)
	require.NoError(t, err)
	key, err := publication.SequenceKey(0)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: fixture.binding.Vault,
		PublicationSeq: 0, SnapshotCID: recordCID,
	})
	require.NoError(t, err)
	reader := &pullTestReader{
		view: publicationstate.SuppliedRepositoryView{
			Origin: fixture.binding, Scope: publicationstate.ViewScopeWholeRepository,
			SuppliedContext: fixture.context, Head: head,
			Snapshots: []publicationstate.SnapshotBlock{{Key: key, Raw: raw}},
		},
		entries: map[string][]byte{string(cid): packed.Payload},
	}

	code, stdout, stderr := runPullFileSetStep(t, fixture, reader, "--did", pullTestDID, "--vault", pullTestVaultHex())
	require.Equal(t, 3, code, stdout)
	assert.Contains(t, stderr, "files:home/config")
	assert.Contains(t, stderr, "files:home/other")
	assert.NotContains(t, stdout, "confirmation: ", "a rebind printed a confirmation token")
	require.NoFileExists(t, fixture.targetPath("kept.conf"))
}

func TestPullAdoptionPropagatesADescriptorRefusal(t *testing.T) {
	paths, _ := cliEnvironment(t)
	publishedRoot := filepath.Join(paths.Home, ".config", "nvim")
	require.NoError(t, os.MkdirAll(publishedRoot, 0o700))
	paths.ConfigHome = filepath.Join(paths.Home, ".config")
	sources := pullApplySources{Paths: paths, Configuration: config.Default()}
	material := pullApplyMaterial{Targets: []model.Target{{
		ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: ".config/nvim", Kind: model.SelectionDirectory},
	}}}

	_, _, _, err := pullAdoptPublishedTargets(sources, material, pullApplyPlanRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "would be republished under a different root")
	assert.Contains(t, err.Error(), "xdg-config/nvim")
}
