package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type bootstrapGenesisPort struct {
	identity     atproto.Identity
	transport    atproto.Transport
	observations atproto.PublicationObservationStore
	order        *[]string
	unresolved   bool
}

func (port bootstrapGenesisPort) Preflight(ctx context.Context) error {
	*port.order = append(*port.order, "preflight")
	return atproto.CheckGenesisRepositoryEmpty(ctx, atproto.RevisionReader{
		Transport: port.transport, DIDDocumentID: port.identity.DIDDocumentID,
		VerificationMethods: append([]atproto.VerificationMethod(nil), port.identity.VerificationMethods...),
	}, port.transport, port.identity.DID)
}

func (port bootstrapGenesisPort) BlobUploadLimit(context.Context) (int64, error) {
	*port.order = append(*port.order, "blob-limit")
	return 1 << 20, nil
}

func (port bootstrapGenesisPort) CommitGenesis(ctx context.Context, limit int64, kit []byte, root vault.DeviceMaterial, genesis vault.Genesis) (atproto.GenesisCommitResult, error) {
	*port.order = append(*port.order, "publication")
	result, err := atproto.CommitGenesis(ctx, atproto.GenesisIO{
		Reader: atproto.RevisionReader{
			Transport: port.transport, Budgets: atproto.DefaultBudgets(), DIDDocumentID: port.identity.DIDDocumentID,
			VerificationMethods: append([]atproto.VerificationMethod(nil), port.identity.VerificationMethods...),
		},
		Transport: port.transport, BlobUploadLimit: limit, DID: port.identity.DID,
		ObservationStore: port.observations,
	}, kit, root, genesis)
	if err == nil && port.unresolved {
		result.Phase = atproto.GenesisSubmitted
		return result, atproto.ErrGenesisUnavailable
	}
	return result, err
}

func TestCoordinatorBootstrapFinalizesTrustForHistoryPullExportAndPush(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	paths := platform.Paths{
		Home: filepath.Join(root, "home"), ConfigHome: filepath.Join(root, "config"),
		StateHome: filepath.Join(root, "state"), CacheHome: filepath.Join(root, "cache"), DataHome: filepath.Join(root, "data"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
	}
	store, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	repositoryKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err := atprototest.NewMemoryPDS(publicationAuditDID, repositoryKey)
	require.NoError(t, err)
	method := pds.VerificationMethod()
	identity := atproto.Identity{
		DID: publicationAuditDID, DIDDocumentID: publicationAuditDID,
		VerificationMethods: []atproto.VerificationMethod{{
			ID: method.ID, Type: method.Type, Controller: method.Controller, PublicKeyMultibase: method.PublicKeyMultibase,
		}},
	}
	keyring := &publicationKeyring{devices: map[string]vault.DeviceMaterial{}}
	now := time.Unix(1_800_000_000, 0)
	require.NoError(t, config.Save(paths, config.Default()))
	order := make([]string, 0, 4)
	port := bootstrapGenesisPort{identity: identity, transport: pds, observations: store, order: &order}
	reader := atproto.RevisionReader{
		Transport: pds, Budgets: atproto.DefaultBudgets(), DIDDocumentID: identity.DIDDocumentID,
		VerificationMethods: identity.VerificationMethods,
	}
	publicationIO := atproto.ATProtoPublicationIO{
		Reader: reader, Transport: pds, BlobUploadLimit: 1 << 20, DID: identity.DID,
		ObservationStore: store, Clock: func() time.Time { return now },
	}
	coordinator, err := service.NewCoordinator(service.Dependencies{
		Config: service.FileConfigPort{Paths: paths}, State: store, DeviceKeys: keyring,
		Trust:     service.StateTrustSource{State: store, Keyring: keyring},
		Session:   publicationReadSession{did: identity.DID, methods: identity.VerificationMethods},
		Remote:    service.VaultReader{Reader: atproto.VaultReader{Transport: pds, ObservationStore: store, Clock: func() time.Time { return now }}},
		Publisher: publicationPublisher{io: publicationIO}, Genesis: port, Clock: func() time.Time { return now },
	})
	require.NoError(t, err)
	kit, err := vault.GenerateRecoveryKit()
	require.NoError(t, err)
	defer clear(kit)
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	defer clear(signing)
	device := vault.DeviceMaterial{DeviceID: "coordinator-bootstrap-root", KeyID: bytes.Clone(signing.Public().(ed25519.PublicKey)), Signing: signing, Recipient: recipient}
	require.NoError(t, coordinator.PreflightVault(ctx))
	result, err := coordinator.InitializeVault(ctx, service.BootstrapRequest{
		VaultName: "coordinator bootstrap", Kit: kit, Device: device,
		DeliverKit: func(_ vault.BootstrapResult, delivered []byte) error {
			require.Equal(t, kit, delivered)
			order = append(order, "kit-delivered")
			return nil
		},
	})
	require.NoError(t, err)
	require.Equal(t, service.BootstrapVerifiedCommit, result.Outcome)
	assert.Equal(t, []string{"preflight", "kit-delivered", "blob-limit", "publication"}, order)
	selection := service.VaultSelection{Vault: result.Bootstrap.Vault, DeviceID: device.DeviceID}
	assert.Equal(t, device.DeviceID, keyring.devices[device.DeviceID].DeviceID)

	history, err := coordinator.History(ctx, selection, false)
	require.NoError(t, err)
	require.Len(t, history.Checkpoints, 1)
	assert.Equal(t, uint64(0), history.Checkpoints[0].Epoch)

	pulled, err := coordinator.Pull(ctx, selection)
	require.NoError(t, err)
	assert.Zero(t, pulled.Read.PublicationCount)
	assert.Empty(t, pulled.Snapshot.Entries)

	archivePath := filepath.Join(paths.CacheHome, "bootstrap-export.tar")
	exported, err := coordinator.Export(ctx, service.ExportRequest{
		Selection: selection, ExpectedVault: result.Bootstrap.Vault, ExpectedAnchor: result.Bootstrap.Anchor,
		Kit: kit, Path: archivePath,
	})
	require.NoError(t, err)
	assert.Equal(t, result.Bootstrap.Vault, exported.VaultID)
	assert.FileExists(t, archivePath)

	pushed, err := coordinator.Push(ctx, selection)
	require.NoError(t, err)
	assert.Equal(t, service.StatusNoOp, pushed.Status)
	assert.True(t, pushed.NoOp)
}

type bootstrapRecoveryFixture struct {
	coordinator   *service.Coordinator
	store         *state.Store
	paths         platform.Paths
	pds           *atprototest.MemoryPDS
	reader        atproto.RevisionReader
	keyring       *publicationKeyring
	device        vault.DeviceMaterial
	kit           []byte
	result        service.BootstrapResult
	initializeErr error
}

func newBootstrapRecoveryFixture(t *testing.T, unresolved, failFinalization bool) *bootstrapRecoveryFixture {
	t.Helper()
	root := t.TempDir()
	paths := platform.Paths{
		Home: filepath.Join(root, "home"), ConfigHome: filepath.Join(root, "config"),
		StateHome: filepath.Join(root, "state"), CacheHome: filepath.Join(root, "cache"), DataHome: filepath.Join(root, "data"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
	}
	store, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	repositoryKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err := atprototest.NewMemoryPDS(publicationAuditDID, repositoryKey)
	require.NoError(t, err)
	method := pds.VerificationMethod()
	identity := atproto.Identity{
		DID: publicationAuditDID, DIDDocumentID: publicationAuditDID,
		VerificationMethods: []atproto.VerificationMethod{{
			ID: method.ID, Type: method.Type, Controller: method.Controller, PublicKeyMultibase: method.PublicKeyMultibase,
		}},
	}
	keyring := &publicationKeyring{devices: map[string]vault.DeviceMaterial{}}
	clock := func() time.Time { return time.Unix(1_800_000_000, 0) }
	reader := atproto.RevisionReader{Transport: pds, Budgets: atproto.DefaultBudgets(), DIDDocumentID: identity.DIDDocumentID, VerificationMethods: identity.VerificationMethods}
	order := make([]string, 0, 4)
	port := bootstrapGenesisPort{identity: identity, transport: pds, observations: store, order: &order, unresolved: unresolved}
	coordinator, err := service.NewCoordinator(service.Dependencies{
		State: store, DeviceKeys: keyring, Genesis: port,
		Trust:   service.StateTrustSource{State: store, Keyring: keyring},
		Session: publicationReadSession{did: identity.DID, methods: identity.VerificationMethods},
		Remote:  service.VaultReader{Reader: atproto.VaultReader{Transport: pds, ObservationStore: store, Clock: clock}}, Clock: clock,
	})
	require.NoError(t, err)
	if failFinalization {
		bootstrapSQLiteExec(t, paths, `CREATE TRIGGER fail_genesis_position_history BEFORE INSERT ON authenticated_position_history BEGIN SELECT RAISE(FAIL, 'interrupted write'); END`)
	}
	require.NoError(t, coordinator.PreflightVault(context.Background()))
	kit, err := vault.GenerateRecoveryKit()
	require.NoError(t, err)
	t.Cleanup(func() { clear(kit) })
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	t.Cleanup(func() { clear(signing) })
	device := vault.DeviceMaterial{DeviceID: "bootstrap-recovery-root", KeyID: bytes.Clone(signing.Public().(ed25519.PublicKey)), Signing: signing, Recipient: recipient}
	result, initializeErr := coordinator.InitializeVault(context.Background(), service.BootstrapRequest{
		VaultName: "bootstrap recovery", Kit: kit, Device: device,
		DeliverKit: func(vault.BootstrapResult, []byte) error { return nil },
	})
	return &bootstrapRecoveryFixture{
		coordinator: coordinator, store: store, paths: paths, pds: pds, reader: reader,
		keyring: keyring, device: device, kit: kit, result: result, initializeErr: initializeErr,
	}
}

func bootstrapSQLiteExec(t *testing.T, paths platform.Paths, statement string) {
	t.Helper()
	databasePath := filepath.Join(paths.AppStateDir(), "state.db")
	database, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: databasePath}).String())
	require.NoError(t, err)
	defer database.Close()
	_, err = database.Exec(statement)
	require.NoError(t, err)
}

func TestCoordinatorFinalizeAfterUnresolvedGenesisSubmission(t *testing.T) {
	fixture := newBootstrapRecoveryFixture(t, true, false)
	require.ErrorIs(t, fixture.initializeErr, atproto.ErrGenesisUnavailable)
	require.Equal(t, service.BootstrapUnresolved, fixture.result.Outcome)
	require.Len(t, fixture.keyring.devices, 1)
	before, err := fixture.reader.Read(context.Background(), publicationAuditDID)
	require.NoError(t, err)
	finalized, err := fixture.coordinator.FinalizeVaultTrust(context.Background(), fixture.result.Bootstrap.Vault)
	require.NoError(t, err)
	assert.False(t, finalized.NoOp)
	assert.Equal(t, fixture.device.DeviceID, finalized.Selection.DeviceID)
	assert.Equal(t, fixture.result.Bootstrap.Vault, finalized.Checkpoint.Vault)
	selections, err := fixture.store.VaultSelections(context.Background())
	require.NoError(t, err)
	assert.Len(t, selections, 1)
	checkpoint, err := fixture.store.VaultCheckpoint(context.Background(), fixture.result.Bootstrap.Vault)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), checkpoint.Epoch)
	after, err := fixture.reader.Read(context.Background(), publicationAuditDID)
	require.NoError(t, err)
	assert.Equal(t, before.CommitCID(), after.CommitCID())
}

func TestCoordinatorFinalizeAfterAtomicFinalizationFailure(t *testing.T) {
	fixture := newBootstrapRecoveryFixture(t, false, true)
	require.ErrorIs(t, fixture.initializeErr, service.ErrBootstrapTrustFinalizationFailed)
	require.Equal(t, service.BootstrapFinalizationError, fixture.result.Outcome)
	selections, err := fixture.store.VaultSelections(context.Background())
	require.NoError(t, err)
	assert.Empty(t, selections)
	_, err = fixture.store.VaultCheckpoint(context.Background(), fixture.result.Bootstrap.Vault)
	assert.ErrorIs(t, err, state.ErrVaultCheckpointNotFound)
	_, err = fixture.store.AuthenticatedPositionEvidenceAtEpoch(context.Background(), fixture.result.Bootstrap.Vault, 0)
	assert.ErrorIs(t, err, state.ErrAuthenticatedPositionEvidenceNotFound)
	bootstrapSQLiteExec(t, fixture.paths, `DROP TRIGGER fail_genesis_position_history`)
	before, err := fixture.reader.Read(context.Background(), publicationAuditDID)
	require.NoError(t, err)
	finalized, err := fixture.coordinator.FinalizeVaultTrust(context.Background(), fixture.result.Bootstrap.Vault)
	require.NoError(t, err)
	assert.False(t, finalized.NoOp)
	assert.Len(t, fixture.keyring.devices, 1)
	after, err := fixture.reader.Read(context.Background(), publicationAuditDID)
	require.NoError(t, err)
	assert.Equal(t, before.CommitCID(), after.CommitCID())
}

func TestCoordinatorFinalizeRefusesDifferentVerifiedCheckpointWithoutChangingTrust(t *testing.T) {
	fixture := newBootstrapRecoveryFixture(t, false, false)
	require.NoError(t, fixture.initializeErr)
	ctx := context.Background()
	root := t.TempDir()
	paths := platform.Paths{
		Home: filepath.Join(root, "home"), ConfigHome: filepath.Join(root, "config"),
		StateHome: filepath.Join(root, "state"), CacheHome: filepath.Join(root, "cache"), DataHome: filepath.Join(root, "data"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
	}
	store, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	bootstrap := fixture.result.Bootstrap
	clock := func() time.Time { return time.Unix(1_800_000_000, 0) }
	remote := service.VaultReader{Reader: atproto.VaultReader{Transport: fixture.pds, ObservationStore: store, Clock: clock}}
	verified, err := remote.Read(ctx, atproto.ReadRequest{
		DID: publicationAuditDID, DIDDocumentID: publicationAuditDID,
		VerificationMethods: fixture.reader.VerificationMethods, Vault: bootstrap.Vault, TrustAnchor: bootstrap.Anchor,
		DeviceKeyID: bytes.Clone(fixture.device.KeyID), DeviceKey: fixture.device.Recipient,
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(0), verified.EpochSeq)
	checkpoint, evidence, err := atproto.TrustMaterialFromVerifiedRead(verified, bootstrap.Anchor)
	require.NoError(t, err)
	checkpoint.RecordedAt = 1
	remoteCheckpointPosition := bytes.Clone(evidence.CheckpointPosition)
	checkpointPosition, err := vault.DecodeCheckpoint(evidence.CheckpointPosition)
	require.NoError(t, err)
	checkpointPosition.Signature[0] ^= 0xff
	evidence.CheckpointPosition, err = vault.EncodeCheckpoint(checkpointPosition)
	require.NoError(t, err)
	assert.NotEqual(t, remoteCheckpointPosition, evidence.CheckpointPosition)
	require.NoError(t, store.InitializeVaultTrust(ctx, state.VaultSelection{
		Vault: bootstrap.Vault, DeviceID: fixture.device.DeviceID, RecordedAt: 1,
	}, checkpoint, evidence))
	coordinator, err := service.NewCoordinator(service.Dependencies{
		State: store, DeviceKeys: fixture.keyring, Trust: service.StateTrustSource{State: store, Keyring: fixture.keyring},
		Session: publicationReadSession{did: publicationAuditDID, methods: fixture.reader.VerificationMethods},
		Remote:  remote, Clock: clock,
	})
	require.NoError(t, err)
	checkpointBefore, err := store.VaultCheckpoint(ctx, bootstrap.Vault)
	require.NoError(t, err)
	evidenceBefore, err := store.AuthenticatedPositionEvidence(ctx, bootstrap.Vault, 0, checkpoint.PolicyDigest)
	require.NoError(t, err)
	stateBytesBefore, err := os.ReadFile(filepath.Join(paths.AppStateDir(), "state.db"))
	require.NoError(t, err)
	revisionBefore, err := fixture.reader.Read(ctx, publicationAuditDID)
	require.NoError(t, err)
	_, err = coordinator.FinalizeVaultTrust(ctx, bootstrap.Vault)
	require.ErrorIs(t, err, service.ErrFinalizeStateConflict)
	checkpointAfter, err := store.VaultCheckpoint(ctx, bootstrap.Vault)
	require.NoError(t, err)
	assert.Equal(t, checkpointBefore, checkpointAfter)
	evidenceAfter, err := store.AuthenticatedPositionEvidence(ctx, bootstrap.Vault, 0, checkpoint.PolicyDigest)
	require.NoError(t, err)
	assert.Equal(t, evidenceBefore, evidenceAfter)
	stateBytesAfter, err := os.ReadFile(filepath.Join(paths.AppStateDir(), "state.db"))
	require.NoError(t, err)
	assert.Equal(t, stateBytesBefore, stateBytesAfter)
	revisionAfter, err := fixture.reader.Read(ctx, publicationAuditDID)
	require.NoError(t, err)
	assert.Equal(t, revisionBefore.CommitCID(), revisionAfter.CommitCID())
}
