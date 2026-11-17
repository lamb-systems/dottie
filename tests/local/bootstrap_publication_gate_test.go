//go:build linux

package local_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
)

const (
	bootstrapGateDID      = "did:plc:bootstrappubgateaaaaaaaa"
	bootstrapGateVault    = "gate vault"
	bootstrapGateDeviceID = "gate-root-device"
	bootstrapGateTargetID = "gate-files"
	bootstrapGateTracked  = "prefs.ini"
	bootstrapGateSentinel = "gate-machine-only"
)

var (
	bootstrapGateAlpha = []byte("gate alpha\n")
	bootstrapGateBeta  = []byte("gate beta\n")
	bootstrapGateKeep  = []byte("gate second-machine sentinel\n")
)

var bootstrapGateLegacyCollections = []string{
	atproto.VaultHeadNSID,
	atproto.VaultControlNSID,
	atproto.VaultSnapshotNSID,
	atproto.VaultPolicyNSID,
	atproto.VaultCertificateNSID,
	atproto.VaultCheckpointNSID,
	atproto.VaultAttestationNSID,
}

type bootstrapGateKeyring struct {
	items map[string]vault.DeviceMaterial
}

func (keyring *bootstrapGateKeyring) LoadDeviceKeys(
	_ context.Context,
	vaultID [32]byte,
	deviceID string,
) (vault.DeviceMaterial, error) {
	if vaultID == ([32]byte{}) {
		return vault.DeviceMaterial{}, platform.ErrKeyringItemNotFound
	}
	device, exists := keyring.items[deviceID]
	if !exists {
		return vault.DeviceMaterial{}, platform.ErrKeyringItemNotFound
	}
	return device, nil
}

func (keyring *bootstrapGateKeyring) StoreDeviceKeys(
	_ context.Context,
	vaultID [32]byte,
	device vault.DeviceMaterial,
) error {
	if vaultID == ([32]byte{}) || device.DeviceID == "" {
		return errors.New("invalid synthetic device keys")
	}
	keyring.items[device.DeviceID] = device
	return nil
}

func (keyring *bootstrapGateKeyring) LoadDeviceKeysForVault(
	_ context.Context,
	vaultID [32]byte,
) ([]vault.DeviceMaterial, error) {
	if vaultID == ([32]byte{}) || len(keyring.items) == 0 {
		return nil, platform.ErrKeyringItemNotFound
	}
	devices := make([]vault.DeviceMaterial, 0, len(keyring.items))
	for _, device := range keyring.items {
		devices = append(devices, device)
	}
	return devices, nil
}

func (keyring *bootstrapGateKeyring) DeleteDeviceKeys(_ context.Context, _ [32]byte, deviceID string) error {
	delete(keyring.items, deviceID)
	return nil
}

type bootstrapGatePreflight struct {
	reader    atproto.RevisionReader
	transport atproto.Transport
	did       string
}

func (port bootstrapGatePreflight) Preflight(ctx context.Context) error {
	return atproto.CheckNoDottiePublication(ctx, port.reader, port.transport, port.did)
}

type bootstrapGateReviews struct {
	review publicationstate.LocalReviewContext
}

func (reviews bootstrapGateReviews) Acquire(
	context.Context,
) (publicationstate.LocalReviewContext, config.Token, service.ConfigGuard, error) {
	return reviews.review, config.Token{1}, bootstrapGateGuard{}, nil
}

type bootstrapGateGuard struct{}

func (bootstrapGateGuard) Release() {}

type bootstrapGateProposals struct {
	records map[[16]byte]service.PublicationProposalRecord
}

func newBootstrapGateProposals() *bootstrapGateProposals {
	return &bootstrapGateProposals{records: make(map[[16]byte]service.PublicationProposalRecord)}
}

func (store *bootstrapGateProposals) List(context.Context) ([]service.PublicationProposalRecord, error) {
	records := make([]service.PublicationProposalRecord, 0, len(store.records))
	for _, record := range store.records {
		records = append(records, record)
	}
	return records, nil
}

func (store *bootstrapGateProposals) Issue(_ context.Context, record service.PublicationProposalRecord) error {
	store.records[record.PublicationID] = record
	return nil
}

func (store *bootstrapGateProposals) Consume(_ context.Context, publicationID [16]byte) error {
	record, exists := store.records[publicationID]
	if !exists {
		return service.ErrPublicationProposalAbsent
	}
	record.Consumed = true
	store.records[publicationID] = record
	return nil
}

func (store *bootstrapGateProposals) Delete(_ context.Context, publicationID [16]byte) error {
	delete(store.records, publicationID)
	return nil
}

type bootstrapGateHome struct {
	paths         platform.Paths
	configuration config.Config
	target        config.Target
	selected      string
	sentinel      string
	local         *service.PublicationLocalContext
	storeDir      string
	records       *bootstrapGateProposals
}

type bootstrapGateMaterial struct {
	base    model.Snapshot
	remote  model.Snapshot
	payload []byte
}

func TestBootstrappedAccountPublishesOnlyV2AndPullsIntoASecondHome(t *testing.T) {
	ctx := context.Background()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	repositoryKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err := atprototest.NewMemoryPDS(bootstrapGateDID, repositoryKey)
	require.NoError(t, err)
	method := pds.VerificationMethod()
	reader := atproto.RevisionReader{
		Transport: pds, DIDDocumentID: bootstrapGateDID,
		VerificationMethods: []atproto.VerificationMethod{
			{
				ID:                 method.ID,
				Type:               method.Type,
				Controller:         method.Controller,
				PublicKeyMultibase: method.PublicKeyMultibase,
			},
		},
	}

	source := newBootstrapGateHome(t, root, "machine-a", bootstrapGateAlpha, bootstrapGateKeep)
	stateStore, err := state.Open(source.paths)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, stateStore.Close()) })
	keyring := &bootstrapGateKeyring{items: make(map[string]vault.DeviceMaterial)}
	clock := func() time.Time { return time.Unix(1_800_000_000, 0) }
	coordinator, err := service.NewCoordinator(service.Dependencies{
		Config: service.FileConfigPort{Paths: source.paths}, State: stateStore, DeviceKeys: keyring,
		GenesisPreflight: bootstrapGatePreflight{reader: reader, transport: pds, did: bootstrapGateDID},
		Paths:            source.paths, Clock: clock,
	})
	require.NoError(t, err)
	seedBootstrapGateRecord(t, pds, "app.bsky.actor.profile", "self")
	seeded, err := reader.Read(ctx, bootstrapGateDID)
	require.NoError(t, err)
	require.Contains(t, seeded.Membership(), atproto.RecordKey{Collection: "app.bsky.actor.profile", RKey: "self"})
	require.NoError(t, coordinator.PreflightVault(ctx))
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	t.Cleanup(func() { clear(signing) })
	device := vault.DeviceMaterial{
		DeviceID:  bootstrapGateDeviceID,
		KeyID:     bytes.Clone(signing.Public().(ed25519.PublicKey)),
		Signing:   signing,
		Recipient: recipient,
	}
	result, err := coordinator.InitializeVault(
		ctx,
		service.BootstrapRequest{VaultName: bootstrapGateVault, Device: device},
	)
	require.NoError(t, err)
	require.Equal(t, service.BootstrapLocalIdentityRecorded, result.Outcome)

	bootstrapped, err := reader.Read(ctx, bootstrapGateDID)
	require.NoError(t, err)
	assert.Len(t, bootstrapped.Membership(), 1, "bootstrap must publish no repository record")
	assert.Contains(
		t,
		bootstrapped.Membership(),
		atproto.RecordKey{Collection: "app.bsky.actor.profile", RKey: "self"},
		"bootstrap must leave the account's other records untouched",
	)
	assert.Equal(t, seeded.CommitCID(), bootstrapped.CommitCID(), "bootstrap must not change the repository")
	selections, err := stateStore.VaultSelections(ctx)
	require.NoError(t, err)
	require.Len(t, selections, 1)

	selected, err := coordinator.ResolveSelection(ctx, service.VaultSelection{})
	require.NoError(t, err)
	binding := publicationstate.Binding{
		AccountDID: bootstrapGateDID, Backend: publicationstate.BackendPublicRepo,
		Repository: "at://" + bootstrapGateDID, Vault: selected.Vault,
	}
	adapter, err := service.NewATProtoMaterialTransport(service.ATProtoMaterialConfig{
		Binding: binding, DID: bootstrapGateDID, Reader: reader, Transport: pds, BlobUploadLimit: 1 << 20,
	})
	require.NoError(t, err)
	blobs := atproto.VaultReader{Transport: pds, Budgets: atproto.DefaultBudgets()}
	published, err := service.NewPublicationReader(service.PublicationReaderConfig{
		Binding: binding, DID: bootstrapGateDID,
		Session: &atproto.Session{DID: bootstrapGateDID, Scopes: atproto.VaultScopes()},
		Adapter: adapter, Blobs: blobs,
	})
	require.NoError(t, err)

	firstPush := publishBootstrapGate(t, ctx, coordinator, source, binding, adapter, published, 1)
	assert.Equal(t, uint64(1), firstPush.Floor.Revision)
	assert.Equal(t, uint64(0), firstPush.Floor.Sequence)
	assert.Equal(t, publicationstate.OutcomeCurrent, firstPush.Outcome)

	destination := newBootstrapGateHome(t, root, "machine-b", bootstrapGateAlpha, bootstrapGateKeep)
	joined := joinBootstrapGatePosition(t, ctx, destination, binding, adapter, blobs)
	assert.Equal(t, uint64(1), joined.Revision)
	assert.Equal(t, uint64(0), joined.Sequence)
	assert.Equal(t, bootstrapGateAlpha, readBootstrapGateFile(t, destination))

	writeBootstrapGateFile(t, source, bootstrapGateBeta)
	secondPush := publishBootstrapGate(t, ctx, coordinator, source, binding, adapter, published, 2)
	require.Equal(t, uint64(2), secondPush.Floor.Revision)
	assert.Equal(t, uint64(1), secondPush.Floor.Sequence)

	pulled := pullBootstrapGate(t, ctx, destination, binding, adapter, blobs)
	assert.Equal(t, 1, pulled.Plan.Changes)
	assert.Equal(t, 1, pulled.Report.Applied)
	assert.Equal(t, bootstrapGateBeta, readBootstrapGateFile(t, destination))
	assert.Equal(t, bootstrapGateKeep, readBootstrapGateSentinel(t, destination))
	assert.Equal(t, secondPush.Floor.RecordCID, pulled.Accepted.RecordCID)
	assert.Equal(t, uint64(1), pulled.Accepted.Sequence)

	publishedRevision, err := reader.Read(ctx, bootstrapGateDID)
	require.NoError(t, err)
	assert.Equal(
		t,
		[]string{"app.bsky.actor.profile", publication.HeadNSID, publication.SnapshotNSID},
		bootstrapGateCollections(t, publishedRevision),
	)
	view, err := adapter.ReadView(ctx)
	require.NoError(t, err)
	require.NotErrorIs(t, err, service.ErrATProtoMaterialView)
	assert.Len(t, view.Snapshots, 2)
	assert.NotEmpty(t, view.Head)
}

func seedBootstrapGateRecord(t *testing.T, pds *atprototest.MemoryPDS, collection, rkey string) {
	t.Helper()
	body := []byte(
		`{"repo":"` + bootstrapGateDID + `","swapCommit":"` + pds.CurrentRevision().CommitCID.String() + `","writes":[{"$type":"com.atproto.repo.applyWrites#create","collection":"` + collection + `","rkey":"` + rkey + `","value":{"$type":"` + collection + `","probe":"bootstrap gate"}}]}`,
	)
	status, _, err := pds.Do(
		context.Background(),
		"POST",
		"com.atproto.repo.applyWrites",
		nil,
		body,
		"application/json",
	)
	require.NoError(t, err)
	require.Equal(t, 200, status)
}

func newBootstrapGateHome(t *testing.T, root, name string, content, sentinel []byte) *bootstrapGateHome {
	t.Helper()
	machineRoot := filepath.Join(root, name)
	paths := platform.Paths{
		Home: filepath.Join(machineRoot, "home"), ConfigHome: filepath.Join(machineRoot, "config"),
		StateHome: filepath.Join(machineRoot, "state"), CacheHome: filepath.Join(machineRoot, "cache"),
		DataHome: filepath.Join(machineRoot, "data"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
	}
	selected := filepath.Join(paths.Home, "synthetic")
	require.NoError(t, os.MkdirAll(selected, 0o700))
	target := config.Target{
		ID:     bootstrapGateTargetID,
		Source: model.SourceFiles,
		Mode:   config.Review,
		Root: &config.Root{
			Base:    model.RootHome,
			Path:    "synthetic",
			Kind:    model.SelectionDirectory,
			Exclude: []string{bootstrapGateSentinel},
		},
	}
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	require.NoError(t, configuration.Validate())
	local, err := service.NewPublicationLocalContext(paths, service.LocalFilesCapture{}, nil)
	require.NoError(t, err)
	storeDir := paths.PublicationStateDir()
	require.NoError(t, os.MkdirAll(storeDir, 0o700))
	require.NoError(t, os.Chmod(storeDir, 0o700))
	home := &bootstrapGateHome{
		paths: paths, configuration: configuration, target: target, selected: selected,
		sentinel: filepath.Join(selected, bootstrapGateSentinel), local: local, storeDir: storeDir,
		records: newBootstrapGateProposals(),
	}
	require.NoError(t, os.WriteFile(filepath.Join(selected, bootstrapGateTracked), content, 0o600))
	require.NoError(t, os.WriteFile(home.sentinel, sentinel, 0o600))
	return home
}

func publishBootstrapGate(
	t *testing.T,
	ctx context.Context,
	coordinator *service.Coordinator,
	home *bootstrapGateHome,
	binding publicationstate.Binding,
	adapter *service.ATProtoMaterialTransport,
	published *service.PublicationReader,
	sequence byte,
) service.MaterialPublishResult {
	t.Helper()
	store, err := publicationstate.Open(home.storeDir, binding)
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	var publicationID [16]byte
	publicationID[15] = sequence
	request := service.PublicationPushRequest{
		Store: store, Transport: adapter, Reader: published, Records: home.records, Binding: binding,
		Configuration: home.configuration, PublicationID: publicationID,
		Reviews: bootstrapGateReviews{review: publicationstate.LocalReviewContext{
			SelectionDigest: [32]byte{0x31}, SelectionRevision: 1, ApprovalDigest: [32]byte{0x32}, ApprovalRevision: 1,
		}},
	}
	preparation, err := coordinator.PreparePublicationPush(ctx, request)
	require.NoError(t, err, "the bootstrapped repository must publish through the v2 profile")
	require.False(t, preparation.NoOp)
	result, err := coordinator.ConfirmPublicationPush(ctx, request, preparation, preparation.Proposal.Confirmation)
	require.NoError(t, err)
	return result
}

func joinBootstrapGatePosition(
	t *testing.T,
	ctx context.Context,
	home *bootstrapGateHome,
	binding publicationstate.Binding,
	adapter *service.ATProtoMaterialTransport,
	blobs atproto.VaultReader,
) publicationstate.Floor {
	t.Helper()
	view, err := adapter.ReadView(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, view.Snapshots)
	terminal, err := publication.DecodeSnapshot(view.Snapshots[len(view.Snapshots)-1].Raw)
	require.NoError(t, err)
	payload, err := blobs.FetchBlob(ctx, bootstrapGateDID, terminal.Blob.CID, int64(terminal.Blob.Size))
	require.NoError(t, err)
	observation := publicationstate.Observation{
		Origin: view.Origin, SuppliedContext: view.SuppliedContext, Head: view.Head, Snapshots: view.Snapshots,
	}
	store, err := publicationstate.Open(home.storeDir, binding)
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	proposal, err := store.Prepare(ctx, publicationstate.ModeFirstUse, observation, payload)
	require.NoError(t, err)
	accepted, err := store.Accept(
		ctx,
		publicationstate.ModeFirstUse,
		proposal.StateToken,
		observation,
		payload,
		proposal.Confirmation,
	)
	require.NoError(t, err)
	return accepted
}

func pullBootstrapGate(
	t *testing.T,
	ctx context.Context,
	home *bootstrapGateHome,
	binding publicationstate.Binding,
	adapter *service.ATProtoMaterialTransport,
	blobs atproto.VaultReader,
) struct {
	Plan     service.PublicationApplyPlan
	Report   service.PublicationApplyReport
	Accepted publicationstate.Floor
} {
	t.Helper()
	inspection, err := publicationstate.Inspect(ctx, home.storeDir, binding)
	require.NoError(t, err)
	require.True(t, inspection.Present)
	view, err := adapter.ReadView(ctx)
	require.NoError(t, err)
	require.Equal(t, binding, view.Origin)
	material := bootstrapGateMaterialRead(t, ctx, view, inspection.Floor, blobs)
	observation := publicationstate.Observation{
		Origin: view.Origin, SuppliedContext: view.SuppliedContext, Head: view.Head, Snapshots: view.Snapshots,
	}
	request := service.PublicationApplyRequest{
		Vault: binding.Vault, FloorRevision: inspection.Floor.Revision, Configuration: home.configuration,
		BaseSnapshot: material.base, RemoteSnapshot: material.remote,
		Roots: map[string]string{home.target.ID: home.selected}, Local: home.local,
	}
	plan, err := service.PlanPublicationApply(ctx, request)
	require.NoError(t, err)
	require.NotZero(t, plan.Changes)
	staged, err := service.StagePublicationAccept(ctx, service.PublicationAcceptStageRequest{
		Directory: home.storeDir, Binding: binding, FloorRevision: inspection.Floor.Revision,
		Observation: observation, Payload: material.payload,
	})
	require.NoError(t, err)
	journal, err := publicationstate.OpenJournal(home.storeDir)
	require.NoError(t, err)
	request.Journal = journal
	request.ExpectedPlan = plan.Digest
	report, err := service.ApplyPublication(ctx, request)
	require.NoError(t, err)
	accepted, err := service.AcceptPublication(ctx, service.PublicationAcceptRequest{
		Directory:     home.storeDir,
		Binding:       binding,
		Mode:          staged.Mode,
		FloorRevision: inspection.Floor.Revision,
		StateToken:    staged.StateToken,
		Confirmation:  staged.Confirmation,
		Observation:   observation,
		Payload:       material.payload,
	})
	require.NoError(t, journal.Close())
	require.NoError(t, err)
	return struct {
		Plan     service.PublicationApplyPlan
		Report   service.PublicationApplyReport
		Accepted publicationstate.Floor
	}{Plan: plan, Report: report, Accepted: accepted}
}

func bootstrapGateMaterialRead(
	t *testing.T,
	ctx context.Context,
	view publicationstate.SuppliedRepositoryView,
	floor publicationstate.Floor,
	blobs atproto.VaultReader,
) bootstrapGateMaterial {
	t.Helper()
	require.NotEmpty(t, view.Snapshots)
	require.Less(t, floor.Sequence, uint64(len(view.Snapshots)))
	baseBlock := view.Snapshots[floor.Sequence]
	baseRecord, err := publication.DecodeSnapshot(baseBlock.Raw)
	require.NoError(t, err)
	basePayload, err := blobs.FetchBlob(ctx, bootstrapGateDID, baseRecord.Blob.CID, int64(baseRecord.Blob.Size))
	require.NoError(t, err)
	base, err := publication.DecodePayload(basePayload, baseRecord.Blob)
	require.NoError(t, err)
	terminal := view.Snapshots[len(view.Snapshots)-1]
	terminalRecord, err := publication.DecodeSnapshot(terminal.Raw)
	require.NoError(t, err)
	terminalPayload, err := blobs.FetchBlob(
		ctx,
		bootstrapGateDID,
		terminalRecord.Blob.CID,
		int64(terminalRecord.Blob.Size),
	)
	require.NoError(t, err)
	remote, err := publication.DecodePayload(terminalPayload, terminalRecord.Blob)
	require.NoError(t, err)
	return bootstrapGateMaterial{base: base, remote: remote, payload: terminalPayload}
}

func bootstrapGateCollections(t *testing.T, revision *atproto.Revision) []string {
	t.Helper()
	seen := make(map[string]struct{})
	for key := range revision.Membership() {
		seen[key.Collection] = struct{}{}
		for _, legacy := range bootstrapGateLegacyCollections {
			assert.NotEqual(t, legacy, key.Collection, "the published repository must hold no v1 record")
		}
	}
	collections := make([]string, 0, len(seen))
	for collection := range seen {
		collections = append(collections, collection)
	}
	sort.Strings(collections)
	return collections
}

func writeBootstrapGateFile(t *testing.T, home *bootstrapGateHome, content []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(home.selected, bootstrapGateTracked), content, 0o600))
}

func readBootstrapGateFile(t *testing.T, home *bootstrapGateHome) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(home.selected, bootstrapGateTracked))
	require.NoError(t, err)
	return content
}

func readBootstrapGateSentinel(t *testing.T, home *bootstrapGateHome) []byte {
	t.Helper()
	content, err := os.ReadFile(home.sentinel)
	require.NoError(t, err)
	return content
}
