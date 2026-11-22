//go:build linux

package local_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
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
)

const (
	publicationTwoMachineDID             = "did:plc:abcdefghijklmnopqrstuvwx"
	publicationTwoMachineTargetID        = "two-machine-files"
	publicationTwoMachineTrackedFile     = "prefs.ini"
	publicationTwoMachineSentinel        = "machine-only"
	publicationTwoMachineCrashMarker     = "DOTTIE_TEST_PUBLICATION_GATE_CRASH"
	publicationTwoMachineCrashRequestEnv = "DOTTIE_TEST_PUBLICATION_GATE_CRASH_REQUEST"
	publicationTwoMachineCrashHelper     = "TestPublicationGateApplyCrashHelper"
	publicationTwoMachineCrashStage      = "journaled"
	publicationTwoMachineCrashWait       = 30 * time.Second
)

var publicationTwoMachineAlpha = []byte("two-machine alpha\n")
var publicationTwoMachineSentinelA = []byte("source A local-only sentinel\n")
var publicationTwoMachineSentinelB = []byte("destination B local-only sentinel\n")
var publicationTwoMachineBeta = []byte("two-machine beta\n")
var publicationTwoMachineGamma = []byte("two-machine gamma\n")
var publicationTwoMachineConflictA = []byte("two-machine conflict from A\n")
var publicationTwoMachineConflictB = []byte("two-machine conflict from B\n")

type publicationTwoMachineFixture struct {
	pds          *atprototest.MemoryPDS
	binding      publicationstate.Binding
	review       publicationstate.LocalReviewContext
	adapter      *service.ATProtoMaterialTransport
	reader       *service.PublicationReader
	stateStore   *state.Store
	clock        time.Time
	a            *publicationTwoMachine
	b            *publicationTwoMachine
	publicationN uint64
}

type publicationTwoMachine struct {
	paths         platform.Paths
	configuration config.Config
	target        config.Target
	selected      string
	sentinel      string
	local         *service.PublicationLocalContext
	storeDir      string
	records       *publicationTwoMachineProposalStore
}

type publicationTwoMachinePullPreparation struct {
	Finding     string
	Floor       publicationstate.Floor
	View        publicationstate.SuppliedRepositoryView
	Base        model.Snapshot
	Remote      model.Snapshot
	Payload     []byte
	Observation publicationstate.Observation
	Request     service.PublicationApplyRequest
	Plan        service.PublicationApplyPlan
	Staged      service.PublicationAcceptProposal
	Applies     bool
}

type publicationTwoMachinePullResult struct {
	Finding  string
	Plan     service.PublicationApplyPlan
	Report   service.PublicationApplyReport
	Accepted publicationstate.Floor
}

type publicationTwoMachineJournalRow struct {
	Entry           int64
	State           publicationstate.JournalState
	Stage           publicationstate.JournalStage
	DestinationPath string
	Postimage       [32]byte
	HasPostimage    bool
}

type publicationTwoMachineFileIdentity struct {
	Inode   uint64
	ModTime time.Time
	Size    int64
}

type publicationTwoMachineCrashRequest struct {
	Paths          platform.Paths
	Vault          [32]byte
	FloorRevision  uint64
	Configuration  config.Config
	BaseSnapshot   model.Snapshot
	RemoteSnapshot model.Snapshot
	Roots          map[string]string
	ExpectedPlan   [32]byte
}

type publicationTwoMachineProposalStore struct {
	mu      sync.Mutex
	records map[[16]byte]service.PublicationProposalRecord
}

type publicationTwoMachineReviews struct {
	review publicationstate.LocalReviewContext
}

type publicationTwoMachineGuard struct{}

func TestTwoMachinePublicationPullApplyGate(t *testing.T) {
	fixture := newPublicationTwoMachineFixture(t)
	writePublicationTwoMachineFile(t, fixture.a, publicationTwoMachineAlpha)
	writePublicationTwoMachineFile(t, fixture.b, publicationTwoMachineAlpha)

	firstPush := fixture.push(t, fixture.a)
	firstRecordCID := bytes.Clone(firstPush.Floor.RecordCID)
	require.NotEmpty(t, firstRecordCID)
	assert.Equal(t, uint64(1), firstPush.Floor.Revision)
	assert.Equal(t, uint64(0), firstPush.Floor.Sequence)

	joined := fixture.joinFirstUse(t, fixture.b)
	assert.Equal(t, uint64(1), joined.Revision)
	assert.Equal(t, uint64(0), joined.Sequence)
	assert.Equal(t, firstRecordCID, joined.RecordCID)
	assert.Equal(t, fixture.binding, joined.Binding)

	writePublicationTwoMachineFile(t, fixture.a, publicationTwoMachineBeta)
	secondPush := fixture.push(t, fixture.a)
	require.Equal(t, uint64(2), secondPush.Floor.Revision)
	publishedCID := bytes.Clone(secondPush.Floor.RecordCID)
	require.NotEmpty(t, publishedCID)
	assert.Equal(t, uint64(1), secondPush.Floor.Sequence)
	assert.NotEqual(t, firstRecordCID, publishedCID)

	pulled := fixture.pull(t, fixture.b)
	assert.Equal(t, "diverges", pulled.Finding)
	assert.Equal(t, 1, pulled.Plan.Changes)
	assert.Equal(t, 1, pulled.Report.Applied)
	assert.Equal(t, uint64(len(publicationTwoMachineBeta)), pulled.Report.BytesWritten)
	assert.Equal(t, uint64(2), pulled.Accepted.Revision)
	assert.Equal(t, uint64(1), pulled.Accepted.Sequence)
	assert.Equal(t, publishedCID, pulled.Accepted.RecordCID)
	assert.Equal(t, fixture.binding, pulled.Accepted.Binding)
	assert.Equal(t, publicationTwoMachineBeta, readPublicationTwoMachineFile(t, fixture.b))
	assert.Equal(t, publicationTwoMachineSentinelB, readPublicationTwoMachineSentinel(t, fixture.b))
	rows := readPublicationTwoMachineJournalRows(t, fixture.b.storeDir)
	require.Len(t, rows, 1)
	assert.Equal(t, publicationstate.JournalStateApplied, rows[0].State)
	assert.Equal(t, publicationstate.JournalStageApplyComplete, rows[0].Stage)
	assert.Equal(t, publicationTwoMachineTrackedFile, rows[0].DestinationPath)
	assert.True(t, rows[0].HasPostimage)
	assert.Equal(t, sha256.Sum256(publicationTwoMachineBeta), rows[0].Postimage)

	beforeIdentity := publicationTwoMachineIdentity(t, fixture.b)
	noop := fixture.pull(t, fixture.b)
	assert.Equal(t, "matches", noop.Finding)
	assert.Equal(t, 0, noop.Plan.Changes)
	assert.Empty(t, noop.Report.Entries)
	assert.Equal(t, publicationstate.Floor{}, noop.Accepted)
	assert.Equal(t, beforeIdentity, publicationTwoMachineIdentity(t, fixture.b))

	writePublicationTwoMachineFile(t, fixture.b, publicationTwoMachineGamma)
	bPush := fixture.push(t, fixture.b)
	require.Equal(t, uint64(3), bPush.Floor.Revision)
	bPublishedCID := bytes.Clone(bPush.Floor.RecordCID)
	require.NotEmpty(t, bPublishedCID)
	assert.Equal(t, uint64(2), bPush.Floor.Sequence)

	aPulled := fixture.pull(t, fixture.a)
	assert.Equal(t, "diverges", aPulled.Finding)
	assert.Equal(t, 1, aPulled.Plan.Changes)
	assert.Equal(t, 1, aPulled.Report.Applied)
	assert.Equal(t, uint64(3), aPulled.Accepted.Revision)
	assert.Equal(t, uint64(2), aPulled.Accepted.Sequence)
	assert.Equal(t, bPublishedCID, aPulled.Accepted.RecordCID)
	assert.Equal(t, publicationTwoMachineGamma, readPublicationTwoMachineFile(t, fixture.a))
	assert.Equal(t, publicationTwoMachineSentinelA, readPublicationTwoMachineSentinel(t, fixture.a))
	aRows := readPublicationTwoMachineJournalRows(t, fixture.a.storeDir)
	require.Len(t, aRows, 1)
	assert.Equal(t, publicationstate.JournalStateApplied, aRows[0].State)
	assert.Equal(t, publicationstate.JournalStageApplyComplete, aRows[0].Stage)
	assert.Equal(t, publicationTwoMachineTrackedFile, aRows[0].DestinationPath)
	assert.Equal(t, sha256.Sum256(publicationTwoMachineGamma), aRows[0].Postimage)

	aNoop := fixture.pull(t, fixture.a)
	assert.Equal(t, "matches", aNoop.Finding)
	assert.Equal(t, 0, aNoop.Plan.Changes)
	assert.Equal(t, publicationTwoMachineGamma, readPublicationTwoMachineFile(t, fixture.a))
}

func TestTwoMachinePublicationPreservesDeclaredFileModes(t *testing.T) {
	fixture := newPublicationTwoMachineFixture(t)
	writePublicationTwoMachineFileMode(t, fixture.a, publicationTwoMachineAlpha, 0o600)
	writePublicationTwoMachineFileMode(t, fixture.b, publicationTwoMachineAlpha, 0o600)
	fixture.push(t, fixture.a)
	fixture.joinFirstUse(t, fixture.b)

	writePublicationTwoMachineFileMode(t, fixture.a, publicationTwoMachineBeta, 0o644)
	fixture.push(t, fixture.a)
	shared := fixture.pull(t, fixture.b)
	assert.Equal(t, "diverges", shared.Finding)
	assert.Equal(t, 1, shared.Report.Applied)
	assert.Equal(t, publicationTwoMachineBeta, readPublicationTwoMachineFile(t, fixture.b))
	assert.Equal(t, os.FileMode(0o644), publicationTwoMachineFileMode(t, fixture.b))

	writePublicationTwoMachineFileMode(t, fixture.a, publicationTwoMachineGamma, 0o600)
	fixture.push(t, fixture.a)
	private := fixture.pull(t, fixture.b)
	assert.Equal(t, "diverges", private.Finding)
	assert.Equal(t, 1, private.Report.Applied)
	assert.Equal(t, publicationTwoMachineGamma, readPublicationTwoMachineFile(t, fixture.b))
	assert.Equal(t, os.FileMode(0o600), publicationTwoMachineFileMode(t, fixture.b))
}

func TestTwoMachinePublicationApplyInterleavingRecovers(t *testing.T) {
	fixture := newPublicationTwoMachineFixture(t)
	writePublicationTwoMachineFile(t, fixture.a, publicationTwoMachineAlpha)
	writePublicationTwoMachineFile(t, fixture.b, publicationTwoMachineAlpha)
	fixture.push(t, fixture.a)
	fixture.joinFirstUse(t, fixture.b)

	writePublicationTwoMachineFile(t, fixture.a, publicationTwoMachineBeta)
	fixture.push(t, fixture.a)

	preparation, err := fixture.preparePull(t, fixture.b)
	require.NoError(t, err)
	require.True(t, preparation.Applies)
	require.Equal(t, 1, preparation.Plan.Changes)
	requestPath := filepath.Join(t.TempDir(), "apply-request.json")
	encoded, err := json.Marshal(publicationTwoMachineCrashRequest{
		Paths: fixture.b.paths, Vault: fixture.binding.Vault, FloorRevision: preparation.Floor.Revision,
		Configuration: preparation.Request.Configuration, BaseSnapshot: preparation.Request.BaseSnapshot,
		RemoteSnapshot: preparation.Request.RemoteSnapshot, Roots: preparation.Request.Roots,
		ExpectedPlan: preparation.Plan.Digest,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(requestPath, encoded, 0o600))
	runPublicationTwoMachineCrashHelper(t, requestPath)

	interrupted := readPublicationTwoMachineJournalRows(t, fixture.b.storeDir)
	require.Len(t, interrupted, 1)
	assert.Equal(t, publicationstate.JournalStatePending, interrupted[0].State)
	assert.Equal(t, publicationstate.JournalStageApplyPending, interrupted[0].Stage)
	assert.Equal(t, publicationTwoMachineTrackedFile, interrupted[0].DestinationPath)
	assert.True(t, interrupted[0].HasPostimage)
	assert.Equal(t, sha256.Sum256(publicationTwoMachineBeta), interrupted[0].Postimage)
	assert.Equal(t, publicationTwoMachineAlpha, readPublicationTwoMachineFile(t, fixture.b))

	recovered := fixture.pull(t, fixture.b)
	assert.Equal(t, "diverges", recovered.Finding)
	assert.Equal(t, 1, recovered.Plan.Changes)
	assert.Equal(t, 1, recovered.Report.Applied)
	assert.Equal(t, uint64(2), recovered.Accepted.Revision)
	assert.Equal(t, publicationTwoMachineBeta, readPublicationTwoMachineFile(t, fixture.b))
	rows := readPublicationTwoMachineJournalRows(t, fixture.b.storeDir)
	require.Len(t, rows, 2)
	assert.Equal(t, publicationstate.JournalStateFailed, rows[0].State)
	assert.Equal(t, publicationstate.JournalStageApplyFailed, rows[0].Stage)
	assert.Equal(t, publicationstate.JournalStateApplied, rows[1].State)
	assert.Equal(t, publicationstate.JournalStageApplyComplete, rows[1].Stage)
	assert.Equal(t, sha256.Sum256(publicationTwoMachineBeta), rows[1].Postimage)
}

func TestTwoMachinePublicationConflictRefusesWithoutMutation(t *testing.T) {
	fixture := newPublicationTwoMachineFixture(t)
	writePublicationTwoMachineFile(t, fixture.a, publicationTwoMachineAlpha)
	writePublicationTwoMachineFile(t, fixture.b, publicationTwoMachineAlpha)
	fixture.push(t, fixture.a)
	fixture.joinFirstUse(t, fixture.b)

	writePublicationTwoMachineFile(t, fixture.a, publicationTwoMachineConflictA)
	aPush := fixture.push(t, fixture.a)
	publishedCID := bytes.Clone(aPush.Floor.RecordCID)
	bFloorBefore, err := publicationstate.Inspect(context.Background(), fixture.b.storeDir, fixture.binding)
	require.NoError(t, err)
	require.True(t, bFloorBefore.Present)
	providerRevision := fixture.pds.CurrentRevision().CommitCID.String()
	writePublicationTwoMachineFile(t, fixture.b, publicationTwoMachineConflictB)

	preparation, err := fixture.preparePull(t, fixture.b)
	require.Error(t, err)
	require.ErrorIs(t, err, service.ErrPublicationApply)
	var refused interface {
		Stage() string
		Reason() string
		Conflicts() []service.PublicationApplyConflict
	}
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, "apply-plan", refused.Stage())
	assert.Equal(t, "plan_conflict", refused.Reason())
	assert.Equal(t, []service.PublicationApplyConflict{
		{TargetID: publicationTwoMachineTargetID, Path: publicationTwoMachineTrackedFile, Shape: "both-modified"},
	}, refused.Conflicts())
	assert.False(t, preparation.Applies)
	assert.Equal(t, publicationTwoMachineConflictA, readPublicationTwoMachineFile(t, fixture.a))
	assert.Equal(t, publicationTwoMachineConflictB, readPublicationTwoMachineFile(t, fixture.b))
	assert.Equal(t, publicationTwoMachineSentinelA, readPublicationTwoMachineSentinel(t, fixture.a))
	assert.Equal(t, publicationTwoMachineSentinelB, readPublicationTwoMachineSentinel(t, fixture.b))
	assert.Equal(t, providerRevision, fixture.pds.CurrentRevision().CommitCID.String())
	assert.Equal(t, publishedCID, aPush.Floor.RecordCID)
	bFloorAfter, err := publicationstate.Inspect(context.Background(), fixture.b.storeDir, fixture.binding)
	require.NoError(t, err)
	assert.Equal(t, bFloorBefore.Floor, bFloorAfter.Floor)
	assert.Empty(t, readPublicationTwoMachineJournalRows(t, fixture.b.storeDir))

	aFloor, err := publicationstate.Inspect(context.Background(), fixture.a.storeDir, fixture.binding)
	require.NoError(t, err)
	require.True(t, aFloor.Present)
	assert.Equal(t, aPush.Floor, aFloor.Floor)
	assert.Empty(t, readPublicationTwoMachineJournalRows(t, fixture.a.storeDir))
}

func newPublicationTwoMachineFixture(t *testing.T) *publicationTwoMachineFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	key, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err := atprototest.NewMemoryPDS(publicationTwoMachineDID, key)
	require.NoError(t, err)
	method := pds.VerificationMethod()
	reader := atproto.RevisionReader{
		Transport: pds, DIDDocumentID: publicationTwoMachineDID,
		VerificationMethods: []atproto.VerificationMethod{
			{
				ID:                 method.ID,
				Type:               method.Type,
				Controller:         method.Controller,
				PublicKeyMultibase: method.PublicKeyMultibase,
			},
		},
	}
	binding := publicationstate.Binding{
		AccountDID: publicationTwoMachineDID, Backend: publicationstate.BackendPublicRepo,
		Repository: "at://" + publicationTwoMachineDID, Vault: [32]byte{0x74, 0x77, 0x6f},
	}
	adapter, err := service.NewATProtoMaterialTransport(service.ATProtoMaterialConfig{
		Binding: binding, DID: publicationTwoMachineDID, Reader: reader, Transport: pds, BlobUploadLimit: 1 << 20,
	})
	require.NoError(t, err)
	session := &atproto.Session{DID: publicationTwoMachineDID, Scopes: atproto.VaultScopes()}
	publicationReader, err := service.NewPublicationReader(service.PublicationReaderConfig{
		Binding: binding, DID: publicationTwoMachineDID, Session: session, Adapter: adapter,
		Blobs: atproto.VaultReader{Transport: pds, Budgets: atproto.DefaultBudgets()},
	})
	require.NoError(t, err)
	stateHome := filepath.Join(root, "coordinator")
	require.NoError(t, os.MkdirAll(stateHome, 0o700))
	stateStore, err := state.Open(platform.Paths{Home: stateHome, StateHome: stateHome})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, stateStore.Close()) })
	fixture := &publicationTwoMachineFixture{
		pds: pds, binding: binding, adapter: adapter, reader: publicationReader, stateStore: stateStore,
		clock: time.Unix(1_800_000_000, 0),
		review: publicationstate.LocalReviewContext{
			SelectionDigest: [32]byte{0x71}, SelectionRevision: 1,
			ApprovalDigest: [32]byte{0x72}, ApprovalRevision: 1,
		},
	}
	fixture.a = newPublicationTwoMachine(t, root, "machine-a")
	fixture.b = newPublicationTwoMachine(t, root, "machine-b")
	return fixture
}

func newPublicationTwoMachine(t *testing.T, root, name string) *publicationTwoMachine {
	t.Helper()
	machineRoot := filepath.Join(root, name)
	home := filepath.Join(machineRoot, "home")
	paths := platform.Paths{
		Home: home, ConfigHome: filepath.Join(machineRoot, "config"),
		StateHome: filepath.Join(machineRoot, "state"), CacheHome: filepath.Join(machineRoot, "cache"),
		DataHome: filepath.Join(machineRoot, "data"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
	}
	selected := filepath.Join(home, "synthetic")
	require.NoError(t, os.MkdirAll(selected, 0o700))
	empty := filepath.Join(home, "synthetic-empty")
	require.NoError(t, os.MkdirAll(empty, 0o700))
	target := config.Target{
		ID:     publicationTwoMachineTargetID,
		Source: model.SourceFiles,
		Mode:   config.Review,
		Root: &config.Root{
			Base:    model.RootHome,
			Path:    "synthetic",
			Kind:    model.SelectionDirectory,
			Exclude: []string{publicationTwoMachineSentinel},
		},
	}
	configuration := config.Default()
	configuration.Targets = []config.Target{target, {
		ID: publicationTwoMachineTargetID + "-empty", Source: model.SourceFiles, Mode: config.Review,
		Root: &config.Root{Base: model.RootHome, Path: "synthetic-empty", Kind: model.SelectionDirectory},
	}}
	require.NoError(t, configuration.Validate())
	local, err := service.NewPublicationLocalContext(paths, service.LocalFilesCapture{}, nil)
	require.NoError(t, err)
	storeDir := paths.PublicationStateDir()
	require.NoError(t, os.MkdirAll(storeDir, 0o700))
	require.NoError(t, os.Chmod(storeDir, 0o700))
	machine := &publicationTwoMachine{
		paths: paths, configuration: configuration, target: target, selected: selected,
		sentinel: filepath.Join(selected, publicationTwoMachineSentinel), local: local, storeDir: storeDir,
		records: newPublicationTwoMachineProposalStore(),
	}
	sentinel := publicationTwoMachineSentinelA
	if name == "machine-b" {
		sentinel = publicationTwoMachineSentinelB
	}
	writePublicationTwoMachineFileAt(t, machine.sentinel, sentinel)
	return machine
}

func (fixture *publicationTwoMachineFixture) push(
	t *testing.T,
	machine *publicationTwoMachine,
) service.MaterialPublishResult {
	t.Helper()
	ctx := context.Background()
	store, err := publicationstate.Open(machine.storeDir, fixture.binding)
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	fixture.publicationN++
	var publicationID [16]byte
	binary.BigEndian.PutUint64(publicationID[:8], fixture.publicationN)
	request := service.PublicationPushRequest{
		Store: store, Transport: fixture.adapter, Reader: fixture.reader, Records: machine.records,
		Binding: fixture.binding, Configuration: machine.configuration,
		Reviews: publicationTwoMachineReviews{review: fixture.review}, PublicationID: publicationID,
	}
	coordinator, err := service.NewCoordinator(
		service.Dependencies{
			State: fixture.stateStore,
			Paths: machine.paths,
			Clock: func() time.Time { return fixture.clock },
		},
	)
	require.NoError(t, err)
	preparation, err := coordinator.PreparePublicationPush(ctx, request)
	require.NoError(t, err)
	require.False(t, preparation.NoOp)
	result, err := coordinator.ConfirmPublicationPush(ctx, request, preparation, preparation.Proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, publicationstate.OutcomeCurrent, result.Outcome)
	assert.Equal(t, publicationstate.AttemptRetiredSuccess, result.Attempt.Lifecycle)
	assert.Equal(t, fixture.binding, result.Floor.Binding)
	return result
}

func (fixture *publicationTwoMachineFixture) joinFirstUse(
	t *testing.T,
	machine *publicationTwoMachine,
) publicationstate.Floor {
	t.Helper()
	ctx := context.Background()
	view, err := fixture.adapter.ReadView(ctx)
	require.NoError(t, err)
	payload := fixture.terminalPayload(t, view)
	observation := publicationTwoMachineObservation(view)
	store, err := publicationstate.Open(machine.storeDir, fixture.binding)
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

func (fixture *publicationTwoMachineFixture) preparePull(
	t *testing.T,
	machine *publicationTwoMachine,
) (publicationTwoMachinePullPreparation, error) {
	t.Helper()
	ctx := context.Background()
	inspection, err := publicationstate.Inspect(ctx, machine.storeDir, fixture.binding)
	require.NoError(t, err)
	require.True(t, inspection.Present)
	view, err := fixture.adapter.ReadView(ctx)
	require.NoError(t, err)
	require.Equal(t, fixture.binding, view.Origin)
	preparation := publicationTwoMachinePullPreparation{
		Finding: publicationTwoMachineFinding(inspection.Floor, view),
		Floor:   inspection.Floor, View: view,
	}
	if preparation.Finding == "matches" {
		return preparation, nil
	}
	base, remote, payload := fixture.pullMaterial(t, view, inspection.Floor)
	preparation.Base, preparation.Remote, preparation.Payload = base, remote, payload
	preparation.Observation = publicationTwoMachineObservation(view)
	preparation.Request = service.PublicationApplyRequest{
		Vault: fixture.binding.Vault, FloorRevision: inspection.Floor.Revision,
		Configuration: machine.configuration, BaseSnapshot: base, RemoteSnapshot: remote,
		Roots: map[string]string{
			machine.target.ID:            machine.selected,
			machine.target.ID + "-empty": filepath.Join(machine.paths.Home, "synthetic-empty"),
		}, Local: machine.local,
	}
	plan, err := service.PlanPublicationApply(ctx, preparation.Request)
	if err != nil {
		return preparation, err
	}
	preparation.Plan = plan
	if plan.Changes == 0 {
		return preparation, nil
	}
	staged, err := service.StagePublicationAccept(ctx, service.PublicationAcceptStageRequest{
		Directory: machine.storeDir, Binding: fixture.binding, FloorRevision: inspection.Floor.Revision,
		Observation: preparation.Observation, Payload: payload,
	})
	if err != nil {
		return preparation, err
	}
	preparation.Staged = staged
	preparation.Applies = true
	return preparation, nil
}

func (fixture *publicationTwoMachineFixture) applyPull(
	t *testing.T,
	machine *publicationTwoMachine,
	preparation publicationTwoMachinePullPreparation,
) (service.PublicationApplyReport, publicationstate.Floor) {
	t.Helper()
	ctx := context.Background()
	journal, err := publicationstate.OpenJournal(machine.storeDir)
	require.NoError(t, err)
	request := preparation.Request
	request.Journal = journal
	request.ExpectedPlan = preparation.Plan.Digest
	report, applyErr := service.ApplyPublication(ctx, request)
	if applyErr != nil {
		_ = journal.Close()
		require.NoError(t, applyErr)
	}
	accepted, acceptErr := service.AcceptPublication(ctx, service.PublicationAcceptRequest{
		Directory: machine.storeDir, Binding: fixture.binding, Mode: preparation.Staged.Mode,
		FloorRevision: preparation.Floor.Revision, StateToken: preparation.Staged.StateToken,
		Confirmation: preparation.Staged.Confirmation, Observation: preparation.Observation,
		Payload: preparation.Payload,
	})
	require.NoError(t, journal.Close())
	require.NoError(t, acceptErr)
	return report, accepted
}

func (fixture *publicationTwoMachineFixture) pull(
	t *testing.T,
	machine *publicationTwoMachine,
) publicationTwoMachinePullResult {
	t.Helper()
	preparation, err := fixture.preparePull(t, machine)
	require.NoError(t, err)
	result := publicationTwoMachinePullResult{Finding: preparation.Finding, Plan: preparation.Plan}
	if !preparation.Applies {
		return result
	}
	result.Report, result.Accepted = fixture.applyPull(t, machine, preparation)
	return result
}

func (fixture *publicationTwoMachineFixture) pullMaterial(
	t *testing.T,
	view publicationstate.SuppliedRepositoryView,
	floor publicationstate.Floor,
) (model.Snapshot, model.Snapshot, []byte) {
	t.Helper()
	require.NotEmpty(t, view.Snapshots)
	require.Less(t, floor.Sequence, uint64(len(view.Snapshots)))
	baseBlock := view.Snapshots[floor.Sequence]
	baseRecord, err := publication.DecodeSnapshot(baseBlock.Raw)
	require.NoError(t, err)
	baseCID, err := publication.RecordCID(baseBlock.Raw)
	require.NoError(t, err)
	require.Equal(t, floor.SnapshotKey, baseBlock.Key)
	require.Equal(t, floor.RecordCID, baseCID)
	require.Equal(t, floor.BlobCID, baseRecord.Blob.CID)
	require.Equal(t, floor.BlobSize, baseRecord.Blob.Size)
	basePayload := fixture.payloadFor(t, baseRecord)
	base, err := publication.DecodePayload(basePayload, baseRecord.Blob)
	require.NoError(t, err)
	terminal := view.Snapshots[len(view.Snapshots)-1]
	terminalRecord, err := publication.DecodeSnapshot(terminal.Raw)
	require.NoError(t, err)
	terminalPayload := fixture.payloadFor(t, terminalRecord)
	remote, err := publication.DecodePayload(terminalPayload, terminalRecord.Blob)
	require.NoError(t, err)
	return base, remote, terminalPayload
}

func (fixture *publicationTwoMachineFixture) terminalPayload(
	t *testing.T,
	view publicationstate.SuppliedRepositoryView,
) []byte {
	t.Helper()
	require.NotEmpty(t, view.Snapshots)
	terminal, err := publication.DecodeSnapshot(view.Snapshots[len(view.Snapshots)-1].Raw)
	require.NoError(t, err)
	return fixture.payloadFor(t, terminal)
}

func (fixture *publicationTwoMachineFixture) payloadFor(t *testing.T, record publication.SnapshotRecord) []byte {
	t.Helper()
	payload, err := atproto.VaultReader{Transport: fixture.pds, Budgets: atproto.DefaultBudgets()}.FetchBlob(
		context.Background(), publicationTwoMachineDID, record.Blob.CID, int64(record.Blob.Size))
	require.NoError(t, err)
	return payload
}

func publicationTwoMachineFinding(floor publicationstate.Floor, view publicationstate.SuppliedRepositoryView) string {
	if len(view.Snapshots) == 0 {
		return "absent"
	}
	terminal := view.Snapshots[len(view.Snapshots)-1]
	recordCID, err := publication.RecordCID(terminal.Raw)
	if err != nil {
		return "unreadable"
	}
	if !bytes.Equal(recordCID, floor.RecordCID) {
		return "diverges"
	}
	record, err := publication.DecodeSnapshot(terminal.Raw)
	if err != nil {
		return "unreadable"
	}
	if record.Blob.Size != floor.BlobSize {
		return "diverges"
	}
	return "matches"
}

func publicationTwoMachineObservation(view publicationstate.SuppliedRepositoryView) publicationstate.Observation {
	return publicationstate.Observation{
		Origin: view.Origin, SuppliedContext: view.SuppliedContext, Head: view.Head, Snapshots: view.Snapshots,
	}
}

func writePublicationTwoMachineFile(t *testing.T, machine *publicationTwoMachine, content []byte) {
	t.Helper()
	writePublicationTwoMachineFileAt(t, filepath.Join(machine.selected, publicationTwoMachineTrackedFile), content)
}

func writePublicationTwoMachineFileAt(t *testing.T, path string, content []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, content, 0o600))
}

func writePublicationTwoMachineFileMode(
	t *testing.T,
	machine *publicationTwoMachine,
	content []byte,
	mode os.FileMode,
) {
	t.Helper()
	path := filepath.Join(machine.selected, publicationTwoMachineTrackedFile)
	require.NoError(t, os.WriteFile(path, content, mode))
	require.NoError(t, os.Chmod(path, mode))
}

func publicationTwoMachineFileMode(t *testing.T, machine *publicationTwoMachine) os.FileMode {
	t.Helper()
	info, err := os.Lstat(filepath.Join(machine.selected, publicationTwoMachineTrackedFile))
	require.NoError(t, err)
	return info.Mode().Perm()
}

func readPublicationTwoMachineFile(t *testing.T, machine *publicationTwoMachine) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(machine.selected, publicationTwoMachineTrackedFile))
	require.NoError(t, err)
	return data
}

func readPublicationTwoMachineSentinel(t *testing.T, machine *publicationTwoMachine) []byte {
	t.Helper()
	data, err := os.ReadFile(machine.sentinel)
	require.NoError(t, err)
	return data
}

func publicationTwoMachineIdentity(t *testing.T, machine *publicationTwoMachine) publicationTwoMachineFileIdentity {
	t.Helper()
	info, err := os.Lstat(filepath.Join(machine.selected, publicationTwoMachineTrackedFile))
	require.NoError(t, err)
	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	return publicationTwoMachineFileIdentity{Inode: stat.Ino, ModTime: info.ModTime(), Size: info.Size()}
}

func readPublicationTwoMachineJournalRows(t *testing.T, directory string) []publicationTwoMachineJournalRow {
	t.Helper()
	databasePath := filepath.Join(directory, "journal.db")
	if _, err := os.Stat(databasePath); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	db, err := sql.Open("sqlite", "file:"+databasePath)
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()
	result, err := db.Query("SELECT entry,state,stage,destination_path,postimage_digest FROM journal ORDER BY entry")
	require.NoError(t, err)
	defer func() { require.NoError(t, result.Close()) }()
	rows := make([]publicationTwoMachineJournalRow, 0)
	for result.Next() {
		var row publicationTwoMachineJournalRow
		var state, stage, destination string
		var postimage []byte
		require.NoError(t, result.Scan(&row.Entry, &state, &stage, &destination, &postimage))
		row.State = publicationstate.JournalState(state)
		row.Stage = publicationstate.JournalStage(stage)
		row.DestinationPath = destination
		if postimage != nil {
			require.Len(t, postimage, sha256.Size)
			copy(row.Postimage[:], postimage)
			row.HasPostimage = true
		}
		rows = append(rows, row)
	}
	require.NoError(t, result.Err())
	return rows
}

func runPublicationTwoMachineCrashHelper(t *testing.T, requestPath string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), publicationTwoMachineCrashWait)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+publicationTwoMachineCrashHelper+"$")
	command.Env = append(os.Environ(),
		publicationTwoMachineCrashMarker+"=1",
		publicationTwoMachineCrashRequestEnv+"="+requestPath,
	)
	output, err := command.CombinedOutput()
	require.NoError(t, ctx.Err(), "publication gate crash helper hung: %s", output)
	var exited *exec.ExitError
	require.ErrorAs(t, err, &exited, "publication gate crash helper did not die: %s", output)
	status, ok := exited.Sys().(syscall.WaitStatus)
	require.True(t, ok, "publication gate crash helper reported no wait status: %s", output)
	require.True(t, status.Signaled(), "publication gate crash helper exited instead of dying: %s", output)
	assert.Equal(
		t,
		syscall.SIGKILL,
		status.Signal(),
		"publication gate crash helper was killed by another signal: %s",
		output,
	)
}

func TestPublicationGateApplyCrashHelper(t *testing.T) {
	if os.Getenv(publicationTwoMachineCrashMarker) != "1" {
		t.Skip("the publication gate crash helper runs only as the re-executed child")
	}
	encoded, err := os.ReadFile(os.Getenv(publicationTwoMachineCrashRequestEnv))
	require.NoError(t, err)
	var input publicationTwoMachineCrashRequest
	require.NoError(t, json.Unmarshal(encoded, &input))
	local, err := service.NewPublicationLocalContext(input.Paths, service.LocalFilesCapture{}, nil)
	require.NoError(t, err)
	journal, err := publicationstate.OpenJournal(input.Paths.PublicationStateDir())
	require.NoError(t, err)
	defer func() { _ = journal.Close() }()
	_, err = service.ApplyPublication(context.Background(), service.PublicationApplyRequest{
		Journal: journal, Vault: input.Vault, FloorRevision: input.FloorRevision,
		Configuration: input.Configuration, BaseSnapshot: input.BaseSnapshot,
		RemoteSnapshot: input.RemoteSnapshot, Roots: input.Roots, Local: local,
		ExpectedPlan: input.ExpectedPlan,
		Barrier: func(phase service.PublicationApplyPhase, _ publicationstate.JournalEntry) error {
			if phase == service.PublicationApplyJournaled {
				_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			}
			return nil
		},
	})
	require.NoError(t, err)
}

func newPublicationTwoMachineProposalStore() *publicationTwoMachineProposalStore {
	return &publicationTwoMachineProposalStore{records: make(map[[16]byte]service.PublicationProposalRecord)}
}

func (store *publicationTwoMachineProposalStore) List(context.Context) ([]service.PublicationProposalRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	records := make([]service.PublicationProposalRecord, 0, len(store.records))
	for _, record := range store.records {
		records = append(records, record)
	}
	return records, nil
}

func (store *publicationTwoMachineProposalStore) Issue(
	_ context.Context,
	record service.PublicationProposalRecord,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.records[record.PublicationID] = record
	return nil
}

func (store *publicationTwoMachineProposalStore) Consume(_ context.Context, publicationID [16]byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, found := store.records[publicationID]
	if !found {
		return service.ErrPublicationProposalAbsent
	}
	record.Consumed = true
	store.records[publicationID] = record
	return nil
}

func (store *publicationTwoMachineProposalStore) Delete(_ context.Context, publicationID [16]byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.records, publicationID)
	return nil
}

func (reviews publicationTwoMachineReviews) Acquire(
	context.Context,
) (publicationstate.LocalReviewContext, config.Token, service.ConfigGuard, error) {
	return reviews.review, config.Token{}, publicationTwoMachineGuard{}, nil
}

func (publicationTwoMachineGuard) Release() {}
