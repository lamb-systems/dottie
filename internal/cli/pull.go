package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	urfave "github.com/urfave/cli/v3"

	"github.com/bluesky-social/indigo/atproto/syntax"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/service"
)

const (
	pullFindingMatches       = "matches"
	pullFindingAbsent        = "absent"
	pullFindingDiverges      = "diverges"
	pullFindingFirstUse      = "first-use"
	pullFindingNoPublication = "no-publication"
	pullFindingUnreadable    = "unreadable"
)

const (
	pullDivergenceRecordCID   = "record_cid"
	pullDivergencePayloadSize = "payload_size"
)

const (
	pullReasonFloorAbsent = "floor_absent"
	pullReasonStoreUnsafe = "unsafe"
	pullReasonIO          = "io"
	pullReasonPosition    = "position"
	pullReasonRecord      = "record"
	pullReasonView        = "view"
	pullReasonHead        = "head"
)

type pullFinding struct {
	Kind   string
	Reason string
}

type pullViewReader interface {
	ReadView(context.Context) (publicationstate.SuppliedRepositoryView, error)
}

type pullRemote struct {
	Reader pullViewReader
	Blob   func(context.Context, publication.SnapshotRecord) ([]byte, error)
	Close  func()
}

type pullRemoteFactory func(context.Context, *urfave.Command, pushSession, publicationstate.Binding) (pullRemote, error)

type pullApplySources struct {
	Paths         platform.Paths
	Configuration config.Config
	Local         *service.PublicationLocalContext
}

type pullApplySourcesFactory func(context.Context, *urfave.Command, publicationstate.Binding) (pullApplySources, error)

type pullApplyMaterial struct {
	Base    model.Snapshot
	Remote  model.Snapshot
	Payload []byte
}

var (
	errPullApplySnapshotUnavailable = errors.New("the provider position holds no snapshot to apply")
	errPullApplySnapshotMoved       = errors.New("the provider position moved while the apply plan was composed")
)

type pullViewReasoner interface {
	Reason() string
}

func runPull(args []string, stdout, stderr io.Writer, openKeyring accountKeyringFactory, env func(string) string) int {
	code := 0
	command := newPullCommand(stdout, stderr, &code,
		productionPushSessionFactory(openKeyring, env), productionPullRemoteFactory(openKeyring, env),
		productionPullVaultFactory(openKeyring, env), productionPullApplySourcesFactory(env),
		productionSessionDIDSource(openKeyring, env), env)
	arguments := append([]string{"dottie"}, args...)
	ctx := context.Background()
	if err := command.Run(ctx, arguments); err != nil && code == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	return code
}

func newPullCommand(
	stdout, stderr io.Writer,
	exitCode *int,
	sessions pushSessionFactory,
	remotes pullRemoteFactory,
	vaults pullVaultFactory,
	applySources pullApplySourcesFactory,
	dids sessionDIDSource,
	env func(string) string,
) *urfave.Command {
	configure := func(command *urfave.Command) *urfave.Command {
		command.Suggest = false
		command.DefaultCommand = ""
		command.UseShortOptionHandling = false
		command.EnableShellCompletion = false
		command.ReadArgsFromStdin = false
		command.OnUsageError = func(_ context.Context, _ *urfave.Command, err error, _ bool) error {
			return urfave.Exit("usage: "+escapeField(err.Error()), 2)
		}
		return command
	}
	pull := configure(&urfave.Command{
		Name: "pull",
		Flags: []urfave.Flag{
			&urfave.StringFlag{Name: "vault", Usage: "local vault fingerprint", OnlyOnce: true},
			&urfave.StringFlag{Name: "did", Usage: "signed-in account DID", OnlyOnce: true},
			&urfave.StringFlag{Name: "handle", Usage: "signed-in account handle", OnlyOnce: true},
			&urfave.StringFlag{Name: "confirm", Usage: "confirmation printed by an earlier apply plan", OnlyOnce: true},
		},
		Action: func(ctx context.Context, command *urfave.Command) error {
			return runPullCommand(ctx, command, sessions, remotes, vaults, applySources, dids, env)
		},
	})
	root := configure(
		&urfave.Command{Name: "dottie", Commands: []*urfave.Command{pull}, Writer: stdout, ErrWriter: stderr},
	)
	root.ExitErrHandler = func(_ context.Context, command *urfave.Command, err error) {
		code := 1
		if exitError, ok := errors.AsType[urfave.ExitCoder](err); ok {
			code = exitError.ExitCode()
		}
		if code != 2 && code != 3 && code != 4 {
			code = 1
		}
		if message := escapeErrorMessage(err.Error()); message != "" {
			fmt.Fprintf(command.ErrWriter, "dottie: %s\n", message)
		}
		*exitCode = code
	}
	return root
}

func runPullCommand(
	ctx context.Context,
	command *urfave.Command,
	sessions pushSessionFactory,
	remotes pullRemoteFactory,
	vaults pullVaultFactory,
	applySources pullApplySourcesFactory,
	dids sessionDIDSource,
	env func(string) string,
) error {
	if command.NArg() != 0 {
		return usageExit("pull takes no positional arguments")
	}
	if command.IsSet("handle") {
		return usageExit("pull requires --did; a handle cannot be resolved before the publication scope check")
	}
	resolved, err := resolveAccountDID(ctx, command, dids)
	if err != nil {
		return accountDIDRefusal("pull", err)
	}
	if err := writeResolvedAccount(command, resolved); err != nil {
		return err
	}
	var confirmation [32]byte
	if command.IsSet("confirm") {
		decoded, err := decodeFixedHex(command.String("confirm"), 32)
		if err != nil {
			return usageExit("--confirm must be the 32-byte hexadecimal confirmation printed by dottie pull")
		}
		copy(confirmation[:], decoded)
	}
	did, err := syntax.ParseDID(command.String("did"))
	if err != nil {
		return usageExit("--did must be a valid account DID")
	}
	paths, err := platform.Resolve(env)
	if err != nil {
		return urfave.Exit("pull refused: the local publication state location is unavailable", 3)
	}
	override := [32]byte{}
	if command.IsSet("vault") {
		parsed, parseErr := parseVaultFingerprint(command.String("vault"))
		if parseErr != nil || parsed == [32]byte{} {
			return usageExit("--vault must be a 32-byte hexadecimal identifier")
		}
		override = parsed
	}
	session, err := sessions(ctx, command)
	if err != nil {
		return urfave.Exit("pull refused: account session is unavailable", 3)
	}
	if err := session.Session.RequirePublicationScopes(); err != nil {
		return urfave.Exit(pullScopeRefusal(err, did.String()), 3)
	}
	if session.Session.DID != did.String() {
		return urfave.Exit(
			"pull refused: the authorized account differs from the --did publication binding; account "+escapeField(
				did.String(),
			)+" is unchanged",
			3,
		)
	}
	vault, err := resolvePublicationVault(ctx, command, "pull", vaults, session, override, paths.PublicationStateDir())
	if err != nil {
		return err
	}
	if err := writeResolvedVault(command, vault); err != nil {
		return err
	}
	binding := publicationstate.Binding{
		AccountDID: did.String(), Backend: publicationstate.BackendPublicRepo,
		Repository: "at://" + did.String(), Vault: vault.Vault,
	}
	store, err := openPublicationPositionStore(paths.PublicationStateDir(), binding)
	if err != nil {
		return pullProvisionRefusal(command, err)
	}
	if err := store.Close(); err != nil {
		return pullProvisionRefusal(command, err)
	}
	inspection, err := publicationstate.Inspect(ctx, paths.PublicationStateDir(), binding)
	if err != nil {
		return pullUnreadableExit(command, pullStoreReason(err))
	}
	remote, err := remotes(ctx, command, session, binding)
	if err != nil {
		return urfave.Exit(pullRemoteFailure(err), 3)
	}
	defer remote.Close()
	view, err := remote.Reader.ReadView(ctx)
	if err != nil {
		return pullViewFailure(command, err)
	}
	finding := pullFinding{Kind: pullFindingFirstUse}
	if inspection.Present {
		finding = comparePullPosition(inspection.Floor, view)
	} else if len(view.Snapshots) == 0 {
		finding = pullFinding{Kind: pullFindingAbsent}
	}
	if finding.Kind == pullFindingUnreadable {
		return pullFindingExit(command, finding)
	}
	if err := writeCommandOutput(command, renderPullFinding(finding)); err != nil {
		return err
	}
	if finding.Kind == pullFindingAbsent {
		return nil
	}
	planRequest := pullApplyPlanRequest{
		Command: command, Binding: binding, Vault: vault.Vault, Floor: inspection.Floor, Present: inspection.Present,
		View: view, Remote: remote, Confirmation: confirmation, Confirmed: command.IsSet("confirm"),
	}
	return runPullApply(ctx, planRequest, applySources)
}

func comparePullPosition(floor publicationstate.Floor, view publicationstate.SuppliedRepositoryView) pullFinding {
	if len(view.Snapshots) == 0 {
		return pullFinding{Kind: pullFindingAbsent}
	}
	terminal := view.Snapshots[len(view.Snapshots)-1]
	recordCID, err := publication.RecordCID(terminal.Raw)
	if err != nil {
		return pullFinding{Kind: pullFindingUnreadable, Reason: pullReasonRecord}
	}
	if !bytes.Equal(recordCID, floor.RecordCID) {
		return pullFinding{Kind: pullFindingDiverges, Reason: pullDivergenceRecordCID}
	}
	record, err := publication.DecodeSnapshot(terminal.Raw)
	if err != nil {
		return pullFinding{Kind: pullFindingUnreadable, Reason: pullReasonRecord}
	}
	if record.Blob.Size != floor.BlobSize {
		return pullFinding{Kind: pullFindingDiverges, Reason: pullDivergencePayloadSize}
	}
	return pullFinding{Kind: pullFindingMatches}
}

func renderPullFinding(finding pullFinding) string {
	if finding.Reason == "" {
		return "pull: " + finding.Kind + "\n"
	}
	return "pull: " + finding.Kind + " (" + escapeField(finding.Reason) + ")\n"
}

func pullFindingExit(command *urfave.Command, finding pullFinding) error {
	if err := writeCommandOutput(command, renderPullFinding(finding)); err != nil {
		return err
	}
	switch finding.Kind {
	case pullFindingMatches, pullFindingAbsent, pullFindingDiverges:
		return nil
	}
	return urfave.Exit("pull is inspection-only: the accepted position cannot be compared; nothing was changed", 3)
}

func pullUnreadableExit(command *urfave.Command, reason string) error {
	return unreadablePositionExit(command, "pull", reason)
}

func pullProvisionRefusal(command *urfave.Command, err error) error {
	reason := pullReasonPosition
	switch {
	case errors.Is(err, errPublicationStoreUnsafe):
		reason = pullReasonStoreUnsafe
	case errors.Is(err, errPublicationStoreCreation):
		reason = pullReasonIO
	default:
		var storeFailure publicationStoreFailure
		if errors.As(err, &storeFailure) {
			reason = string(storeFailure.Reason())
		}
	}
	if writeErr := writeCommandOutput(
		command,
		renderPullFinding(pullFinding{Kind: pullFindingUnreadable, Reason: reason}),
	); writeErr != nil {
		return writeErr
	}
	return urfave.Exit(
		"pull refused: the local position store is unusable and was neither created nor repaired; nothing was changed",
		3,
	)
}

func pullViewFailure(command *urfave.Command, err error) error {
	finding := pullFinding{Kind: pullFindingUnreadable, Reason: pullReasonView}
	var reasoned pullViewReasoner
	if errors.As(err, &reasoned) {
		finding.Reason = reasoned.Reason()
	}
	if writeErr := writeCommandOutput(command, renderPullFinding(finding)); writeErr != nil {
		return writeErr
	}
	if errors.Is(err, atproto.ErrAmbiguousTransport) || errors.Is(err, atproto.ErrRevisionMoving) {
		return urfave.Exit("pull is indeterminate: the provider position read did not resolve; re-run dottie pull", 4)
	}
	return urfave.Exit("pull refused: the provider position cannot be read or validated; nothing was changed", 3)
}

func pullStoreReason(err error) string {
	var storeFailure publicationStoreFailure
	if errors.As(err, &storeFailure) {
		return string(storeFailure.Reason())
	}
	return pullReasonPosition
}

type publicationStageRefusal interface {
	Stage() string
	Reason() string
}

type pullApplyPlanRequest struct {
	Command      *urfave.Command
	Binding      publicationstate.Binding
	Vault        [32]byte
	Floor        publicationstate.Floor
	Present      bool
	View         publicationstate.SuppliedRepositoryView
	Remote       pullRemote
	Confirmation [32]byte
	Confirmed    bool
	RemoteOnly   bool
	Label        string
}

func (input pullApplyPlanRequest) label() string {
	if input.Label == "" {
		return "pull"
	}
	return input.Label
}

type pullApplyPreparation struct {
	Sources     pullApplySources
	Request     service.PublicationApplyRequest
	Material    pullApplyMaterial
	Plan        service.PublicationApplyPlan
	Observation publicationstate.Observation
	Staged      service.PublicationAcceptProposal
	Token       [32]byte
}

func (preparation pullApplyPreparation) applies() bool {
	return preparation.Staged.StateToken != ([32]byte{})
}

func preparePullApply(
	ctx context.Context,
	input pullApplyPlanRequest,
	applySources pullApplySourcesFactory,
) (pullApplyPreparation, error) {
	sources, err := applySources(ctx, input.Command, input.Binding)
	if err != nil {
		return pullApplyPreparation{}, urfave.Exit(
			input.label()+" refused: the local configuration cannot be opened for apply; nothing was changed",
			3,
		)
	}
	preparation := pullApplyPreparation{Sources: sources}
	if len(sources.Configuration.Targets) == 0 {
		return preparation, nil
	}
	if sources.Local == nil {
		return pullApplyPreparation{}, urfave.Exit(
			input.label()+" refused: the local publication context is not available for apply; nothing was changed",
			3,
		)
	}
	roots, err := pullApplyRoots(sources.Configuration, sources.Paths)
	if err != nil {
		return pullApplyPreparation{}, urfave.Exit(
			input.label()+" refused: a selected filesystem target cannot be resolved for apply; nothing was changed",
			3,
		)
	}
	material, err := pullApplySnapshots(ctx, input.Remote, input.View, input.Floor, input.Present)
	if err != nil {
		return pullApplyPreparation{}, pullApplyRemoteFailure(input.label(), err)
	}
	request := service.PublicationApplyRequest{
		Vault: input.Vault, FloorRevision: input.Floor.Revision,
		Configuration: sources.Configuration, BaseSnapshot: material.Base, RemoteSnapshot: material.Remote,
		Roots: roots, Local: sources.Local, ApplyRemoteOnly: input.RemoteOnly,
	}
	plan, err := service.PlanPublicationApply(ctx, request)
	if err != nil {
		return pullApplyPreparation{}, pullApplyRefusal(input.label(), err)
	}
	preparation.Request = request
	preparation.Material = material
	preparation.Plan = plan
	if plan.Changes == 0 {
		return preparation, nil
	}
	observation := pullApplyObservation(input.View)
	staged, err := service.StagePublicationAccept(ctx, service.PublicationAcceptStageRequest{
		Directory: sources.Paths.PublicationStateDir(), Binding: input.Binding,
		FloorRevision: input.Floor.Revision, Observation: observation, Payload: material.Payload,
	})
	if err != nil {
		return pullApplyPreparation{}, pullAcceptStagingFailure(input.label(), err)
	}
	preparation.Observation = observation
	preparation.Staged = staged
	preparation.Token = pullApplyConfirmationToken(
		input.Binding,
		plan.Digest,
		staged.StateToken,
		staged.ObservationDigest,
	)
	return preparation, nil
}

func applyPullPreparation(
	ctx context.Context,
	input pullApplyPlanRequest,
	preparation pullApplyPreparation,
	output string,
) (publicationstate.Floor, string, error) {
	current, err := publicationstate.Inspect(ctx, preparation.Sources.Paths.PublicationStateDir(), input.Binding)
	if err != nil || current.Present != input.Present || current.Floor.Revision != input.Floor.Revision {
		return publicationstate.Floor{}, output, urfave.Exit(
			input.label()+" refused: the accepted floor changed after the apply plan was prepared; re-run dottie "+input.label(),
			3,
		)
	}
	journal, err := publicationstate.OpenJournal(preparation.Sources.Paths.PublicationStateDir())
	if err != nil {
		return publicationstate.Floor{}, output, urfave.Exit(
			input.label()+" refused: the apply journal cannot be opened ("+escapeField(
				pullStoreReason(err),
			)+"); nothing was changed",
			3,
		)
	}
	defer func() { _ = journal.Close() }()
	request := preparation.Request
	request.Journal = journal
	request.ExpectedPlan = preparation.Plan.Digest
	report, applyErr := service.ApplyPublication(ctx, request)
	if applyErr != nil {
		return publicationstate.Floor{}, output, pullApplyFailure(input.Command, input.label(), output, applyErr)
	}
	output += renderPullApplyReport(report)
	accepted, acceptErr := service.AcceptPublication(ctx, service.PublicationAcceptRequest{
		Directory: preparation.Sources.Paths.PublicationStateDir(), Binding: input.Binding,
		Mode: preparation.Staged.Mode, FloorRevision: input.Floor.Revision,
		StateToken: preparation.Staged.StateToken, Confirmation: preparation.Staged.Confirmation,
		Observation: preparation.Observation, Payload: preparation.Material.Payload,
	})
	if acceptErr != nil {
		return publicationstate.Floor{}, output, pullAcceptFailure(input.Command, input.label(), output, acceptErr)
	}
	output += fmt.Sprintf(
		"floor: revision=%d generation=%d sequence=%d\n",
		accepted.Revision,
		accepted.Generation,
		accepted.Sequence,
	)
	return accepted, output, nil
}

func runPullApply(ctx context.Context, input pullApplyPlanRequest, applySources pullApplySourcesFactory) error {
	preparation, err := preparePullApply(ctx, input, applySources)
	if err != nil {
		return err
	}
	if len(preparation.Sources.Configuration.Targets) == 0 {
		return nil
	}
	if !preparation.applies() {
		return nil
	}
	output := renderPullApplyPlan(preparation.Plan)
	output += fmt.Sprintf("confirmation: %x\n", preparation.Token)
	if !input.Confirmed {
		output += fmt.Sprintf("pull: plan only; nothing was applied; repeat with --confirm %x\n", preparation.Token)
		return writeCommandOutput(input.Command, output)
	}
	if preparation.Token != input.Confirmation {
		if writeErr := writeCommandOutput(input.Command, output); writeErr != nil {
			return writeErr
		}
		return urfave.Exit(
			input.label()+" refused: the reviewed apply plan is stale or bound to a different vault; nothing was changed",
			3,
		)
	}
	_, output, err = applyPullPreparation(ctx, input, preparation, output)
	if err != nil {
		return err
	}
	if err := writeCommandOutput(input.Command, output); err != nil {
		return urfave.Exit(input.label()+" applied changes but its result could not be written", 4)
	}
	return nil
}

func pullApplyRoots(configuration config.Config, paths platform.Paths) (map[string]string, error) {
	roots := make(map[string]string, len(configuration.Targets))
	for _, target := range configuration.Targets {
		if target.Source != model.SourceFiles || target.Root == nil {
			continue
		}
		resolved, err := target.ResolvedPath(paths)
		if err != nil {
			return nil, err
		}
		canonical, err := platform.RealPath(resolved)
		if err != nil {
			return nil, err
		}
		roots[target.ID] = canonical
	}
	return roots, nil
}

func pullApplySnapshots(
	ctx context.Context,
	remote pullRemote,
	view publicationstate.SuppliedRepositoryView,
	floor publicationstate.Floor,
	present bool,
) (pullApplyMaterial, error) {
	if len(view.Snapshots) == 0 || remote.Blob == nil {
		return pullApplyMaterial{}, errPullApplySnapshotUnavailable
	}
	terminal, err := publication.DecodeSnapshot(view.Snapshots[len(view.Snapshots)-1].Raw)
	if err != nil {
		return pullApplyMaterial{}, errPullApplySnapshotUnavailable
	}
	payload, err := remote.Blob(ctx, terminal)
	if err != nil {
		return pullApplyMaterial{}, err
	}
	remoteSnapshot, err := publication.DecodePayload(payload, terminal.Blob)
	if err != nil {
		return pullApplyMaterial{}, errPullApplySnapshotUnavailable
	}
	if !present {
		return pullApplyMaterial{
			Base:    model.Snapshot{Version: model.SnapshotVersion},
			Remote:  remoteSnapshot,
			Payload: payload,
		}, nil
	}
	if floor.Sequence >= uint64(len(view.Snapshots)) {
		return pullApplyMaterial{}, errPullApplySnapshotMoved
	}
	block := view.Snapshots[floor.Sequence]
	baseRecord, err := publication.DecodeSnapshot(block.Raw)
	if err != nil {
		return pullApplyMaterial{}, errPullApplySnapshotUnavailable
	}
	baseCID, err := publication.RecordCID(block.Raw)
	if err != nil || block.Key != floor.SnapshotKey || !bytes.Equal(baseCID, floor.RecordCID) ||
		!bytes.Equal(baseRecord.Blob.CID, floor.BlobCID) ||
		baseRecord.Blob.Size != floor.BlobSize {
		return pullApplyMaterial{}, errPullApplySnapshotMoved
	}
	basePayload, err := remote.Blob(ctx, baseRecord)
	if err != nil {
		return pullApplyMaterial{}, err
	}
	base, err := publication.DecodePayload(basePayload, baseRecord.Blob)
	if err != nil {
		return pullApplyMaterial{}, errPullApplySnapshotUnavailable
	}
	return pullApplyMaterial{Base: base, Remote: remoteSnapshot, Payload: payload}, nil
}

func pullApplyObservation(view publicationstate.SuppliedRepositoryView) publicationstate.Observation {
	return publicationstate.Observation{
		Origin: view.Origin, SuppliedContext: view.SuppliedContext, Head: view.Head, Snapshots: view.Snapshots,
	}
}

func pullApplyRemoteFailure(label string, err error) error {
	if errors.Is(err, errPullApplySnapshotMoved) || errors.Is(err, errPullApplySnapshotUnavailable) ||
		errors.Is(err, atproto.ErrAmbiguousTransport) ||
		errors.Is(err, atproto.ErrRevisionMoving) {
		return urfave.Exit(
			label+" is indeterminate: the provider position changed or was unavailable while the apply plan was composed; re-run dottie "+label,
			4,
		)
	}
	return urfave.Exit(
		label+" refused: the provider payload for the validated position cannot be read; nothing was changed",
		3,
	)
}

func pullApplyRefusal(label string, err error) error {
	var refusal publicationStageRefusal
	if errors.As(err, &refusal) {
		if refusal.Reason() == "backup_only" {
			return urfave.Exit(
				label+" refused: the effective selection is backup-only; apply never writes or deletes local files for that selection; nothing was changed",
				3,
			)
		}
		return urfave.Exit(
			label+" refused: the apply plan is unusable ("+escapeField(
				refusal.Stage()+"/"+refusal.Reason(),
			)+"); nothing was changed",
			3,
		)
	}
	return urfave.Exit(label+" refused: the apply plan is unusable; nothing was changed", 3)
}

func pullAcceptStagingFailure(label string, err error) error {
	var refusal publicationStageRefusal
	if errors.As(err, &refusal) {
		if refusal.Reason() == "revision_moved" {
			return urfave.Exit(
				label+" refused: the accepted floor changed after the apply plan was prepared; re-run dottie "+label,
				3,
			)
		}
		return urfave.Exit(
			label+" refused: the applied material cannot be staged for accept ("+escapeField(
				refusal.Stage()+"/"+refusal.Reason(),
			)+"); nothing was changed",
			3,
		)
	}
	return urfave.Exit(label+" refused: the applied material cannot be staged for accept; nothing was changed", 3)
}

func pullAcceptFailure(command *urfave.Command, label, output string, err error) error {
	var refusal publicationStageRefusal
	detail := "accept"
	if errors.As(err, &refusal) {
		detail = refusal.Stage() + "/" + refusal.Reason()
	}
	output += label + ": applied but not accepted (" + escapeField(detail) + ")\n"
	if writeErr := writeCommandOutput(command, output); writeErr != nil {
		return writeErr
	}
	unproven := errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	var storeFailure *publicationstate.Error
	if errors.As(err, &storeFailure) && storeFailure.Class() == publicationstate.ErrStorage {
		unproven = true
	}
	if unproven {
		return urfave.Exit(
			label+" did not complete: the apply finished but the accepted floor is not confirmed ("+escapeField(
				detail,
			)+"); re-run dottie "+label,
			4,
		)
	}
	return urfave.Exit(
		label+" did not complete: the apply finished but the accepted floor is unchanged ("+escapeField(
			detail,
		)+"); re-run dottie "+label,
		3,
	)
}

func pullApplyFailure(command *urfave.Command, label, output string, err error) error {
	if writeErr := writeCommandOutput(command, output); writeErr != nil {
		return writeErr
	}
	var refusal publicationStageRefusal
	var blocked *publicationstate.JournalBlockedError
	switch {
	case errors.As(err, &refusal) && refusal.Reason() == "backup_only":
		return urfave.Exit(
			label+" refused: the effective selection is backup-only; apply never writes or deletes local files for that selection; nothing was changed",
			3,
		)
	case errors.As(err, &refusal) && (refusal.Stage() == "apply-mutate" || refusal.Stage() == "apply-observation"):
		return urfave.Exit(
			label+" did not complete: the apply is indeterminate ("+escapeField(
				refusal.Stage()+"/"+refusal.Reason(),
			)+"); re-run dottie "+label+" to resolve the journal",
			4,
		)
	case errors.As(err, &refusal):
		return urfave.Exit(
			label+" refused: the apply was refused ("+escapeField(
				refusal.Stage()+"/"+refusal.Reason(),
			)+"); nothing was changed",
			3,
		)
	case errors.As(err, &blocked):
		return urfave.Exit(
			label+" refused: an earlier apply journal entry still blocks this apply; nothing was changed",
			3,
		)
	}
	var storeFailure publicationStoreFailure
	if errors.As(err, &storeFailure) {
		return urfave.Exit(
			label+" refused: the apply journal cannot be used ("+escapeField(
				string(storeFailure.Reason()),
			)+"); nothing was changed",
			3,
		)
	}
	if errors.Is(err, service.ErrPublicationApply) {
		return urfave.Exit(label+" refused: the apply was refused; nothing was changed", 3)
	}
	return urfave.Exit(label+" did not complete: the apply result is indeterminate; re-run dottie "+label, 4)
}

func renderPullApplyPlan(plan service.PublicationApplyPlan) string {
	var output strings.Builder
	fmt.Fprintf(&output, "apply: changes=%d unchanged=%d\n", plan.Changes, len(plan.Entries)-plan.Changes)
	for _, entry := range plan.Entries {
		switch entry.Operation {
		case service.PublicationApplyWrite:
			fmt.Fprintf(&output, "apply: write %s size=%d\n", escapeField(entry.Path), entry.Size)
		case service.PublicationApplyDelete:
			fmt.Fprintf(&output, "apply: delete %s\n", escapeField(entry.Path))
		}
	}
	return output.String()
}

func renderPullApplyReport(report service.PublicationApplyReport) string {
	return fmt.Sprintf(
		"pull: applied changes=%d unchanged=%d bytes=%d\n",
		report.Applied,
		report.Unchanged,
		report.BytesWritten,
	)
}

func pullApplyConfirmationToken(
	binding publicationstate.Binding,
	plan [32]byte,
	stateToken [32]byte,
	observationDigest [32]byte,
) [32]byte {
	digest := sha256.New()
	var length [4]byte
	writeField := func(value string) {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write([]byte(value))
	}
	writeField("dottie/pull-apply/v2")
	writeField(binding.AccountDID)
	writeField(string(binding.Backend))
	writeField(binding.Repository)
	_, _ = digest.Write(binding.Vault[:])
	_, _ = digest.Write(plan[:])
	_, _ = digest.Write(stateToken[:])
	_, _ = digest.Write(observationDigest[:])
	var token [32]byte
	copy(token[:], digest.Sum(nil))
	return token
}

func productionPullApplySourcesFactory(env func(string) string) pullApplySourcesFactory {
	return func(ctx context.Context, _ *urfave.Command, _ publicationstate.Binding) (pullApplySources, error) {
		paths, err := platform.Resolve(env)
		if err != nil {
			return pullApplySources{}, err
		}
		configuration, err := service.FileConfigPort{Paths: paths}.Load(ctx)
		if err != nil {
			return pullApplySources{}, err
		}
		if err := configuration.Validate(); err != nil {
			return pullApplySources{}, err
		}
		sources := pullApplySources{Paths: paths, Configuration: configuration}
		if len(configuration.Targets) == 0 {
			return sources, nil
		}
		local, err := service.NewPublicationLocalContext(paths, service.LocalFilesCapture{}, nil)
		if err != nil {
			return pullApplySources{}, err
		}
		sources.Local = local
		return sources, nil
	}
}

func pullScopeRefusal(err error, did string) string {
	if _, ok := errors.AsType[*atproto.PublicationScopeError](err); ok {
		return "pull refused: the account authorization does not cover the v2 publication profile; run dottie account login --handle HANDLE to sign in again and grant it; account " + escapeField(
			did,
		) + " is unchanged"
	}
	return "pull refused: the account session cannot prove the v2 publication scope; account " + escapeField(
		did,
	) + " is unchanged"
}

func pullRemoteFailure(err error) string {
	if errors.Is(err, service.ErrPublicationReaderInput) || errors.Is(err, service.ErrPublicationReaderIdentity) {
		return "pull refused: the account identity or publication binding does not match the authorized session"
	}
	return "pull refused: the account identity or provider transport is unavailable"
}

func productionPullRemoteFactory(openKeyring accountKeyringFactory, env func(string) string) pullRemoteFactory {
	return func(ctx context.Context, _ *urfave.Command, session pushSession, binding publicationstate.Binding) (pullRemote, error) {
		identity, transport, reader, closeResources, err := openAuthorizedPublicationReader(
			ctx,
			openKeyring,
			env,
			session,
		)
		if err != nil {
			return pullRemote{}, err
		}
		fail := func(err error) (pullRemote, error) {
			closeResources()
			return pullRemote{}, err
		}
		adapter, err := service.NewATProtoMaterialTransport(service.ATProtoMaterialConfig{
			Binding: binding, DID: identity.DID, Reader: reader, Transport: transport,
			BlobUploadLimit: int64(publication.MaxBlobBytes),
		})
		if err != nil {
			return fail(err)
		}
		blobs := atproto.VaultReader{Transport: transport, Budgets: atproto.DefaultBudgets()}
		publicationReader, err := service.NewPublicationReader(service.PublicationReaderConfig{
			Binding: binding, DID: identity.DID, Session: session.Session, Adapter: adapter,
			Blobs: blobs,
		})
		if err != nil {
			return fail(err)
		}
		blob := func(ctx context.Context, record publication.SnapshotRecord) ([]byte, error) {
			return blobs.FetchBlob(ctx, identity.DID, record.Blob.CID, int64(record.Blob.Size))
		}
		return pullRemote{Reader: publicationReader, Blob: blob, Close: closeResources}, nil
	}
}

func openAuthorizedPublicationReader(
	ctx context.Context,
	openKeyring accountKeyringFactory,
	env func(string) string,
	session pushSession,
) (atproto.Identity, atproto.Transport, atproto.RevisionReader, func(), error) {
	keyring, err := openKeyring()
	if err != nil {
		return atproto.Identity{}, nil, atproto.RevisionReader{}, func() {}, err
	}
	fail := func(err error) (atproto.Identity, atproto.Transport, atproto.RevisionReader, func(), error) {
		_ = keyring.Close()
		return atproto.Identity{}, nil, atproto.RevisionReader{}, func() {}, err
	}
	client, err := newAuthorizedAccountClient(keyring, env)
	if err != nil {
		return fail(err)
	}
	identity, err := client.Discover(ctx, session.Session.Handle)
	if err != nil || identity.DID != session.Session.DID || identity.DIDDocumentID == "" ||
		len(identity.VerificationMethods) == 0 {
		return fail(errors.New("account identity is unavailable"))
	}
	api, err := atproto.NewSessionAPIClient(client, identity, identity.Handle, session.Session)
	if err != nil {
		return fail(err)
	}
	transport := atproto.NewATClientTransport(api)
	reader := atproto.RevisionReader{
		Transport: transport, Budgets: atproto.DefaultBudgets(), DIDDocumentID: identity.DIDDocumentID,
		VerificationMethods: append([]atproto.VerificationMethod(nil), identity.VerificationMethods...),
	}
	return identity, transport, reader, func() { _ = keyring.Close() }, nil
}
