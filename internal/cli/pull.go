package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strconv"
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
	pullDivergencePayloadForm = "payload_form"
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

const publicationApplyConflictLimit = 20

const (
	pullApplyMaxEntryBytes uint64 = 8 << 20
	pullApplyMaxTotalBytes uint64 = 256 << 20
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
	Entry  func(context.Context, publication.BlobReference) ([]byte, error)
	Close  func()
}

type pullRemoteFactory func(context.Context, *urfave.Command, pushSession, publicationstate.Binding) (pullRemote, error)

type pullApplySources struct {
	Paths         platform.Paths
	Configuration config.Config
	Token         config.Token
	Local         *service.PublicationLocalContext
}

type pullApplySourcesFactory func(context.Context, *urfave.Command, publicationstate.Binding) (pullApplySources, error)

type pullApplyMaterial struct {
	Base        model.Snapshot
	Remote      model.Snapshot
	Payload     []byte
	Form        publication.PayloadForm
	BaseForm    publication.PayloadForm
	Entries     []publication.PayloadEntry
	BaseEntries []publication.PayloadEntry
	Targets     []model.Target
	TargetID    string
	TargetRoot  model.FileRoot
	RecordCID   []byte
	Sequence    uint64
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
		productionPullVaultFactory(openKeyring, env), productionPullApplySourcesFactory(env, manualGNOMESettings()),
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
		Name:                      "pull",
		DisableSliceFlagSeparator: true,
		Flags: []urfave.Flag{
			&urfave.StringFlag{Name: "vault", Usage: "local vault fingerprint", OnlyOnce: true},
			&urfave.StringFlag{Name: "did", Usage: "signed-in account DID", OnlyOnce: true},
			&urfave.StringFlag{Name: "handle", Usage: "signed-in account handle", OnlyOnce: true},
			&urfave.StringFlag{Name: "confirm", Usage: "confirmation printed by an earlier apply plan", OnlyOnce: true},
			&urfave.StringSliceFlag{
				Name: "settings", Usage: "GNOME target and categories to adopt, id=CATEGORY[,CATEGORY]",
			},
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
	settings, err := parsePullSettings(command.StringSlice("settings"))
	if err != nil {
		return err
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
		AcceptPosition: !inspection.Present || finding.Kind == pullFindingDiverges,
		Settings:       settings,
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
	if record.PayloadForm() == publication.PayloadFormFileSet {
		if floor.FileSet == nil || len(floor.BlobCID) != 0 || floor.BlobSize != 0 ||
			len(floor.FileSet.Entries) != len(record.Entries) {
			return pullFinding{Kind: pullFindingDiverges, Reason: pullDivergencePayloadForm}
		}
		for index, entry := range record.Entries {
			reference := floor.FileSet.Entries[index]
			if reference.Path != entry.Path || reference.Size != entry.Size ||
				!bytes.Equal(reference.CID, entry.Blob.CID) {
				return pullFinding{Kind: pullFindingDiverges, Reason: pullDivergencePayloadForm}
			}
		}
		return pullFinding{Kind: pullFindingMatches}
	}
	if floor.FileSet != nil {
		return pullFinding{Kind: pullFindingDiverges, Reason: pullDivergencePayloadForm}
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

type publicationConflictRefusal interface {
	Conflicts() []service.PublicationApplyConflict
}

func writePublicationApplyConflicts(command *urfave.Command, err error) {
	var refusal publicationConflictRefusal
	if !errors.As(err, &refusal) {
		return
	}
	conflicts := refusal.Conflicts()
	if len(conflicts) == 0 {
		return
	}
	shown := conflicts
	if len(shown) > publicationApplyConflictLimit {
		shown = shown[:publicationApplyConflictLimit]
	}
	writer := command.Root().ErrWriter
	for _, conflict := range shown {
		fmt.Fprintf(
			writer,
			"  %s  %s  %s\n",
			escapeField(conflict.TargetID),
			escapeField(conflict.Path),
			escapeField(conflict.Shape),
		)
	}
	if remaining := len(conflicts) - len(shown); remaining > 0 {
		fmt.Fprintf(writer, "  and %d more conflicting entries\n", remaining)
	}
}

type pullApplyPlanRequest struct {
	Command        *urfave.Command
	Binding        publicationstate.Binding
	Vault          [32]byte
	Floor          publicationstate.Floor
	Present        bool
	View           publicationstate.SuppliedRepositoryView
	Remote         pullRemote
	Confirmation   [32]byte
	Confirmed      bool
	RemoteOnly     bool
	AcceptPosition bool
	Label          string
	Settings       []pullSettingsSelection
}

type pullSettingsSelection struct {
	TargetID   string
	Categories []string
}

func (input pullApplyPlanRequest) label() string {
	if input.Label == "" {
		return "pull"
	}
	return input.Label
}

type pullApplyPreparation struct {
	Sources         pullApplySources
	Request         service.PublicationApplyRequest
	Material        pullApplyMaterial
	Plan            service.PublicationApplyPlan
	Observation     publicationstate.Observation
	Staged          service.PublicationAcceptProposal
	Adoption        *pullApplyTargetAdoption
	Token           [32]byte
	AcceptOnly      bool
	AdoptionPending bool
	Adopted         bool
	Skipped         []string
}

type pullApplyTargetAdoption struct {
	ConfigToken config.Token
	Targets     []config.Target
}

func (preparation pullApplyPreparation) applies() bool {
	return !preparation.AcceptOnly && preparation.Staged.StateToken != ([32]byte{})
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
	if len(sources.Configuration.Targets) == 0 && input.Present {
		return preparation, nil
	}
	material, err := pullApplySnapshots(ctx, input.Remote, input.View, input.Floor, input.Present)
	if err != nil {
		return pullApplyPreparation{}, pullApplyRemoteFailure(input.label(), err)
	}
	configuration, adoption, skipped, err := pullApplyAdoption(sources, material, input)
	if err != nil {
		return pullApplyPreparation{}, err
	}
	preparation.Skipped = skipped
	if adoption != nil {
		preparation.Adoption = adoption
		token := pullAdoptionConfirmationToken(
			input.Binding, input.Floor.Revision, input.Present, material.RecordCID, material.Sequence, adoption,
		)
		if !input.Confirmed || input.Confirmation != token {
			preparation.AdoptionPending = true
			preparation.Token = token
			return preparation, nil
		}
		preparation.Adopted = true
	}
	preparation.Sources.Configuration = configuration
	if len(configuration.Targets) == 0 {
		return pullApplyPreparation{}, urfave.Exit(
			input.label()+" refused: no target is configured and the published position names none to adopt; run dottie targets add or pass --settings; nothing was changed",
			3,
		)
	}
	if sources.Local == nil {
		return pullApplyPreparation{}, urfave.Exit(
			input.label()+" refused: the local publication context is not available for apply; nothing was changed",
			3,
		)
	}
	roots, err := pullApplyRoots(configuration, sources.Paths)
	if err != nil {
		if adoption != nil {
			return pullApplyPreparation{}, urfave.Exit(
				input.label()+" refused: the published target root "+escapeField(pullAdoptionSelector(adoption))+" does not exist or cannot be resolved; create it and re-run; nothing was changed",
				3,
			)
		}
		return pullApplyPreparation{}, urfave.Exit(
			input.label()+" refused: a selected filesystem target cannot be resolved for apply; nothing was changed",
			3,
		)
	}
	if material.Form == publication.PayloadFormFileSet || material.BaseForm == publication.PayloadFormFileSet {
		target, portable, err := service.FileSetPublicationTarget(configuration)
		if err != nil {
			return pullApplyPreparation{}, urfave.Exit(
				input.label()+" refused: a file-set publication requires the sole local files target; nothing was changed",
				3,
			)
		}
		material.TargetID = target.ID
		material.TargetRoot = *portable.Root
		if material.Form == publication.PayloadFormFileSet {
			material.Remote, err = service.ProjectFileSetSnapshot(portable, material.Entries)
			if err != nil {
				return pullApplyPreparation{}, urfave.Exit(
					input.label()+" refused: the file-set publication entries cannot be projected onto the local target; nothing was changed",
					3,
				)
			}
		}
		if input.Present && material.BaseForm == publication.PayloadFormFileSet {
			material.Base, err = service.ProjectFileSetSnapshot(portable, material.BaseEntries)
			if err != nil {
				return pullApplyPreparation{}, urfave.Exit(
					input.label()+" refused: the accepted file-set position cannot be projected onto the local target; nothing was changed",
					3,
				)
			}
		}
	}
	request := service.PublicationApplyRequest{
		Vault: input.Vault, FloorRevision: input.Floor.Revision,
		Configuration: configuration, BaseSnapshot: material.Base, RemoteSnapshot: material.Remote,
		Roots: roots, Local: sources.Local, ApplyRemoteOnly: input.RemoteOnly,
		FileSet: material.Form == publication.PayloadFormFileSet,
	}
	plan, err := service.PlanPublicationApply(ctx, request)
	if err != nil {
		return pullApplyPreparation{}, pullApplyRefusal(input.Command, input.label(), err)
	}
	preparation.Request = request
	preparation.Material = material
	preparation.Plan = plan
	if preparation.Adopted {
		if err := commitPullAdoption(ctx, sources.Paths, adoption); err != nil {
			return pullApplyPreparation{}, err
		}
		reloaded, err := service.FileConfigPort{Paths: sources.Paths}.Snapshot(ctx)
		if err != nil || !pullAdoptionApplied(reloaded.Config, adoption.Targets) {
			return pullApplyPreparation{}, urfave.Exit(
				"pull refused: the configuration does not carry the adopted target; nothing was applied",
				3,
			)
		}
		configuration = reloaded.Config
		preparation.Sources.Configuration = configuration
		request.Configuration = configuration
		preparation.Request = request
	}
	observation := pullApplyObservation(input.View)
	if plan.Changes == 0 {
		if !input.AcceptPosition {
			return preparation, nil
		}
		staged, err := service.StagePublicationAccept(ctx, service.PublicationAcceptStageRequest{
			Directory: sources.Paths.PublicationStateDir(), Binding: input.Binding,
			FloorRevision: input.Floor.Revision, Observation: observation, Payload: material.Payload,
			Entries: material.Entries,
		})
		if err != nil {
			return pullApplyPreparation{}, pullAcceptPositionStagingFailure(input.label(), err)
		}
		preparation.Observation = observation
		preparation.Staged = staged
		preparation.AcceptOnly = true
		preparation.Token = pullAcceptPositionConfirmationToken(
			input.Binding,
			input.Floor.Revision,
			input.Present,
			material.RecordCID,
			material.Sequence,
			staged.ObservationDigest,
			pullApplyTargetBinding{
				TargetID: material.TargetID, Root: material.TargetRoot,
				SelectionRevision: configuration.SelectionRevision,
				ApprovalRevision:  configuration.ApprovalRevision,
			},
		)
		return preparation, nil
	}
	staged, err := service.StagePublicationAccept(ctx, service.PublicationAcceptStageRequest{
		Directory: sources.Paths.PublicationStateDir(), Binding: input.Binding,
		FloorRevision: input.Floor.Revision, Observation: observation, Payload: material.Payload,
		Entries: material.Entries,
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
		pullApplyTargetBinding{
			TargetID: material.TargetID, Root: material.TargetRoot,
			SelectionRevision: configuration.SelectionRevision,
			ApprovalRevision:  configuration.ApprovalRevision,
		},
	)
	return preparation, nil
}

func pullApplyAdoption(
	sources pullApplySources,
	material pullApplyMaterial,
	input pullApplyPlanRequest,
) (config.Config, *pullApplyTargetAdoption, []string, error) {
	if input.Label != "" && input.Label != "pull" {
		return sources.Configuration, nil, nil, nil
	}
	if len(sources.Configuration.Targets) == 0 && material.Form == publication.PayloadFormFileSet {
		return pullAdoptFileSetTarget(sources, material, input)
	}
	if material.Form != publication.PayloadFormPacked {
		return sources.Configuration, nil, nil, nil
	}
	return pullAdoptPackedTargets(sources, material, input)
}

func pullAdoptFileSetTarget(
	sources pullApplySources,
	material pullApplyMaterial,
	input pullApplyPlanRequest,
) (config.Config, *pullApplyTargetAdoption, []string, error) {
	if len(material.Targets) == 0 {
		return sources.Configuration, nil, nil, nil
	}
	if len(material.Targets) != 1 {
		return config.Config{}, nil, nil, pullAdoptionRefusal(
			input, "the file-set publication names more than one target",
		)
	}
	published := material.Targets[0]
	if published.Source != model.SourceFiles || published.Root == nil || published.Validate() != nil {
		return config.Config{}, nil, nil, pullAdoptionRefusal(
			input, "the file-set publication names an unsupported target layout",
		)
	}
	target, err := pullAdoptFilesTarget(sources, published)
	if err != nil {
		return config.Config{}, nil, nil, pullAdoptionFailure(input, err)
	}
	if err := config.CheckAddition(sources.Configuration, sources.Paths, target); err != nil {
		return config.Config{}, nil, nil, pullAdoptionFailure(
			input, fmt.Errorf("the published target %s cannot be adopted (%w)", pullPortableSelector(*published.Root), err),
		)
	}
	next := sources.Configuration
	next.Targets = append(append([]config.Target(nil), sources.Configuration.Targets...), target)
	return next, &pullApplyTargetAdoption{ConfigToken: sources.Token, Targets: []config.Target{target}}, nil, nil
}

func pullAdoptPackedTargets(
	sources pullApplySources,
	material pullApplyMaterial,
	input pullApplyPlanRequest,
) (config.Config, *pullApplyTargetAdoption, []string, error) {
	selected := make(map[string]struct{}, len(input.Settings))
	for _, settings := range input.Settings {
		selected[settings.TargetID] = struct{}{}
		existing, found := pullTargetByID(sources.Configuration, settings.TargetID)
		if found {
			if existing.Source != model.SourceGNOME {
				return config.Config{}, nil, nil, pullAdoptionRefusal(
					input, "target "+escapeField(settings.TargetID)+" is not a settings target",
				)
			}
			policy, err := config.ApprovedGNOMEPolicy(settings.Categories)
			if err != nil {
				return config.Config{}, nil, nil, pullAdoptionFailure(input, err)
			}
			if !samePullGNOMEPolicy(existing.GNOMEPolicy, policy) {
				return config.Config{}, nil, nil, pullAdoptionRefusal(
					input,
					"settings target "+escapeField(settings.TargetID)+" is already configured; run dottie targets approve to change it",
				)
			}
			continue
		}
		if _, ok := pullPublishedTarget(material.Targets, settings.TargetID, model.SourceGNOME); !ok {
			return config.Config{}, nil, nil, pullAdoptionRefusal(
				input, "the published position names no settings target "+escapeField(settings.TargetID),
			)
		}
	}

	configuration := sources.Configuration
	adopted := make([]config.Target, 0, len(material.Targets))
	skipped := make([]string, 0)
	appendTarget := func(target config.Target) error {
		if err := config.CheckAddition(configuration, sources.Paths, target); err != nil {
			return pullAdoptionFailure(
				input, fmt.Errorf("target %s cannot be adopted (%w)", pullTargetSelector(target), err),
			)
		}
		next := configuration
		next.Targets = append(append([]config.Target(nil), configuration.Targets...), target)
		configuration = next
		adopted = append(adopted, target)
		return nil
	}

	for _, published := range material.Targets {
		if published.Source != model.SourceFiles || published.Root == nil || published.Validate() != nil {
			continue
		}
		if pullFilesRootConfigured(sources.Paths, configuration, *published.Root) {
			continue
		}
		selector := pullPortableSelector(*published.Root)
		target, err := pullAdoptFilesTarget(sources, published)
		if err != nil {
			skipped = append(skipped, "target "+escapeField(selector)+" is not configured; create the root and run dottie targets add")
			continue
		}
		if err := appendTarget(target); err != nil {
			skipped = append(skipped, "target "+escapeField(selector)+" is not configured; "+escapeField(err.Error()))
			continue
		}
	}

	for _, settings := range input.Settings {
		if _, found := pullTargetByID(configuration, settings.TargetID); found {
			continue
		}
		published, ok := pullPublishedTarget(material.Targets, settings.TargetID, model.SourceGNOME)
		if !ok {
			continue
		}
		policy, err := config.ApprovedGNOMEPolicy(settings.Categories)
		if err != nil {
			return config.Config{}, nil, nil, pullAdoptionFailure(input, err)
		}
		target := config.Target{
			ID: published.ID, Source: model.SourceGNOME, Mode: config.Review, GNOMEPolicy: &policy,
		}
		if err := appendTarget(target); err != nil {
			return config.Config{}, nil, nil, err
		}
	}

	for _, published := range material.Targets {
		if published.Source != model.SourceGNOME {
			continue
		}
		if _, configured := pullTargetByID(sources.Configuration, published.ID); configured {
			continue
		}
		if _, chosen := selected[published.ID]; chosen {
			continue
		}
		skipped = append(skipped, "settings target "+escapeField(published.ID)+
			" is not configured; pass --settings "+escapeField(published.ID)+"=CATEGORY[,CATEGORY]")
	}
	slices.Sort(skipped)

	if len(adopted) == 0 {
		return sources.Configuration, nil, skipped, nil
	}
	return configuration, &pullApplyTargetAdoption{ConfigToken: sources.Token, Targets: adopted}, skipped, nil
}

func pullAdoptFilesTarget(sources pullApplySources, published model.Target) (config.Target, error) {
	selector := pullPortableSelector(*published.Root)
	provisional := config.Target{
		ID: published.ID, Source: model.SourceFiles,
		Root: &config.Root{Base: published.Root.Base, Path: published.Root.Path, Kind: published.Root.Kind},
	}
	absolute, err := provisional.ResolvedPath(sources.Paths)
	if err != nil {
		return config.Target{}, errors.New("the published target " + selector + " cannot be resolved")
	}
	root, err := config.ResolveSelection(sources.Paths, absolute)
	if err != nil {
		return config.Target{}, errors.New(
			"the published target " + selector + " cannot be adopted (" + err.Error() + ")",
		)
	}
	if root.Kind != published.Root.Kind {
		return config.Target{}, errors.New("the published target " + selector + " resolves to a different kind")
	}
	return config.Target{ID: published.ID, Source: model.SourceFiles, Mode: config.Review, Root: &root}, nil
}

func pullFilesRootConfigured(paths platform.Paths, configuration config.Config, published model.FileRoot) bool {
	for _, target := range configuration.Targets {
		if target.Source != model.SourceFiles || target.Root == nil {
			continue
		}
		if target.Root.Base == published.Base && target.Root.Path == published.Path &&
			target.Root.Kind == published.Kind {
			return true
		}
		resolved, err := target.ResolvedPath(paths)
		if err != nil {
			continue
		}
		canonical, err := platform.RealPath(resolved)
		if err != nil {
			continue
		}
		publishedPath, err := platform.RealPath(filepath.Join(rootBasePath(paths, published.Base), published.Path))
		if err != nil || canonical != publishedPath {
			continue
		}
		return true
	}
	return false
}

func rootBasePath(paths platform.Paths, base model.RootBase) string {
	if base == model.RootHome {
		return paths.Home
	}
	return paths.ConfigHome
}

func pullTargetByID(configuration config.Config, id string) (config.Target, bool) {
	for _, target := range configuration.Targets {
		if target.ID == id {
			return target, true
		}
	}
	return config.Target{}, false
}

func pullPublishedTarget(targets []model.Target, id string, source model.SourceKind) (model.Target, bool) {
	for _, target := range targets {
		if target.ID == id && target.Source == source {
			return target, true
		}
	}
	return model.Target{}, false
}

func samePullGNOMEPolicy(existing *config.GNOMEPolicy, wanted config.GNOMEPolicy) bool {
	if existing == nil {
		return false
	}
	categories := append([]string(nil), existing.Categories...)
	slices.Sort(categories)
	return existing.Approval == wanted.Approval &&
		existing.MatrixVersion == wanted.MatrixVersion &&
		existing.KeyDigest == wanted.KeyDigest &&
		slices.Equal(categories, wanted.Categories)
}

func parsePullSettings(values []string) ([]pullSettingsSelection, error) {
	selections := make([]pullSettingsSelection, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		id, list, ok := strings.Cut(value, "=")
		if !ok || id == "" || list == "" {
			return nil, usageExit("--settings must be id=CATEGORY[,CATEGORY]")
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, usageExit("--settings names target " + escapeField(id) + " more than once")
		}
		seen[id] = struct{}{}
		categories := strings.Split(list, ",")
		for _, category := range categories {
			if category == "" {
				return nil, usageExit("--settings must be id=CATEGORY[,CATEGORY]")
			}
		}
		selections = append(selections, pullSettingsSelection{TargetID: id, Categories: categories})
	}
	return selections, nil
}

func pullAdoptionFailure(input pullApplyPlanRequest, err error) error {
	return urfave.Exit(input.label()+" refused: "+escapeField(err.Error())+"; nothing was changed", 3)
}

func pullAdoptionRefusal(input pullApplyPlanRequest, reason string) error {
	return urfave.Exit(input.label()+" refused: "+reason+"; nothing was changed", 3)
}

func pullTargetSelector(target config.Target) string {
	if target.Root == nil {
		return string(target.Source)
	}
	return "files:" + string(target.Root.Base) + "/" + target.Root.Path
}

func pullPortableSelector(root model.FileRoot) string {
	return "files:" + string(root.Base) + "/" + root.Path
}

func pullAdoptionSelector(adoption *pullApplyTargetAdoption) string {
	if adoption == nil || len(adoption.Targets) == 0 {
		return ""
	}
	return pullTargetSelector(adoption.Targets[0])
}

func renderPullApplyAdoption(adoption *pullApplyTargetAdoption) string {
	return renderPullApplyAdoptionVerb(adoption, "create")
}

func renderPullApplyAdoptionCreated(adoption *pullApplyTargetAdoption) string {
	return renderPullApplyAdoptionVerb(adoption, "created")
}

func renderPullApplyAdoptionVerb(adoption *pullApplyTargetAdoption, verb string) string {
	if adoption == nil {
		return ""
	}
	var output strings.Builder
	for _, target := range adoption.Targets {
		if target.Source == model.SourceGNOME {
			output.WriteString("adopt: " + verb + " target " + escapeField(target.ID) + " (gnome, " +
				renderPullGNOMEPolicy(target.GNOMEPolicy) + ")\n")
			continue
		}
		output.WriteString("adopt: " + verb + " target " + escapeField(target.ID) + " (" + escapeField(
			pullTargetSelector(target),
		) + ", " + escapeField(string(target.Root.Kind)) + ", mode " + escapeField(string(target.Mode)) + ")\n")
	}
	return output.String()
}

func renderPullGNOMEPolicy(policy *config.GNOMEPolicy) string {
	if policy == nil {
		return "no policy"
	}
	return "categories=" + escapeField(strings.Join(policy.Categories, ",")) +
		", matrix=" + strconv.FormatUint(uint64(policy.MatrixVersion), 10) +
		", digest=" + escapeField(policy.KeyDigest)
}

func renderPullSkipped(lines []string) string {
	var output strings.Builder
	for _, line := range lines {
		output.WriteString("skip: " + line + "\n")
	}
	return output.String()
}

func commitPullAdoption(ctx context.Context, paths platform.Paths, adoption *pullApplyTargetAdoption) error {
	if adoption == nil {
		return nil
	}
	snapshot, err := service.FileConfigPort{Paths: paths}.Update(
		ctx,
		adoption.ConfigToken,
		func(current config.Config) (config.Config, error) {
			for _, target := range adoption.Targets {
				if err := config.CheckAddition(current, paths, target); err != nil {
					return current, err
				}
				current.Targets = append(current.Targets, target)
			}
			return current, nil
		},
	)
	if err != nil {
		return urfave.Exit(
			"pull refused: the adopted target could not be created ("+escapeField(err.Error())+"); nothing was applied",
			3,
		)
	}
	if !pullAdoptionApplied(snapshot.Config, adoption.Targets) {
		return urfave.Exit("pull refused: the configuration does not carry the adopted target; nothing was applied", 3)
	}
	return nil
}

func pullAdoptionApplied(configuration config.Config, targets []config.Target) bool {
	for _, wanted := range targets {
		found := false
		for _, existing := range configuration.Targets {
			if existing.ID != wanted.ID || existing.Source != wanted.Source || existing.Mode != wanted.Mode {
				continue
			}
			if !samePullRoot(existing.Root, wanted.Root) {
				continue
			}
			if !samePullPolicyPointer(existing.GNOMEPolicy, wanted.GNOMEPolicy) {
				continue
			}
			found = true
			break
		}
		if !found {
			return false
		}
	}
	return true
}

func samePullRoot(existing, wanted *config.Root) bool {
	if existing == nil || wanted == nil {
		return existing == nil && wanted == nil
	}
	return existing.Base == wanted.Base && existing.Path == wanted.Path && existing.Kind == wanted.Kind
}

func samePullPolicyPointer(existing, wanted *config.GNOMEPolicy) bool {
	if existing == nil || wanted == nil {
		return existing == nil && wanted == nil
	}
	return samePullGNOMEPolicy(existing, *wanted)
}

func applyPullPreparation(
	ctx context.Context,
	input pullApplyPlanRequest,
	preparation pullApplyPreparation,
	output string,
) (string, error) {
	current, err := publicationstate.Inspect(ctx, preparation.Sources.Paths.PublicationStateDir(), input.Binding)
	if err != nil || current.Present != input.Present || current.Floor.Revision != input.Floor.Revision {
		return output, urfave.Exit(
			input.label()+" refused: the accepted floor changed after the apply plan was prepared; re-run dottie "+input.label(),
			3,
		)
	}
	journal, err := publicationstate.OpenJournal(preparation.Sources.Paths.PublicationStateDir())
	if err != nil {
		return output, urfave.Exit(
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
		return output, pullApplyFailure(input.Command, input.label(), output, applyErr)
	}
	output += renderPullApplyReport(report)
	accepted, acceptErr := service.AcceptPublication(ctx, service.PublicationAcceptRequest{
		Directory: preparation.Sources.Paths.PublicationStateDir(), Binding: input.Binding,
		Mode: preparation.Staged.Mode, FloorRevision: input.Floor.Revision,
		StateToken: preparation.Staged.StateToken, Confirmation: preparation.Staged.Confirmation,
		Observation: preparation.Observation, Payload: preparation.Material.Payload,
		Entries: preparation.Material.Entries,
	})
	if acceptErr != nil {
		return output, pullAcceptFailure(input.Command, input.label(), output, acceptErr)
	}
	output += fmt.Sprintf(
		"floor: revision=%d generation=%d sequence=%d\n",
		accepted.Revision,
		accepted.Generation,
		accepted.Sequence,
	)
	return output, nil
}

func runPullApply(ctx context.Context, input pullApplyPlanRequest, applySources pullApplySourcesFactory) error {
	preparation, err := preparePullApply(ctx, input, applySources)
	if err != nil {
		return err
	}
	if preparation.AdoptionPending {
		output := renderPullSkipped(preparation.Skipped)
		output += renderPullApplyAdoption(preparation.Adoption)
		output += fmt.Sprintf("confirmation: %x\n", preparation.Token)
		output += fmt.Sprintf(
			"pull: adoption only; nothing local was read or changed; repeat with --confirm %x\n",
			preparation.Token,
		)
		return writeCommandOutput(input.Command, output)
	}
	if preparation.Adopted {
		return writePullAdoptionRun(input, preparation)
	}
	if len(preparation.Sources.Configuration.Targets) == 0 {
		return nil
	}
	if preparation.AcceptOnly {
		return runPullAcceptPosition(ctx, input, preparation)
	}
	if !preparation.applies() {
		if len(preparation.Skipped) != 0 {
			return writeCommandOutput(input.Command, renderPullSkipped(preparation.Skipped))
		}
		return nil
	}
	output := renderPullSkipped(preparation.Skipped) + renderPullApplyPlan(preparation.Plan)
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
	output, err = applyPullPreparation(ctx, input, preparation, output)
	if err != nil {
		return err
	}
	if err := writeCommandOutput(input.Command, output); err != nil {
		return urfave.Exit(input.label()+" applied changes but its result could not be written", 4)
	}
	return nil
}

func writePullAdoptionRun(input pullApplyPlanRequest, preparation pullApplyPreparation) error {
	output := renderPullSkipped(preparation.Skipped)
	output += renderPullApplyAdoptionCreated(preparation.Adoption)
	switch {
	case preparation.AcceptOnly:
		output += renderPullAcceptPosition(preparation.Plan, preparation.Material)
		output += fmt.Sprintf("confirmation: %x\n", preparation.Token)
		output += fmt.Sprintf(
			"pull: acceptance only; nothing was applied; repeat with --confirm %x\n",
			preparation.Token,
		)
	case preparation.applies():
		output += renderPullApplyPlan(preparation.Plan)
		output += fmt.Sprintf("confirmation: %x\n", preparation.Token)
		output += fmt.Sprintf("pull: plan only; nothing was applied; repeat with --confirm %x\n", preparation.Token)
	default:
		output += "pull: matches; the target is now configured; nothing else was changed\n"
	}
	return writeCommandOutput(input.Command, output)
}

func runPullAcceptPosition(ctx context.Context, input pullApplyPlanRequest, preparation pullApplyPreparation) error {
	output := renderPullSkipped(preparation.Skipped)
	output += renderPullAcceptPosition(preparation.Plan, preparation.Material)
	output += fmt.Sprintf("confirmation: %x\n", preparation.Token)
	if !input.Confirmed {
		output += fmt.Sprintf(
			"pull: acceptance only; nothing was applied; repeat with --confirm %x\n",
			preparation.Token,
		)
		return writeCommandOutput(input.Command, output)
	}
	if preparation.Token != input.Confirmation {
		if writeErr := writeCommandOutput(input.Command, output); writeErr != nil {
			return writeErr
		}
		return urfave.Exit(
			"pull refused: the reviewed acceptance is stale or bound to a different observation; nothing was changed",
			3,
		)
	}
	output, err := acceptPullPosition(ctx, input, preparation, output)
	if err != nil {
		return err
	}
	if err := writeCommandOutput(input.Command, output); err != nil {
		return urfave.Exit("pull accepted the position but its result could not be written", 4)
	}
	return nil
}

func acceptPullPosition(
	ctx context.Context,
	input pullApplyPlanRequest,
	preparation pullApplyPreparation,
	output string,
) (string, error) {
	current, err := publicationstate.Inspect(ctx, preparation.Sources.Paths.PublicationStateDir(), input.Binding)
	if err != nil || current.Present != input.Present || current.Floor.Revision != input.Floor.Revision {
		return output, urfave.Exit(
			"pull refused: the accepted floor changed after the acceptance was prepared; re-run dottie pull",
			3,
		)
	}
	accepted, acceptErr := service.AcceptPublication(ctx, service.PublicationAcceptRequest{
		Directory: preparation.Sources.Paths.PublicationStateDir(), Binding: input.Binding,
		Mode: preparation.Staged.Mode, FloorRevision: input.Floor.Revision,
		StateToken: preparation.Staged.StateToken, Confirmation: preparation.Staged.Confirmation,
		Observation: preparation.Observation, Payload: preparation.Material.Payload,
		Entries: preparation.Material.Entries,
	})
	if acceptErr != nil {
		return output, pullAcceptPositionFailure(input.Command, output, acceptErr)
	}
	output += fmt.Sprintf(
		"floor: revision=%d generation=%d sequence=%d\n",
		accepted.Revision,
		accepted.Generation,
		accepted.Sequence,
	)
	return output, nil
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
	if len(view.Snapshots) == 0 {
		return pullApplyMaterial{}, errPullApplySnapshotUnavailable
	}
	terminalBlock := view.Snapshots[len(view.Snapshots)-1]
	terminal, err := publication.DecodeSnapshot(terminalBlock.Raw)
	if err != nil {
		return pullApplyMaterial{}, errPullApplySnapshotUnavailable
	}
	recordCID, err := publication.RecordCID(terminalBlock.Raw)
	if err != nil {
		return pullApplyMaterial{}, errPullApplySnapshotUnavailable
	}
	payload, raw, err := pullApplyResolvedPayload(ctx, remote, terminal)
	if err != nil {
		return pullApplyMaterial{}, err
	}
	targets := payload.Snapshot.Targets
	if payload.Form == publication.PayloadFormFileSet {
		targets = terminal.Targets
	}
	if !present {
		return pullApplyMaterial{
			Base:      model.Snapshot{Version: model.SnapshotVersion},
			Remote:    payload.Snapshot,
			Payload:   raw,
			BaseForm:  publication.PayloadFormPacked,
			Form:      payload.Form,
			Entries:   payload.Entries,
			Targets:   targets,
			RecordCID: recordCID,
			Sequence:  terminal.PublicationSeq,
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
		!pullApplyFloorMatchesRecord(floor, baseRecord) {
		return pullApplyMaterial{}, errPullApplySnapshotMoved
	}
	basePayload, _, err := pullApplyResolvedPayload(ctx, remote, baseRecord)
	if err != nil {
		return pullApplyMaterial{}, err
	}
	return pullApplyMaterial{
		Base:        basePayload.Snapshot,
		Remote:      payload.Snapshot,
		Payload:     raw,
		Form:        payload.Form,
		BaseForm:    basePayload.Form,
		Entries:     payload.Entries,
		BaseEntries: basePayload.Entries,
		Targets:     targets,
		RecordCID:   recordCID,
		Sequence:    terminal.PublicationSeq,
	}, nil
}

func pullApplyResolvedPayload(
	ctx context.Context,
	remote pullRemote,
	record publication.SnapshotRecord,
) (publication.Payload, []byte, error) {
	if record.PayloadForm() == publication.PayloadFormPacked {
		if remote.Blob == nil {
			return publication.Payload{}, nil, errPullApplySnapshotUnavailable
		}
		payload, err := remote.Blob(ctx, record)
		if err != nil {
			return publication.Payload{}, nil, err
		}
		snapshot, err := publication.DecodePayload(payload, record.Blob)
		if err != nil {
			return publication.Payload{}, nil, errPullApplySnapshotUnavailable
		}
		return publication.Payload{Form: publication.PayloadFormPacked, Snapshot: snapshot}, payload, nil
	}
	if remote.Entry == nil {
		return publication.Payload{}, nil, errPullApplySnapshotUnavailable
	}
	limits := publication.PayloadLimits{
		MaxEntries: publication.MaxSnapshotEntries, MaxEntryBytes: pullApplyMaxEntryBytes,
		MaxTotalBytes: pullApplyMaxTotalBytes,
	}
	payload, err := publication.ResolvePayload(record, limits, func(blob publication.BlobReference) ([]byte, error) {
		return remote.Entry(ctx, blob)
	})
	if err != nil {
		return publication.Payload{}, nil, err
	}
	return payload, nil, nil
}

func pullApplyFloorMatchesRecord(floor publicationstate.Floor, record publication.SnapshotRecord) bool {
	if record.PayloadForm() == publication.PayloadFormFileSet {
		if floor.FileSet == nil || len(floor.BlobCID) != 0 || floor.BlobSize != 0 ||
			len(floor.FileSet.Entries) != len(record.Entries) {
			return false
		}
		for index, entry := range record.Entries {
			reference := floor.FileSet.Entries[index]
			if reference.Path != entry.Path || reference.Size != entry.Size ||
				!bytes.Equal(reference.CID, entry.Blob.CID) {
				return false
			}
		}
		return true
	}
	return floor.FileSet == nil && bytes.Equal(floor.BlobCID, record.Blob.CID) &&
		floor.BlobSize == record.Blob.Size
}

func pullApplyObservation(view publicationstate.SuppliedRepositoryView) publicationstate.Observation {
	return publicationstate.Observation{
		Origin: view.Origin, SuppliedContext: view.SuppliedContext, Head: view.Head, Snapshots: view.Snapshots,
	}
}

func pullApplyRemoteFailure(label string, err error) error {
	if errors.Is(err, publication.ErrFileSetPayload) {
		return urfave.Exit(
			label+" refused: the provider position carries a file-set publication that this build cannot apply; nothing was changed",
			3,
		)
	}
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

func pullApplyRefusal(command *urfave.Command, label string, err error) error {
	var refusal publicationStageRefusal
	if errors.As(err, &refusal) {
		if refusal.Reason() == "backup_only" {
			return urfave.Exit(
				label+" refused: the effective selection is backup-only; apply never writes or deletes local files for that selection; nothing was changed",
				3,
			)
		}
		writePublicationApplyConflicts(command, err)
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

func pullAcceptPositionStagingFailure(label string, err error) error {
	var refusal publicationStageRefusal
	if errors.As(err, &refusal) {
		if refusal.Reason() == "revision_moved" {
			return urfave.Exit(
				label+" refused: the accepted floor changed after the reconciliation was prepared; re-run dottie "+label,
				3,
			)
		}
		return urfave.Exit(
			label+" refused: the verified position cannot be staged for acceptance ("+escapeField(
				refusal.Stage()+"/"+refusal.Reason(),
			)+"); nothing was changed",
			3,
		)
	}
	return urfave.Exit(
		label+" refused: the verified position cannot be staged for acceptance; nothing was changed",
		3,
	)
}

func pullAcceptPositionFailure(command *urfave.Command, output string, err error) error {
	var refusal publicationStageRefusal
	detail := "accept"
	if errors.As(err, &refusal) {
		detail = refusal.Stage() + "/" + refusal.Reason()
	}
	output += "pull: not accepted (" + escapeField(detail) + ")\n"
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
			"pull did not complete: the accepted floor is not confirmed ("+escapeField(
				detail,
			)+"); re-run dottie pull",
			4,
		)
	}
	return urfave.Exit(
		"pull did not complete: the accepted floor is unchanged ("+escapeField(detail)+"); re-run dottie pull",
		3,
	)
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
		writePublicationApplyConflicts(command, err)
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
		case service.PublicationApplyMkdir:
			fmt.Fprintf(&output, "apply: mkdir %s\n", escapeField(entry.Path))
		case service.PublicationApplyDelete:
			fmt.Fprintf(&output, "apply: delete %s\n", escapeField(entry.Path))
		case service.PublicationApplyUnchanged:
		}
	}
	return output.String()
}

func renderPullAcceptPosition(plan service.PublicationApplyPlan, material pullApplyMaterial) string {
	return fmt.Sprintf(
		"pull: reconciled changes=0 unchanged=%d; the published position sequence=%d can be adopted without writing files\n",
		len(plan.Entries)-plan.Changes,
		material.Sequence,
	)
}

func renderPullApplyReport(report service.PublicationApplyReport) string {
	return fmt.Sprintf(
		"pull: applied changes=%d unchanged=%d bytes=%d\n",
		report.Applied,
		report.Unchanged,
		report.BytesWritten,
	)
}

type pullApplyTargetBinding struct {
	TargetID          string
	Root              model.FileRoot
	SelectionRevision uint64
	ApprovalRevision  uint64
}

func writePullApplyTargetBinding(digest hashWriter, target pullApplyTargetBinding) {
	if target.TargetID == "" {
		return
	}
	writeField := func(value string) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write([]byte(value))
	}
	_, _ = digest.Write([]byte{1})
	writeField(target.TargetID)
	writeField(string(target.Root.Base))
	writeField(target.Root.Path)
	writeField(string(target.Root.Kind))
	var scratch [8]byte
	binary.BigEndian.PutUint64(scratch[:], target.SelectionRevision)
	_, _ = digest.Write(scratch[:])
	binary.BigEndian.PutUint64(scratch[:], target.ApprovalRevision)
	_, _ = digest.Write(scratch[:])
}

type hashWriter interface {
	Write([]byte) (int, error)
}

func pullApplyConfirmationToken(
	binding publicationstate.Binding,
	plan [32]byte,
	stateToken [32]byte,
	observationDigest [32]byte,
	target pullApplyTargetBinding,
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
	writePullApplyTargetBinding(digest, target)
	var token [32]byte
	copy(token[:], digest.Sum(nil))
	return token
}

func pullAcceptPositionConfirmationToken(
	binding publicationstate.Binding,
	floorRevision uint64,
	present bool,
	recordCID []byte,
	sequence uint64,
	observationDigest [32]byte,
	target pullApplyTargetBinding,
) [32]byte {
	digest := sha256.New()
	var length [4]byte
	writeField := func(value string) {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write([]byte(value))
	}
	var scratch [8]byte
	writeField("dottie/pull-accept-position/v1")
	writeField(binding.AccountDID)
	writeField(string(binding.Backend))
	writeField(binding.Repository)
	_, _ = digest.Write(binding.Vault[:])
	binary.BigEndian.PutUint64(scratch[:], floorRevision)
	_, _ = digest.Write(scratch[:])
	if present {
		_, _ = digest.Write([]byte{1})
	} else {
		_, _ = digest.Write([]byte{0})
	}
	binary.BigEndian.PutUint32(length[:], uint32(len(recordCID)))
	_, _ = digest.Write(length[:])
	_, _ = digest.Write(recordCID)
	binary.BigEndian.PutUint64(scratch[:], sequence)
	_, _ = digest.Write(scratch[:])
	_, _ = digest.Write(observationDigest[:])
	writePullApplyTargetBinding(digest, target)
	var token [32]byte
	copy(token[:], digest.Sum(nil))
	return token
}

func pullAdoptionConfirmationToken(
	binding publicationstate.Binding,
	floorRevision uint64,
	present bool,
	recordCID []byte,
	sequence uint64,
	adoption *pullApplyTargetAdoption,
) [32]byte {
	digest := sha256.New()
	var length [4]byte
	writeField := func(value string) {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write([]byte(value))
	}
	var scratch [8]byte
	writeField("dottie/pull-adopt/v1")
	writeField(binding.AccountDID)
	writeField(string(binding.Backend))
	writeField(binding.Repository)
	_, _ = digest.Write(binding.Vault[:])
	binary.BigEndian.PutUint64(scratch[:], floorRevision)
	_, _ = digest.Write(scratch[:])
	if present {
		_, _ = digest.Write([]byte{1})
	} else {
		_, _ = digest.Write([]byte{0})
	}
	binary.BigEndian.PutUint32(length[:], uint32(len(recordCID)))
	_, _ = digest.Write(length[:])
	_, _ = digest.Write(recordCID)
	binary.BigEndian.PutUint64(scratch[:], sequence)
	_, _ = digest.Write(scratch[:])
	_, _ = digest.Write(adoption.ConfigToken[:])
	for _, target := range adoption.Targets {
		writeField(target.ID)
		writeField(string(target.Source))
		writeField(string(target.Mode))
		if target.Root != nil {
			_, _ = digest.Write([]byte{1})
			writeField(string(target.Root.Base))
			writeField(target.Root.Path)
			writeField(string(target.Root.Kind))
		} else {
			_, _ = digest.Write([]byte{0})
		}
		if target.GNOMEPolicy != nil {
			_, _ = digest.Write([]byte{1})
			writeField(string(target.GNOMEPolicy.Approval))
			writeField(strings.Join(target.GNOMEPolicy.Categories, ","))
			binary.BigEndian.PutUint64(scratch[:], uint64(target.GNOMEPolicy.MatrixVersion))
			_, _ = digest.Write(scratch[:])
			writeField(target.GNOMEPolicy.KeyDigest)
		} else {
			_, _ = digest.Write([]byte{0})
		}
	}
	var token [32]byte
	copy(token[:], digest.Sum(nil))
	return token
}

func productionPullApplySourcesFactory(env func(string) string, settings service.SettingsPort) pullApplySourcesFactory {
	return func(ctx context.Context, _ *urfave.Command, _ publicationstate.Binding) (pullApplySources, error) {
		paths, err := platform.Resolve(env)
		if err != nil {
			return pullApplySources{}, err
		}
		snapshot, err := service.FileConfigPort{Paths: paths}.Snapshot(ctx)
		if err != nil {
			return pullApplySources{}, err
		}
		configuration := snapshot.Config
		if err := configuration.Validate(); err != nil {
			return pullApplySources{}, err
		}
		sources := pullApplySources{Paths: paths, Configuration: configuration, Token: snapshot.Token}
		local, err := service.NewPublicationLocalContext(paths, service.LocalFilesCapture{}, settings)
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
		entry := func(ctx context.Context, reference publication.BlobReference) ([]byte, error) {
			return blobs.FetchBlob(ctx, identity.DID, reference.CID, int64(reference.Size))
		}
		return pullRemote{Reader: publicationReader, Blob: blob, Entry: entry, Close: closeResources}, nil
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
