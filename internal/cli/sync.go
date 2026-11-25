package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	urfave "github.com/urfave/cli/v3"

	"github.com/bluesky-social/indigo/atproto/syntax"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
)

var errSyncFloorMismatch = errors.New("the post-pull accepted floor does not match the reviewed provider position")

const planInputVersion uint32 = 1

type planInputBundle struct {
	Version      *uint32                `json:"version"`
	BaseStatus   *syncengine.BaseStatus `json:"base_status"`
	Targets      *[]model.Target        `json:"targets"`
	Base         *[]model.Entry         `json:"base"`
	Observations *[]model.Observation   `json:"observations"`
	Remote       *[]model.Entry         `json:"remote"`
	Coverage     *[]string              `json:"coverage"`
}

type PlanInputError struct {
	Field string
	Kind  string
	Err   error
}

func (e *PlanInputError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("plan input %s field %q", e.Kind, e.Field)
	}
	if e.Kind != "" {
		return "plan input " + e.Kind
	}
	return "invalid plan input"
}

func (e *PlanInputError) Unwrap() error {
	return e.Err
}

func runPlan(args []string, stdout, stderr io.Writer) int {
	exitCode := 0
	root := newPlanCommand(stdout, stderr, &exitCode)
	arguments := append([]string{"plan"}, args...)
	ctx := context.Background()
	if err := root.Run(ctx, arguments); err != nil && exitCode == 0 {
		root.ExitErrHandler(ctx, root, err)
	}
	return exitCode
}

func newPlanCommand(stdout, stderr io.Writer, exitCode *int) *urfave.Command {
	usageHandler := func(_ context.Context, _ *urfave.Command, err error, _ bool) error {
		return urfave.Exit("usage: "+escapePlanField(err.Error()), 2)
	}
	command := &urfave.Command{
		Name: "plan",
		Flags: []urfave.Flag{
			&urfave.StringFlag{Name: "from", Usage: "validated JSON view bundle", OnlyOnce: true},
			&urfave.BoolFlag{Name: "json", Usage: "write the plan as JSON", OnlyOnce: true},
		},
		Action: func(_ context.Context, command *urfave.Command) error {
			if !command.IsSet("from") || command.String("from") == "" {
				return usageExit("dottie plan requires --from <path>")
			}
			preview, err := loadPreview(command.String("from"))
			if err != nil {
				return urfave.Exit(err.Error(), 1)
			}
			var output string
			if command.Bool("json") {
				encoded, err := json.Marshal(preview)
				if err != nil {
					return urfave.Exit("cannot encode plan output", 1)
				}
				output = string(escapeJSONControls(encoded)) + "\n"
			} else {
				output = renderPreview(preview)
			}
			if _, err := io.WriteString(command.Root().Writer, output); err != nil {
				return urfave.Exit("cannot write command output", 1)
			}
			return nil
		},
		Writer:    stdout,
		ErrWriter: stderr,
	}
	command.Suggest = false
	command.DefaultCommand = ""
	command.UseShortOptionHandling = false
	command.EnableShellCompletion = false
	command.ReadArgsFromStdin = false
	command.OnUsageError = usageHandler
	command.ExitErrHandler = func(_ context.Context, command *urfave.Command, err error) {
		code := 1
		if exitError, ok := errors.AsType[urfave.ExitCoder](err); ok {
			code = exitError.ExitCode()
		}
		if code >= 3 || (code != 1 && code != 2) {
			code = 1
		}
		if message := escapeErrorMessage(err.Error()); message != "" {
			fmt.Fprintf(command.ErrWriter, "dottie: %s\n", message)
		}
		*exitCode = code
	}
	return command
}

func loadPreview(path string) (syncengine.Preview, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return syncengine.Preview{}, &PlanInputError{Kind: "cannot read file", Err: err}
	}
	bundle, err := decodePlanInput(data)
	if err != nil {
		return syncengine.Preview{}, err
	}
	bindings := make([]syncengine.TargetBinding, 0, len(*bundle.Targets))
	for _, target := range *bundle.Targets {
		binding, err := syncengine.NewTargetBinding(target)
		if err != nil {
			return syncengine.Preview{}, &PlanInputError{Kind: "contains an invalid target", Err: err}
		}
		bindings = append(bindings, binding)
	}
	local := syncengine.LocalView{Coverage: append([]string(nil), (*bundle.Coverage)...)}
	for _, observation := range *bundle.Observations {
		if err := observation.Validate(); err != nil {
			return syncengine.Preview{}, &PlanInputError{Kind: "contains an invalid observation", Err: err}
		}
		switch observation.State {
		case model.ObservationPresent:
			local.Entries = append(local.Entries, *observation.Entry)
		case model.ObservationMissing:
		case model.ObservationUnknown:
			local.Unknown = append(local.Unknown, observation.Identity)
		case model.ObservationUntracked:
			local.Untracked = append(local.Untracked, observation.Identity)
		default:
			return syncengine.Preview{}, &PlanInputError{Kind: "contains an unsupported observation"}
		}
	}
	plan, err := syncengine.Reconcile(
		syncengine.BaseView{Status: *bundle.BaseStatus, Entries: append([]model.Entry(nil), (*bundle.Base)...)},
		local,
		append([]model.Entry(nil), (*bundle.Remote)...),
		syncengine.Options{Bindings: bindings},
	)
	if err != nil {
		return syncengine.Preview{}, &PlanInputError{Kind: "cannot reconcile supplied views", Err: err}
	}
	preview, err := syncengine.BuildPreview(plan, *bundle.Targets, *bundle.Observations)
	if err != nil {
		return syncengine.Preview{}, &PlanInputError{Kind: "cannot build preview", Err: err}
	}
	return preview, nil
}

func decodePlanInput(data []byte) (planInputBundle, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var bundle planInputBundle
	if err := decoder.Decode(&bundle); err != nil {
		return planInputBundle{}, &PlanInputError{Kind: "is invalid JSON", Err: err}
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return planInputBundle{}, &PlanInputError{Kind: "must contain exactly one JSON value", Err: err}
	}
	if bundle.Version == nil {
		return planInputBundle{}, &PlanInputError{Kind: "is missing required", Field: "version"}
	}
	if *bundle.Version != planInputVersion {
		return planInputBundle{}, &PlanInputError{Kind: "has unsupported version", Field: "version"}
	}
	if bundle.BaseStatus == nil {
		return planInputBundle{}, &PlanInputError{Kind: "is missing required", Field: "base_status"}
	}
	if bundle.Targets == nil {
		return planInputBundle{}, &PlanInputError{Kind: "is missing required", Field: "targets"}
	}
	if bundle.Base == nil {
		return planInputBundle{}, &PlanInputError{Kind: "is missing required", Field: "base"}
	}
	if bundle.Observations == nil {
		return planInputBundle{}, &PlanInputError{Kind: "is missing required", Field: "observations"}
	}
	if bundle.Remote == nil {
		return planInputBundle{}, &PlanInputError{Kind: "is missing required", Field: "remote"}
	}
	if bundle.Coverage == nil {
		return planInputBundle{}, &PlanInputError{Kind: "is missing required", Field: "coverage"}
	}
	return bundle, nil
}

func renderPreview(preview syncengine.Preview) string {
	var output strings.Builder
	for _, target := range preview.Targets {
		fmt.Fprintf(&output, "target %s\n", escapePlanField(target.ID))
		for _, entry := range target.Entries {
			label := string(entry.Action)
			if label == "" {
				label = string(entry.State)
			}
			if label == "" {
				label = "unchanged"
			}
			fmt.Fprintf(
				&output,
				"  %s\t%s\ttransfer-bytes=%d\tsnapshot-bytes=%d",
				escapePlanField(label),
				escapePlanField(previewEntryName(entry.Key)),
				entry.Size,
				entry.SnapshotBytes,
			)
			if entry.Reason != "" {
				fmt.Fprintf(&output, "\treason=%s", escapePlanField(string(entry.Reason)))
			}
			if entry.Detail != "" {
				fmt.Fprintf(&output, "\tdetail=%s", escapePlanField(entry.Detail))
			}
			if entry.Preimage != nil {
				fmt.Fprintf(&output, "\tpreimage=%s/%04o", escapePlanField(entry.Preimage.Digest), entry.Preimage.Mode)
			}
			if len(entry.Risks) != 0 {
				for _, risk := range entry.Risks {
					fmt.Fprintf(&output, "\trisk=%s", escapePlanField(string(risk)))
				}
			}
			output.WriteByte('\n')
		}
	}
	fmt.Fprintf(&output, "transfer bytes=%d\n", preview.TransferBytes)
	if preview.Complete {
		fmt.Fprintf(&output, "resulting snapshot bytes=%d (complete)\n", preview.ResultingSnapshotBytes)
	} else {
		fmt.Fprintf(
			&output,
			"resulting snapshot at least %d bytes, incomplete: %d unresolved\n",
			preview.ResultingSnapshotBytes,
			preview.UnresolvedEntries,
		)
	}
	return output.String()
}

func escapePlanField(value string) string {
	var escaped strings.Builder
	for _, r := range value {
		switch {
		case r == '\\':
			escaped.WriteRune(r)
			escaped.WriteRune(r)
		case unicode.IsControl(r) && r <= 0xff:
			escaped.WriteByte(92)
			escaped.WriteByte('x')
			fmt.Fprintf(&escaped, "%02X", r)
		case unicode.IsControl(r):
			escaped.WriteByte(92)
			escaped.WriteByte('u')
			fmt.Fprintf(&escaped, "%04X", r)
		default:
			escaped.WriteRune(r)
		}
	}
	return escaped.String()
}

func escapeJSONControls(encoded []byte) []byte {
	result := make([]byte, 0, len(encoded))
	inString := false
	escaped := false
	for index := 0; index < len(encoded); {
		current := encoded[index]
		if !inString {
			result = append(result, current)
			if current == '"' {
				inString = true
			}
			index++
			continue
		}
		if escaped {
			result = append(result, current)
			escaped = false
			index++
			continue
		}
		if current == '\\' {
			result = append(result, current)
			escaped = true
			index++
			continue
		}
		if current == '"' {
			result = append(result, current)
			inString = false
			index++
			continue
		}
		if current >= utf8.RuneSelf {
			r, size := utf8.DecodeRune(encoded[index:])
			if unicode.IsControl(r) {
				result = appendJSONUnicodeEscape(result, r)
				index += size
				continue
			}
			result = append(result, encoded[index:index+size]...)
			index += size
			continue
		}
		result = append(result, current)
		index++
	}
	return result
}

func appendJSONUnicodeEscape(destination []byte, value rune) []byte {
	const (
		hexDigits  = "0123456789abcdef"
		nibbleBits = 4
		nibbleMask = 0xf
	)
	destination = append(destination, '\\', 'u')
	destination = append(destination,
		hexDigits[(value>>(3*nibbleBits))&nibbleMask],
		hexDigits[(value>>(2*nibbleBits))&nibbleMask],
		hexDigits[(value>>nibbleBits)&nibbleMask],
		hexDigits[value&nibbleMask],
	)
	return destination
}

func previewEntryName(key model.EntryKey) string {
	if key.Source == model.SourceFiles {
		return key.FilePath
	}
	return key.SchemaID + "@" + key.SettingsPath + "/" + key.SettingKey
}

type syncPushIdentity struct {
	Form           publication.PayloadForm
	PayloadCID     []byte
	PayloadDigest  [32]byte
	PayloadSize    uint64
	EntryCount     int
	EntrySetDigest [32]byte
	Targets        int
	Entries        int
	Review         publicationstate.LocalReviewContext
}

type syncPushPreviewSources struct {
	Binding       publicationstate.Binding
	Coordinator   *service.Coordinator
	Reviews       service.ReviewSource
	Configuration config.Config
	Close         func()
}

type syncPushPreviewFactory func(context.Context, *urfave.Command, publicationstate.Binding) (syncPushPreviewSources, error)

func runSync(args []string, stdout, stderr io.Writer, openKeyring accountKeyringFactory, env func(string) string) int {
	code := 0
	command := newSyncCommand(
		stdout,
		stderr,
		&code,
		productionPushSessionFactory(openKeyring, env),
		productionPullRemoteFactory(openKeyring, env),
		productionPullVaultFactory(
			openKeyring,
			env,
		),
		productionPullApplySourcesFactory(env, manualGNOMESettings()),
		productionSyncPushPreviewFactory(env),
		productionPushSourcesFactory(openKeyring, env),
		productionSessionDIDSource(openKeyring, env),
	)
	arguments := append([]string{"dottie"}, args...)
	ctx := context.Background()
	if err := command.Run(ctx, arguments); err != nil && code == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	return code
}

func newSyncCommand(
	stdout, stderr io.Writer,
	exitCode *int,
	sessions pushSessionFactory,
	remotes pullRemoteFactory,
	vaults pullVaultFactory,
	applySources pullApplySourcesFactory,
	previews syncPushPreviewFactory,
	pushes pushSourcesFactory,
	dids sessionDIDSource,
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
	sync := configure(&urfave.Command{
		Name: "sync",
		Flags: []urfave.Flag{
			&urfave.StringFlag{Name: "vault", Usage: "local vault fingerprint", OnlyOnce: true},
			&urfave.StringFlag{Name: "did", Usage: "signed-in account DID", OnlyOnce: true},
			&urfave.StringFlag{Name: "confirm", Usage: "confirmation printed by an earlier sync plan", OnlyOnce: true},
		},
		Action: func(ctx context.Context, command *urfave.Command) error {
			return runSyncCommand(
				ctx,
				command,
				sessions,
				remotes,
				vaults,
				applySources,
				previews,
				pushes,
				dids,
				os.Getenv,
			)
		},
	})
	root := configure(
		&urfave.Command{Name: "dottie", Commands: []*urfave.Command{sync}, Writer: stdout, ErrWriter: stderr},
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

func runSyncCommand(
	ctx context.Context,
	command *urfave.Command,
	sessions pushSessionFactory,
	remotes pullRemoteFactory,
	vaults pullVaultFactory,
	applySources pullApplySourcesFactory,
	previews syncPushPreviewFactory,
	pushes pushSourcesFactory,
	dids sessionDIDSource,
	env func(string) string,
) error {
	if command.NArg() != 0 {
		return usageExit("sync takes no positional arguments")
	}
	resolved, err := resolveAccountDID(ctx, command, dids)
	if err != nil {
		return accountDIDRefusal("sync", err)
	}
	if err := writeResolvedAccount(command, resolved); err != nil {
		return err
	}
	var confirmation [32]byte
	if command.IsSet("confirm") {
		decoded, err := decodeFixedHex(command.String("confirm"), 32)
		if err != nil {
			return usageExit("--confirm must be the 32-byte hexadecimal confirmation printed by dottie sync")
		}
		copy(confirmation[:], decoded)
	}
	did, err := syntax.ParseDID(command.String("did"))
	if err != nil {
		return usageExit("--did must be a valid account DID")
	}
	paths, err := platform.Resolve(env)
	if err != nil {
		return urfave.Exit("sync refused: the local publication state location is unavailable", 3)
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
		return urfave.Exit("sync refused: account session is unavailable", 3)
	}
	if err := session.Session.RequirePublicationScopes(); err != nil {
		return urfave.Exit(syncScopeRefusal(err, did.String()), 3)
	}
	if session.Session.DID != did.String() {
		return urfave.Exit(
			"sync refused: the authorized account differs from the --did publication binding; account "+escapeField(
				did.String(),
			)+" is unchanged",
			3,
		)
	}
	vault, err := resolvePublicationVault(ctx, command, "sync", vaults, session, override, paths.PublicationStateDir())
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
	inspection, err := publicationstate.Inspect(ctx, paths.PublicationStateDir(), binding)
	if err != nil {
		if publicationPositionAbsent(err) {
			return syncNewcomerRefusal(command, pullStoreReason(err))
		}
		return syncUnreadableExit(command, pullStoreReason(err))
	}
	if !inspection.Present {
		return syncNewcomerRefusal(command, pullReasonFloorAbsent)
	}
	remote, err := remotes(ctx, command, session, binding)
	if err != nil {
		return urfave.Exit(syncRemoteFailure(err), 3)
	}
	defer remote.Close()
	view, err := remote.Reader.ReadView(ctx)
	if err != nil {
		return syncViewFailure(command, err)
	}
	finding := comparePullPosition(inspection.Floor, view)
	if finding.Kind == pullFindingUnreadable {
		return syncFindingExit(command, finding)
	}
	if err := writeCommandOutput(command, renderPullFinding(finding)); err != nil {
		return err
	}
	if finding.Kind == pullFindingAbsent {
		return urfave.Exit("sync refused: the provider position holds no records to reconcile; nothing was changed", 3)
	}
	planRequest := pullApplyPlanRequest{
		Command: command, Binding: binding, Vault: vault.Vault, Floor: inspection.Floor, Present: inspection.Present,
		View: view, Remote: remote, Confirmation: confirmation, Confirmed: command.IsSet("confirm"),
		RemoteOnly: true, Label: "sync",
	}
	preparation, err := preparePullApply(ctx, planRequest, applySources)
	if err != nil {
		return err
	}
	if len(preparation.Sources.Configuration.Targets) == 0 {
		return nil
	}
	if finding.Kind == pullFindingDiverges && preparation.Plan.Changes == 0 {
		return urfave.Exit(
			"sync refused: the provider position differs from the accepted floor but the pull half changes nothing; the accepted floor cannot advance; nothing was changed",
			3,
		)
	}
	identity, err := prepareSyncPushIdentity(
		ctx,
		previews,
		command,
		binding,
		inspection.Floor,
		inspection.Present,
		preparation.Material.Base,
		preparation.Material.Remote,
	)
	if err != nil {
		return err
	}
	viewDigest := syncViewDigest(view)
	token := syncConfirmationToken(
		binding,
		preparation.Plan.Digest,
		preparation.Staged.StateToken,
		preparation.Staged.ObservationDigest,
		viewDigest,
		identity,
	)
	output := renderPullApplyPlan(preparation.Plan)
	output += renderSyncPushPreview(identity)
	output += fmt.Sprintf("confirmation: %x\n", token)
	if !command.IsSet("confirm") {
		output += fmt.Sprintf("sync: plan only; nothing was applied or published; repeat with --confirm %x\n", token)
		return writeCommandOutput(command, output)
	}
	if token != confirmation {
		if writeErr := writeCommandOutput(command, output); writeErr != nil {
			return writeErr
		}
		return urfave.Exit(
			"sync refused: the reviewed pull and push plan is stale or bound to a different vault; nothing was changed",
			3,
		)
	}
	pullApplied := preparation.applies()
	if pullApplied {
		output, err = applyPullPreparation(ctx, planRequest, preparation, output)
		if err != nil {
			return err
		}
	} else {
		output += "pull: no changes\n"
	}
	return runSyncPushHalf(ctx, command, session, binding, view, viewDigest, identity, output, pushes)
}

func runSyncPushHalf(
	ctx context.Context,
	command *urfave.Command,
	session pushSession,
	binding publicationstate.Binding,
	view publicationstate.SuppliedRepositoryView,
	viewDigest [32]byte,
	identity syncPushIdentity,
	output string,
	pushes pushSourcesFactory,
) error {
	sources, err := pushes(ctx, command, session)
	if err != nil {
		if writeErr := writeCommandOutput(command, output); writeErr != nil {
			return writeErr
		}
		return urfave.Exit(
			"sync did not complete: the pull half is settled but the push half cannot be opened; re-run dottie sync",
			4,
		)
	}
	defer sources.Close()
	if sources.Binding != binding {
		if writeErr := writeCommandOutput(command, output); writeErr != nil {
			return writeErr
		}
		return urfave.Exit(
			"sync refused: the push half resolved a different publication binding; nothing was published",
			4,
		)
	}
	position, err := publicationstate.Open(sources.Paths.PublicationStateDir(), binding)
	if err != nil {
		return syncPushRefusal(command, output, "the local publication position store is unusable", "post_pull_store")
	}
	defer func() { _ = position.Close() }()
	floor, present, err := position.Load(ctx)
	if err != nil || !present {
		return syncPushRefusal(command, output, "the post-pull accepted floor cannot be read", "post_pull_floor")
	}
	if err := syncViewMatchesFloor(floor, view); err != nil {
		return syncPushRefusal(
			command,
			output,
			"the accepted floor does not match the reviewed provider position",
			"post_pull_floor_mismatch",
		)
	}
	accepted, err := sources.Reader.ReadAcceptedPayload(ctx)
	if err != nil {
		return syncPushRefusal(command, output, "the provider position cannot be re-read", "post_pull_provider")
	}
	acceptedSnapshot, err := service.PublicationPayloadSnapshot(accepted.Payload, sources.Configuration)
	if err != nil {
		return syncPushRefusal(
			command,
			output,
			"the provider position cannot be projected onto the local target",
			"post_pull_payload_form",
		)
	}
	if syncViewDigest(accepted.View) != viewDigest {
		return syncPushRefusal(
			command,
			output,
			"the provider position moved after the pull half was reviewed",
			"post_pull_provider_moved",
		)
	}
	if err := syncViewMatchesFloor(floor, accepted.View); err != nil {
		return syncPushRefusal(
			command,
			output,
			"the provider position no longer matches the accepted floor",
			"post_pull_provider_moved",
		)
	}
	material, err := position.ReadAcceptedMaterial(ctx, binding, floor)
	if err != nil {
		return syncPushRefusal(command, output, "the accepted material cannot be read", "post_pull_floor")
	}
	baseline, err := syncAcceptedSnapshot(material, sources.Configuration)
	if err != nil {
		return syncPushRefusal(command, output, "the accepted material cannot be decoded", "post_pull_floor")
	}
	publicationID := [16]byte{}
	if _, err := rand.Read(publicationID[:]); err != nil || publicationID == ([16]byte{}) {
		return syncPushRefusal(command, output, "a fresh publication identity is unavailable", "post_pull_candidate")
	}
	snapshot, err := sources.Coordinator.ComposePublicationSyncSnapshot(ctx, service.PublicationSyncSnapshotRequest{
		Configuration:  sources.Configuration,
		FloorSnapshot:  baseline,
		RemoteSnapshot: acceptedSnapshot,
		PublicationID:  publicationID,
	})
	if err != nil {
		return syncPushRefusal(command, output, "the post-pull publication cannot be composed", "post_pull_candidate")
	}
	form, candidateSnapshot, err := service.SelectPublicationForm(sources.Configuration, snapshot, baseline)
	if err != nil {
		return syncPushRefusal(command, output, "the post-pull publication form cannot be selected", "post_pull_candidate")
	}
	candidateMaterial, candidateBlob, err := service.EncodePublicationCandidate(
		binding, form, candidateSnapshot, floor, true, publicationID,
	)
	if err != nil {
		return syncPushRefusal(command, output, "the post-pull publication identity is unavailable", "post_pull_candidate")
	}
	switch form {
	case publication.PayloadFormPacked:
		if digest := syncPayloadDigest(
			candidateMaterial.Payload,
		); digest != identity.PayloadDigest ||
			uint64(len(candidateMaterial.Payload)) != identity.PayloadSize ||
			!bytes.Equal(candidateBlob.CID, identity.PayloadCID) {
			return syncPushRefusal(
				command,
				output,
				"the post-pull publication differs from the reviewed candidate",
				"post_pull_candidate_mismatch",
			)
		}
	case publication.PayloadFormFileSet:
		record, err := publication.DecodeSnapshot(candidateMaterial.SnapshotRecord)
		if err != nil || len(record.Entries) != identity.EntryCount ||
			service.FileSetEntrySetDigest(record.Entries) != identity.EntrySetDigest {
			return syncPushRefusal(
				command,
				output,
				"the post-pull publication differs from the reviewed candidate",
				"post_pull_candidate_mismatch",
			)
		}
	}
	review, _, guard, err := sources.Reviews.Acquire(ctx)
	if err != nil {
		return syncPushRefusal(command, output, "the review identity is unavailable", "post_pull_review")
	}
	guard.Release()
	if review != identity.Review {
		return syncPushRefusal(
			command,
			output,
			"the review identity changed after the sync plan was prepared",
			"post_pull_review_mismatch",
		)
	}
	request := service.PublicationPushRequest{
		Store: position, Transport: sources.Transport, Reader: sources.Reader, Records: sources.Records,
		Binding: binding, Configuration: sources.Configuration, Reviews: sources.Reviews,
		PublicationID: publicationID,
	}
	preparation, prepareErr := sources.Coordinator.PreparePublicationPush(ctx, request)
	if prepareErr != nil {
		return syncPushRefusal(command, output, "the push half could not be prepared", "post_pull_prepare")
	}
	if preparation.NoOp {
		output += "push: no-op\n"
		if preparation.Present {
			output += fmt.Sprintf(
				"floor: revision=%d generation=%d sequence=%d\n",
				preparation.Floor.Revision,
				preparation.Floor.Generation,
				preparation.Floor.Sequence,
			)
		}
		if writeErr := writeCommandOutput(command, output); writeErr != nil {
			return urfave.Exit("sync completed but its result could not be written", 4)
		}
		return nil
	}
	if !syncPreparedMatches(preparation.Record, binding, identity) {
		_ = sources.Records.Delete(ctx, preparation.Record.PublicationID)
		return syncPushRefusal(
			command,
			output,
			"the prepared attempt differs from the reviewed candidate",
			"post_pull_attempt_mismatch",
		)
	}
	result, publishErr := sources.Coordinator.ConfirmPublicationPush(
		ctx,
		request,
		preparation,
		preparation.Proposal.Confirmation,
	)
	status := pushMaterialStatus(publishErr)
	if status == service.StatusCommitted {
		output += fmt.Sprintf(
			"floor: revision=%d generation=%d sequence=%d\n",
			result.Floor.Revision,
			result.Floor.Generation,
			result.Floor.Sequence,
		)
	}
	if publishErr != nil {
		output += renderPushFailure(status, publishErr)
	} else {
		output += renderPush(status)
	}
	if writeErr := writeCommandOutput(command, output); writeErr != nil {
		if status == service.StatusCommitted {
			return urfave.Exit("publication committed but its output could not be written", 4)
		}
		return writeErr
	}
	if status == service.StatusCommitted {
		return nil
	}
	if status == service.StatusRejected || status == service.StatusConflicted {
		return urfave.Exit(
			"sync refused after pull: the push half did not commit; the pull half is settled and nothing was published",
			4,
		)
	}
	return urfave.Exit(
		"sync did not complete: the pull half is settled and the push half is indeterminate; re-run dottie sync",
		4,
	)
}

func syncPushRefusal(command *urfave.Command, output, message, reason string) error {
	if writeErr := writeCommandOutput(command, output); writeErr != nil {
		return writeErr
	}
	return urfave.Exit(
		"sync refused after pull: "+message+" ("+reason+"); the pull half is settled and nothing was published",
		4,
	)
}

func syncViewMatchesFloor(floor publicationstate.Floor, view publicationstate.SuppliedRepositoryView) error {
	if len(view.Snapshots) == 0 {
		return errSyncFloorMismatch
	}
	terminal := view.Snapshots[len(view.Snapshots)-1]
	record, err := publication.DecodeSnapshot(terminal.Raw)
	if err != nil {
		return errSyncFloorMismatch
	}
	cid, err := publication.RecordCID(terminal.Raw)
	if err != nil {
		return errSyncFloorMismatch
	}
	if !bytes.Equal(floor.RecordCID, cid) ||
		floor.Sequence != record.PublicationSeq ||
		floor.SnapshotKey != terminal.Key {
		return errSyncFloorMismatch
	}
	if record.PayloadForm() == publication.PayloadFormFileSet {
		if floor.FileSet == nil || len(floor.BlobCID) != 0 || floor.BlobSize != 0 ||
			len(floor.FileSet.Entries) != len(record.Entries) {
			return errSyncFloorMismatch
		}
		for index, entry := range record.Entries {
			reference := floor.FileSet.Entries[index]
			if reference.Path != entry.Path || reference.Size != entry.Size ||
				!bytes.Equal(reference.CID, entry.Blob.CID) {
				return errSyncFloorMismatch
			}
		}
		return nil
	}
	if floor.FileSet != nil || !bytes.Equal(floor.BlobCID, record.Blob.CID) ||
		floor.BlobSize != record.Blob.Size {
		return errSyncFloorMismatch
	}
	return nil
}

func syncAcceptedSnapshot(
	material publicationstate.AcceptedMaterial,
	configuration config.Config,
) (model.Snapshot, error) {
	snapshot, _, err := service.AcceptedPublicationSnapshot(material, configuration)
	return snapshot, err
}

func syncPayloadDigest(payload []byte) [32]byte {
	return sha256.Sum256(payload)
}

func syncPreparedMatches(
	record service.PublicationProposalRecord,
	binding publicationstate.Binding,
	identity syncPushIdentity,
) bool {
	if record.Binding != binding || record.Review != identity.Review {
		return false
	}
	switch identity.Form {
	case publication.PayloadFormPacked:
		return (record.Form == "" || record.Form == publication.PayloadFormPacked) &&
			bytes.Equal(record.CandidatePayloadCID, identity.PayloadCID) &&
			record.CandidatePayloadSize == identity.PayloadSize
	case publication.PayloadFormFileSet:
		return record.Form == publication.PayloadFormFileSet &&
			record.CandidateEntryCount == identity.EntryCount &&
			record.CandidateEntryDigest == identity.EntrySetDigest
	default:
		return false
	}
}

func renderSyncPushPreview(identity syncPushIdentity) string {
	var output strings.Builder
	fmt.Fprintf(&output, "push: form=%s targets=%d entries=%d\n", identity.Form, identity.Targets, identity.Entries)
	if identity.Form == publication.PayloadFormFileSet {
		fmt.Fprintf(
			&output,
			"push: candidate file-set: entries=%d entry-set=%x\n",
			identity.EntryCount,
			identity.EntrySetDigest,
		)
	} else {
		fmt.Fprintf(&output, "push: candidate payload: %x size=%d\n", identity.PayloadCID, identity.PayloadSize)
	}
	fmt.Fprintf(
		&output,
		"push: review: selection-digest=%x selection-revision=%d approval-digest=%x approval-revision=%d\n",
		identity.Review.SelectionDigest,
		identity.Review.SelectionRevision,
		identity.Review.ApprovalDigest,
		identity.Review.ApprovalRevision,
	)
	return output.String()
}

func prepareSyncPushIdentity(
	ctx context.Context,
	previews syncPushPreviewFactory,
	command *urfave.Command,
	binding publicationstate.Binding,
	position publicationstate.Floor,
	present bool,
	floor, remote model.Snapshot,
) (syncPushIdentity, error) {
	preview, err := previews(ctx, command, binding)
	if err != nil {
		return syncPushIdentity{}, urfave.Exit(
			"sync refused: the local publication configuration is unavailable; nothing was changed",
			3,
		)
	}
	defer preview.Close()
	publicationID := [16]byte{}
	if _, err := rand.Read(publicationID[:]); err != nil || publicationID == ([16]byte{}) {
		return syncPushIdentity{}, urfave.Exit(
			"sync refused: a fresh publication identity is unavailable; nothing was changed",
			3,
		)
	}
	snapshot, err := preview.Coordinator.ComposePublicationSyncSnapshot(ctx, service.PublicationSyncSnapshotRequest{
		Configuration:  preview.Configuration,
		FloorSnapshot:  floor,
		RemoteSnapshot: remote,
		PublicationID:  publicationID,
	})
	if err != nil {
		return syncPushIdentity{}, urfave.Exit(
			"sync refused: the push half cannot be composed from the post-pull state; nothing was changed",
			3,
		)
	}
	form, candidate, err := service.SelectPublicationForm(preview.Configuration, snapshot, floor)
	if err != nil {
		return syncPushIdentity{}, urfave.Exit(
			"sync refused: the post-pull publication form cannot be selected; nothing was changed",
			3,
		)
	}
	material, blob, err := service.EncodePublicationCandidate(
		binding, form, candidate, position, present, publicationID,
	)
	if err != nil {
		return syncPushIdentity{}, urfave.Exit(
			"sync refused: the post-pull publication identity is unavailable; nothing was changed",
			3,
		)
	}
	identity := syncPushIdentity{
		Form:        form,
		PayloadCID:  append([]byte(nil), blob.CID...),
		PayloadSize: blob.Size,
		Targets:     len(candidate.Targets),
		Entries:     len(candidate.Entries),
		Review:      publicationstate.LocalReviewContext{},
	}
	switch form {
	case publication.PayloadFormPacked:
		identity.PayloadDigest = syncPayloadDigest(material.Payload)
	case publication.PayloadFormFileSet:
		record, err := publication.DecodeSnapshot(material.SnapshotRecord)
		if err != nil {
			return syncPushIdentity{}, urfave.Exit(
				"sync refused: the post-pull publication identity is unavailable; nothing was changed",
				3,
			)
		}
		identity.EntryCount = len(record.Entries)
		identity.EntrySetDigest = service.FileSetEntrySetDigest(record.Entries)
	}
	review, _, guard, err := preview.Reviews.Acquire(ctx)
	if err != nil {
		return syncPushIdentity{}, urfave.Exit(
			"sync refused: the review identity is unavailable; nothing was changed",
			3,
		)
	}
	guard.Release()
	identity.Review = review
	return identity, nil
}

func syncConfirmationToken(
	binding publicationstate.Binding,
	plan, stateToken, observationDigest, viewDigest [32]byte,
	identity syncPushIdentity,
) [32]byte {
	digest := sha256.New()
	var length [4]byte
	writeField := func(value string) {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write([]byte(value))
	}
	writeField("dottie/sync/v1")
	writeField(binding.AccountDID)
	writeField(string(binding.Backend))
	writeField(binding.Repository)
	_, _ = digest.Write(binding.Vault[:])
	_, _ = digest.Write(plan[:])
	_, _ = digest.Write(stateToken[:])
	_, _ = digest.Write(observationDigest[:])
	_, _ = digest.Write(viewDigest[:])
	var scratch [8]byte
	if identity.Form == publication.PayloadFormFileSet {
		writeField("dottie/sync/file-set/v1")
		writeField(string(identity.Form))
		binary.BigEndian.PutUint64(scratch[:], uint64(identity.EntryCount))
		_, _ = digest.Write(scratch[:])
		_, _ = digest.Write(identity.EntrySetDigest[:])
	} else {
		_, _ = digest.Write(identity.PayloadDigest[:])
		binary.BigEndian.PutUint64(scratch[:], identity.PayloadSize)
		_, _ = digest.Write(scratch[:])
	}
	_, _ = digest.Write(identity.Review.SelectionDigest[:])
	binary.BigEndian.PutUint64(scratch[:], identity.Review.SelectionRevision)
	_, _ = digest.Write(scratch[:])
	_, _ = digest.Write(identity.Review.ApprovalDigest[:])
	binary.BigEndian.PutUint64(scratch[:], identity.Review.ApprovalRevision)
	_, _ = digest.Write(scratch[:])
	var token [32]byte
	copy(token[:], digest.Sum(nil))
	return token
}

func syncViewDigest(view publicationstate.SuppliedRepositoryView) [32]byte {
	digest := sha256.New()
	var length [4]byte
	writeField := func(value string) {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write([]byte(value))
	}
	writeField("dottie/sync-view/v1")
	writeField(view.Origin.AccountDID)
	writeField(string(view.Origin.Backend))
	writeField(view.Origin.Repository)
	_, _ = digest.Write(view.Origin.Vault[:])
	writeField(string(view.Scope))
	writeField(view.SuppliedContext.RepositoryRevision)
	_, _ = digest.Write(view.SuppliedContext.RepositoryDigest)
	headDigest := sha256.Sum256(view.Head)
	_, _ = digest.Write(headDigest[:])
	for _, block := range view.Snapshots {
		writeField(block.Key)
		rawDigest := sha256.Sum256(block.Raw)
		_, _ = digest.Write(rawDigest[:])
	}
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func productionSyncPushPreviewFactory(env func(string) string) syncPushPreviewFactory {
	return func(ctx context.Context, _ *urfave.Command, binding publicationstate.Binding) (syncPushPreviewSources, error) {
		paths, err := platform.Resolve(env)
		if err != nil {
			return syncPushPreviewSources{}, err
		}
		store, err := state.Open(paths)
		if err != nil {
			return syncPushPreviewSources{}, err
		}
		closeResources := func() { _ = store.Close() }
		configuration := service.FileConfigPort{Paths: paths}
		coordinator, err := service.NewCoordinator(service.Dependencies{
			Config: configuration, State: store, Settings: manualGNOMESettings(), Paths: paths, Clock: time.Now,
		})
		if err != nil {
			closeResources()
			return syncPushPreviewSources{}, err
		}
		selected, err := coordinator.ResolveSelection(ctx, service.VaultSelection{Vault: binding.Vault})
		if err != nil {
			closeResources()
			return syncPushPreviewSources{}, err
		}
		if selected.Vault != binding.Vault {
			closeResources()
			return syncPushPreviewSources{}, errors.New(
				"the local vault selection differs from the publication binding",
			)
		}
		loaded, err := configuration.Load(ctx)
		if err != nil {
			closeResources()
			return syncPushPreviewSources{}, err
		}
		if err := loaded.Validate(); err != nil {
			closeResources()
			return syncPushPreviewSources{}, err
		}
		return syncPushPreviewSources{
			Binding:       binding,
			Coordinator:   coordinator,
			Reviews:       configuration,
			Configuration: loaded,
			Close:         closeResources,
		}, nil
	}
}

func syncScopeRefusal(err error, did string) string {
	if _, ok := errors.AsType[*atproto.PublicationScopeError](err); ok {
		return "sync refused: the account authorization does not cover the v2 publication profile; run dottie account login --handle HANDLE to sign in again and grant it; account " + escapeField(
			did,
		) + " is unchanged"
	}
	return "sync refused: the account session cannot prove the v2 publication scope; account " + escapeField(
		did,
	) + " is unchanged"
}

func syncRemoteFailure(err error) string {
	if errors.Is(err, service.ErrPublicationReaderInput) || errors.Is(err, service.ErrPublicationReaderIdentity) {
		return "sync refused: the account identity or publication binding does not match the authorized session"
	}
	return "sync refused: the account identity or provider transport is unavailable"
}

func syncUnreadableExit(command *urfave.Command, reason string) error {
	return unreadablePositionExit(command, "sync", reason)
}

func syncNewcomerRefusal(command *urfave.Command, reason string) error {
	if err := writeCommandOutput(
		command,
		renderPullFinding(pullFinding{Kind: pullFindingUnreadable, Reason: reason}),
	); err != nil {
		return err
	}
	return urfave.Exit(
		"sync refused: sync needs an accepted publication floor to reconcile against; run dottie pull --confirm first to accept the published position, then run dottie sync; nothing was changed",
		3,
	)
}

func syncFindingExit(command *urfave.Command, finding pullFinding) error {
	if err := writeCommandOutput(command, renderPullFinding(finding)); err != nil {
		return err
	}
	return urfave.Exit(
		"sync refused: the accepted position cannot be compared with the provider; nothing was changed",
		3,
	)
}

func syncViewFailure(command *urfave.Command, err error) error {
	finding := pullFinding{Kind: pullFindingUnreadable, Reason: pullReasonView}
	var reasoned pullViewReasoner
	if errors.As(err, &reasoned) {
		finding.Reason = reasoned.Reason()
	}
	if writeErr := writeCommandOutput(command, renderPullFinding(finding)); writeErr != nil {
		return writeErr
	}
	if errors.Is(err, atproto.ErrAmbiguousTransport) || errors.Is(err, atproto.ErrRevisionMoving) {
		return urfave.Exit("sync is indeterminate: the provider position read did not resolve; re-run dottie sync", 4)
	}
	return urfave.Exit("sync refused: the provider position cannot be read or validated; nothing was changed", 3)
}
