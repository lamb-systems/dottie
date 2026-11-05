package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
)

type manualFactory func(context.Context, *urfave.Command, bool) (*service.Coordinator, service.VaultSelection, func(), error)

func runManual(args []string, stdout, stderr io.Writer, openKeyring accountKeyringFactory, env func(string) string) int {
	code := 0
	command := newManualCommand(stdout, stderr, &code, func(ctx context.Context, command *urfave.Command, remote bool) (*service.Coordinator, service.VaultSelection, func(), error) {
		return productionManualCoordinator(ctx, command, remote, openKeyring, env)
	})
	arguments := append([]string{"dottie"}, args...)
	ctx := context.Background()
	if err := command.Run(ctx, arguments); err != nil && code == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	return code
}

func newManualCommand(stdout, stderr io.Writer, exitCode *int, factory manualFactory) *urfave.Command {
	remoteFlags := func() []urfave.Flag {
		return []urfave.Flag{
			&urfave.StringFlag{Name: "vault", Usage: "local vault fingerprint", OnlyOnce: true},
			&urfave.StringFlag{Name: "device-id", Usage: "local device identifier", OnlyOnce: true},
			&urfave.StringFlag{Name: "did", Usage: "signed-in account DID", OnlyOnce: true},
			&urfave.StringFlag{Name: "handle", Usage: "signed-in account handle", OnlyOnce: true},
		}
	}
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
	status := configure(&urfave.Command{Name: "status", Action: func(ctx context.Context, command *urfave.Command) error {
		coordinator, _, closeResources, err := factory(ctx, command, false)
		if err != nil {
			return refused(err)
		}
		defer closeResources()
		result, err := coordinator.Status(ctx)
		if err != nil {
			return refused(err)
		}
		return writeCommandOutput(command, renderManualStatus(result))
	}})
	history := configure(&urfave.Command{Name: "history", Flags: remoteFlags(), Action: func(ctx context.Context, command *urfave.Command) error {
		return runManualHistory(ctx, command, factory)
	}})
	pull := configure(&urfave.Command{Name: "pull", Flags: remoteFlags(), Action: func(ctx context.Context, command *urfave.Command) error {
		if err := validateRemoteFlags(command); err != nil {
			return err
		}
		coordinator, selection, closeResources, err := factory(ctx, command, true)
		if err != nil {
			return refused(err)
		}
		defer closeResources()
		result, err := coordinator.Pull(ctx, selection)
		if err != nil {
			return refused(err)
		}
		return writeCommandOutput(command, renderPull(result))
	}})
	preview := configure(&urfave.Command{Name: "preview", Flags: append(remoteFlags(), &urfave.StringFlag{Name: "target", Usage: "selected target ID", OnlyOnce: true}), Action: func(ctx context.Context, command *urfave.Command) error {
		if command.String("target") == "" {
			return usageExit("preview requires --target ID")
		}
		if err := validateRemoteFlags(command); err != nil {
			return err
		}
		coordinator, selection, closeResources, err := factory(ctx, command, true)
		if err != nil {
			return refused(err)
		}
		defer closeResources()
		candidate, err := coordinator.Preview(ctx, selection, command.String("target"))
		if err != nil {
			return refused(err)
		}
		return writeCommandOutput(command, renderCandidate(candidate))
	}})
	restore := configure(&urfave.Command{Name: "restore", Flags: append(remoteFlags(),
		&urfave.StringFlag{Name: "target", Usage: "selected target ID", OnlyOnce: true},
		&urfave.StringFlag{Name: "confirm", Usage: "candidate digest for review-mode apply", OnlyOnce: true},
		&urfave.StringFlag{Name: "archive", Usage: "ciphertext archive source file", OnlyOnce: true},
		&urfave.StringFlag{Name: "kit-file", Usage: "private recovery kit file (mode 0600)", OnlyOnce: true},
		&urfave.StringFlag{Name: "anchor", Usage: "independently supplied recovery anchor fingerprint", OnlyOnce: true},
	), Action: func(ctx context.Context, command *urfave.Command) error {
		if command.NArg() != 0 || command.String("target") == "" {
			return usageExit("restore requires --target ID and takes no positional arguments")
		}
		if command.IsSet("archive") {
			if command.String("archive") == "" || command.String("kit-file") == "" || command.String("anchor") == "" {
				return usageExit("archive restore requires --archive FILE, --kit-file FILE and --anchor HEX")
			}
			if command.IsSet("did") || command.IsSet("handle") {
				return usageExit("--archive is mutually exclusive with --did and --handle")
			}
			if command.IsSet("vault") && command.String("vault") == "" || command.IsSet("device-id") && command.String("device-id") == "" {
				return usageExit("vault selector value is missing")
			}
			anchor, err := parseVaultFingerprint(command.String("anchor"))
			if err != nil {
				return usageExit("--anchor must be a 32-byte hexadecimal fingerprint")
			}
			kit, err := readRecoveryKitFile(command.String("kit-file"))
			if err != nil {
				return urfave.Exit("restore refused: recovery kit file is unavailable or invalid", 3)
			}
			defer clear(kit)
			coordinator, selection, closeResources, err := factory(ctx, command, false)
			if err != nil {
				return refused(err)
			}
			defer closeResources()
			report, err := coordinator.RestoreFromArchive(ctx, service.ArchiveRestoreRequest{
				Selection: selection, Path: command.String("archive"), Anchor: anchor, Kit: kit,
				TargetID: command.String("target"), Confirm: command.String("confirm"),
			})
			if err != nil {
				if len(report.Applied) != 0 || report.Failed != nil {
					if writeErr := writeCommandOutput(command, renderRestore(report)); writeErr != nil {
						return writeErr
					}
					return urfave.Exit("partial restore", 4)
				}
				return refused(err)
			}
			return writeCommandOutput(command, renderRestore(report))
		}
		if command.IsSet("kit-file") || command.IsSet("anchor") {
			return usageExit("--kit-file and --anchor require --archive")
		}
		if err := validateRemoteFlags(command); err != nil {
			return err
		}
		coordinator, selection, closeResources, err := factory(ctx, command, true)
		if err != nil {
			return refused(err)
		}
		defer closeResources()
		report, err := coordinator.Restore(ctx, service.RestoreRequest{Selection: selection, TargetID: command.String("target"), Confirm: command.String("confirm")})
		if err != nil {
			if len(report.Applied) != 0 || report.Failed != nil {
				if writeErr := writeCommandOutput(command, renderRestore(report)); writeErr != nil {
					return writeErr
				}
				return urfave.Exit("partial restore", 4)
			}
			return refused(err)
		}
		return writeCommandOutput(command, renderRestore(report))
	}})
	recoverCommand := configure(&urfave.Command{Name: "recover", Action: func(ctx context.Context, command *urfave.Command) error {
		coordinator, _, closeResources, err := factory(ctx, command, false)
		if err != nil {
			return refused(err)
		}
		defer closeResources()
		report, err := coordinator.Recover(ctx)
		if err != nil {
			return refused(err)
		}
		return writeCommandOutput(command, renderRecovery(report))
	}})
	export := configure(&urfave.Command{Name: "export", Flags: append(remoteFlags(),
		&urfave.StringFlag{Name: "out", Usage: "ciphertext archive output file", OnlyOnce: true},
		&urfave.StringFlag{Name: "kit-file", Usage: "private recovery kit file (mode 0600)", OnlyOnce: true},
		&urfave.StringFlag{Name: "anchor", Usage: "expected recovery anchor fingerprint", OnlyOnce: true},
		&urfave.BoolFlag{Name: "overwrite", Usage: "replace an existing regular archive file", OnlyOnce: true},
	), Action: func(ctx context.Context, command *urfave.Command) error {
		return runManualExport(ctx, command, factory)
	}})
	importArchive := configure(&urfave.Command{Name: "import", Flags: []urfave.Flag{
		&urfave.StringFlag{Name: "archive", Usage: "ciphertext archive file", OnlyOnce: true},
		&urfave.StringFlag{Name: "kit-file", Usage: "private recovery kit file (mode 0600)", OnlyOnce: true},
		&urfave.StringFlag{Name: "anchor", Usage: "independently supplied recovery anchor fingerprint", OnlyOnce: true},
		&urfave.StringFlag{Name: "vault", Usage: "independently supplied vault fingerprint", OnlyOnce: true},
	}, Action: func(ctx context.Context, command *urfave.Command) error {
		return runManualImport(ctx, command, factory)
	}})
	root := configure(&urfave.Command{Name: "dottie", Commands: []*urfave.Command{status, history, preview, pull, restore, recoverCommand, export, importArchive}, Writer: stdout, ErrWriter: stderr})
	root.ExitErrHandler = func(_ context.Context, command *urfave.Command, err error) {
		code := 1
		var exitError urfave.ExitCoder
		if errors.As(err, &exitError) {
			code = exitError.ExitCode()
		}
		if code >= 3 && code <= 4 {
			*exitCode = code
		} else if code == 2 {
			*exitCode = 2
		} else {
			*exitCode = 1
		}
		if message := escapeErrorMessage(err.Error()); message != "" {
			fmt.Fprintf(command.ErrWriter, "dottie: %s\n", message)
		}
	}
	return root
}

func refused(err error) error {
	return urfave.Exit(escapeErrorMessage(err.Error()), 3)
}

func runManualHistory(ctx context.Context, command *urfave.Command, factory manualFactory) error {
	if command.NArg() != 0 {
		return usageExit("history takes no positional arguments")
	}
	remoteRequested := command.IsSet("did") || command.IsSet("handle")
	if remoteRequested {
		if err := validateRemoteFlags(command); err != nil {
			return err
		}
	}
	selection := service.VaultSelection{DeviceID: command.String("device-id")}
	if command.IsSet("vault") {
		vaultID, err := parseVaultFingerprint(command.String("vault"))
		if err != nil {
			return usageExit("--vault must be a 32-byte hexadecimal identifier")
		}
		selection.Vault = vaultID
	}
	if command.IsSet("device-id") && selection.DeviceID == "" {
		return usageExit("device selector value is missing")
	}
	coordinator, _, closeResources, err := factory(ctx, command, false)
	if err != nil {
		return urfave.Exit("history refused: local coordinator unavailable", 3)
	}
	report, err := coordinator.History(ctx, selection, false)
	closeResources()
	if err != nil {
		return urfave.Exit("history refused: local history unavailable", 3)
	}
	if remoteRequested {
		remoteCoordinator, remoteSelection, closeRemote, factoryErr := factory(ctx, command, true)
		if factoryErr != nil {
			report.Remote.Status = historyRemoteFailure(factoryErr)
		} else {
			remoteReport, historyErr := remoteCoordinator.History(ctx, remoteSelection, true)
			closeRemote()
			if historyErr != nil {
				report.Remote.Status = service.HistoryRemoteUnavailable
			} else {
				report.Remote = remoteReport.Remote
			}
		}
	}
	return writeCommandOutput(command, renderHistory(report))
}

func runManualExport(ctx context.Context, command *urfave.Command, factory manualFactory) error {
	if command.NArg() != 0 || command.String("out") == "" || command.String("kit-file") == "" {
		return usageExit("export requires --out and --kit-file")
	}
	if err := validateRemoteFlags(command); err != nil {
		return err
	}
	if command.IsSet("anchor") && command.String("anchor") == "" {
		return usageExit("--anchor requires a value")
	}
	var expectedAnchor [32]byte
	if command.IsSet("anchor") {
		var err error
		expectedAnchor, err = parseVaultFingerprint(command.String("anchor"))
		if err != nil {
			return usageExit("--anchor must be a 32-byte hexadecimal fingerprint")
		}
	}
	if err := checkExportOutput(command.String("out"), command.Bool("overwrite")); err != nil {
		return urfave.Exit(err.Error(), 3)
	}
	outputPath, err := filepath.Abs(command.String("out"))
	if err != nil {
		return urfave.Exit("export refused: output path is unavailable", 3)
	}
	kit, err := readRecoveryKitFile(command.String("kit-file"))
	if err != nil {
		return urfave.Exit("export refused: recovery kit file is unavailable or invalid", 3)
	}
	defer clear(kit)
	coordinator, selection, closeResources, err := factory(ctx, command, true)
	if err != nil {
		return urfave.Exit("export refused: account or local coordinator unavailable", 3)
	}
	defer closeResources()
	localHistory, err := coordinator.History(ctx, selection, false)
	if err != nil {
		return urfave.Exit("export refused: local checkpoint summary unavailable", 3)
	}
	var checkpoint *service.HistoryCheckpointSummary
	for index := range localHistory.Checkpoints {
		if localHistory.Checkpoints[index].Vault == selection.Vault {
			checkpoint = &localHistory.Checkpoints[index]
			break
		}
	}
	if checkpoint == nil {
		return urfave.Exit("export refused: local checkpoint is unavailable", 3)
	}
	if expectedAnchor == ([32]byte{}) {
		expectedAnchor = checkpoint.Anchor
	} else if expectedAnchor != checkpoint.Anchor {
		return urfave.Exit("export refused: expected anchor does not match local checkpoint", 3)
	}
	report, err := coordinator.Export(ctx, service.ExportRequest{
		Selection: selection, ExpectedVault: selection.Vault, ExpectedAnchor: expectedAnchor, Kit: kit, Path: outputPath,
	})
	if err != nil {
		return urfave.Exit("export refused: required verified history or guarded output is unavailable", 3)
	}
	output := renderExportReport(report)
	output += "archive: written atomically with mode 0600\nrecovery kit: not stored or included\ncompleteness: required authenticated closure verified; any optional omissions are listed\n"
	return writeCommandOutput(command, output)
}

func runManualImport(ctx context.Context, command *urfave.Command, factory manualFactory) error {
	if command.NArg() != 0 || command.String("archive") == "" || command.String("kit-file") == "" || command.String("anchor") == "" || command.String("vault") == "" {
		return usageExit("import requires --archive, --kit-file, --anchor and --vault")
	}
	expectedVault, err := parseVaultFingerprint(command.String("vault"))
	if err != nil {
		return usageExit("--vault must be a 32-byte hexadecimal identifier supplied independently of the archive")
	}
	expectedAnchor, err := parseVaultFingerprint(command.String("anchor"))
	if err != nil {
		return usageExit("--anchor must be a 32-byte hexadecimal fingerprint supplied independently of the archive")
	}
	kit, err := readRecoveryKitFile(command.String("kit-file"))
	if err != nil {
		return urfave.Exit("import refused: recovery kit file is unavailable or invalid", 3)
	}
	defer clear(kit)
	coordinator, _, closeResources, err := factory(ctx, command, false)
	if err != nil {
		return urfave.Exit("import refused: validation coordinator unavailable", 3)
	}
	defer closeResources()
	report, err := coordinator.ImportExportArchive(ctx, service.ImportExportRequest{
		Path: command.String("archive"), ExpectedVault: expectedVault, ExpectedAnchor: expectedAnchor, Kit: kit,
	})
	if err != nil {
		switch {
		case errors.Is(err, vault.ErrForeignVault):
			return urfave.Exit("import refused: expected vault does not match archive", 3)
		case errors.Is(err, vault.ErrForeignAnchor):
			return urfave.Exit("import refused: expected anchor does not match archive", 3)
		default:
			return urfave.Exit("import refused: recovery kit, archive version or archive integrity check failed", 3)
		}
	}
	output := "archive validation: successful\n"
	output += fmt.Sprintf("expected vault: %x\ncontained vault: %x\nexpected anchor: %x\ncontained anchor: %x\n", expectedVault, report.VaultID, expectedAnchor, report.Anchor)
	output += renderExportReport(report)
	output += "recovery limits: ciphertext validation does not decrypt content or establish global freshness; export completeness requires retained authenticated history\nimport: validation-only; no state, configuration, target or preference changes\n"
	return writeCommandOutput(command, output)
}

func checkExportOutput(path string, overwrite bool) error {
	if path == "" {
		return errors.New("export output path is required")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("export output cannot be inspected")
	}
	if !overwrite {
		return errors.New("export output already exists; choose another path or pass --overwrite")
	}
	if !info.Mode().IsRegular() {
		return errors.New("export overwrite is limited to regular files")
	}
	return nil
}

func historyRemoteFailure(err error) service.HistoryRemoteStatus {
	if errors.Is(err, atproto.ErrAuthMethodSession) || errors.Is(err, atproto.ErrAuthMethodToken) ||
		errors.Is(err, atproto.ErrSessionUnavailable) || errors.Is(err, atproto.ErrSessionRefreshPending) || errors.Is(err, atproto.ErrSessionNotFound) {
		return service.HistoryRemoteAuthExpired
	}
	return service.HistoryRemoteUnavailable
}

func renderHistory(report service.HistoryReport) string {
	var output strings.Builder
	output.WriteString("local history\n")
	if len(report.Targets) == 0 {
		output.WriteString("no targets or local history\n")
	}
	for _, target := range report.Targets {
		fmt.Fprintf(&output, "target %s\n", escapeField(target.ID))
		fmt.Fprintf(&output, "  journal: total=%d\n", target.JournalCount)
		for _, count := range target.JournalCounts {
			fmt.Fprintf(&output, "  journal state=%s stage=%s count=%d\n", escapeField(count.State), escapeField(count.Stage), count.Count)
		}
		if target.LatestJournalState != "" {
			fmt.Fprintf(&output, "  latest journal: state=%s stage=%s\n", escapeField(target.LatestJournalState), escapeField(target.LatestJournalReason))
		}
		fmt.Fprintf(&output, "  applied base: count=%d", target.AppliedBaseCount)
		if target.AppliedBaseCount > 0 {
			fmt.Fprintf(&output, " latest-recorded-at=%d latest-digest=%s", target.AppliedBaseRecorded, escapeField(target.AppliedBaseDigest))
		}
		output.WriteByte('\n')
	}
	for _, checkpoint := range report.Checkpoints {
		fmt.Fprintf(&output, "checkpoint: vault=%x anchor=%x epoch=%d policy-digest=%x recorded-at=%d\n", checkpoint.Vault, checkpoint.Anchor, checkpoint.Epoch, checkpoint.PolicyDigest, checkpoint.RecordedAt)
	}
	fmt.Fprintf(&output, "remote: %s\n", escapeField(string(report.Remote.Status)))
	if report.Remote.Status == service.HistoryRemoteVerified {
		fmt.Fprintf(&output, "remote head: %s\npublication count: %d\nremote epoch: %d\nremote policy-digest: %x\nfreshness: %s\ncheckpoint status: %s\n",
			escapeField(report.Remote.HeadCID), report.Remote.PublicationCount, report.Remote.Epoch,
			report.Remote.PolicyDigest, escapeField(string(report.Remote.Freshness)), escapeField(string(report.Remote.Currency)))
	} else if report.Remote.Status == service.HistoryRemoteNotRequested {
		output.WriteString("freshness: not-checked\ncheckpoint status: not-checked\n")
	} else {
		output.WriteString("freshness: unavailable\ncheckpoint status: unavailable\n")
	}
	return output.String()
}

func renderExportReport(report service.ExportReport) string {
	var output strings.Builder
	fmt.Fprintf(&output, "positions: %d\nblobs: %d\nomissions: %d\n", 1+len(report.Lineage)+len(report.RecoveryPoints), exportBlobCount(report), len(report.Omissions))
	fmt.Fprintf(&output, "position: current epoch=%d snapshot=%s publications=%d policy-digest=%x\n", report.Current.Epoch, escapeField(report.Current.SnapshotCID), report.Current.PublicationCount, report.Current.PolicyDigest)
	for _, position := range report.Lineage {
		fmt.Fprintf(&output, "position: lineage epoch=%d snapshot=%s publications=%d policy-digest=%x\n", position.Epoch, escapeField(position.SnapshotCID), position.PublicationCount, position.PolicyDigest)
	}
	for _, position := range report.RecoveryPoints {
		fmt.Fprintf(&output, "position: recovery epoch=%d snapshot=%s publications=%d policy-digest=%x\n", position.Epoch, escapeField(position.SnapshotCID), position.PublicationCount, position.PolicyDigest)
	}
	for _, omission := range report.Omissions {
		fmt.Fprintf(&output, "omission: %s\n", escapeField(string(omission)))
	}
	return output.String()
}

func exportBlobCount(report service.ExportReport) int {
	seen := make(map[string]struct{}, 1+len(report.Lineage)+len(report.RecoveryPoints))
	if report.Current.SnapshotCID != "" {
		seen[report.Current.SnapshotCID] = struct{}{}
	}
	for _, position := range append(append([]service.ExportPositionReport(nil), report.Lineage...), report.RecoveryPoints...) {
		if position.SnapshotCID != "" {
			seen[position.SnapshotCID] = struct{}{}
		}
	}
	return len(seen)
}

func validateRemoteFlags(command *urfave.Command) error {
	if command.IsSet("did") == command.IsSet("handle") {
		return usageExit("supply exactly one of --did or --handle")
	}
	if command.IsSet("did") && command.String("did") == "" || command.IsSet("handle") && command.String("handle") == "" {
		return usageExit("account selector value is missing")
	}
	if command.IsSet("vault") && command.String("vault") == "" || command.IsSet("device-id") && command.String("device-id") == "" {
		return usageExit("vault selector value is missing")
	}
	return nil
}

func productionManualCoordinator(ctx context.Context, command *urfave.Command, needsRemote bool, openKeyring accountKeyringFactory, env func(string) string) (*service.Coordinator, service.VaultSelection, func(), error) {
	paths, err := platform.Resolve(env)
	if err != nil {
		return nil, service.VaultSelection{}, func() {}, err
	}
	store, err := state.Open(paths)
	if err != nil {
		return nil, service.VaultSelection{}, func() {}, err
	}
	closeStore := func() { _ = store.Close() }
	configuration := service.FileConfigPort{Paths: paths}
	dependencies := service.Dependencies{Config: configuration, State: store, Settings: manualGNOMESettings(), Paths: paths, Clock: time.Now}
	coordinator, err := service.NewCoordinator(dependencies)
	if err != nil {
		closeStore()
		return nil, service.VaultSelection{}, func() {}, err
	}
	needsDeviceKeys := command.IsSet("archive")
	if !needsRemote && !needsDeviceKeys {
		return coordinator, service.VaultSelection{}, closeStore, nil
	}
	var selection service.VaultSelection
	if command.IsSet("vault") {
		vaultID, parseErr := parseVaultFingerprint(command.String("vault"))
		if parseErr != nil {
			closeStore()
			return nil, selection, func() {}, usageExit("--vault must be a 32-byte hexadecimal identifier")
		}
		selection.Vault = vaultID
	}
	selection.DeviceID = command.String("device-id")
	selection, err = coordinator.ResolveSelection(ctx, selection)
	if err != nil {
		closeStore()
		return nil, selection, func() {}, err
	}
	keyring, err := openKeyring()
	if err != nil {
		closeStore()
		return nil, selection, func() {}, err
	}
	closeAll := func() { _ = keyring.Close(); _ = store.Close() }
	dependencies.DeviceKeys = keyring
	if !needsRemote {
		coordinator, err = service.NewCoordinator(dependencies)
		if err != nil {
			closeAll()
			return nil, selection, func() {}, err
		}
		return coordinator, selection, closeAll, nil
	}
	client, err := newAuthorizedAccountClient(keyring, env)
	if err != nil {
		closeAll()
		return nil, selection, func() {}, err
	}
	var identity atproto.Identity
	if command.IsSet("handle") {
		identity, err = client.Discover(ctx, command.String("handle"))
	} else {
		session, loadErr := client.LoadSession(ctx, command.String("did"))
		if loadErr != nil {
			err = loadErr
		} else {
			identity, err = client.Discover(ctx, session.Handle)
			if err == nil && identity.DID != command.String("did") {
				err = errors.New("discovered identity differs from requested DID")
			}
		}
	}
	if err != nil {
		closeAll()
		return nil, selection, func() {}, err
	}
	if identity.DID == "" {
		closeAll()
		return nil, selection, func() {}, errors.New("account identity is unavailable")
	}
	session, err := client.LoadSession(ctx, identity.DID)
	if err != nil {
		closeAll()
		return nil, selection, func() {}, err
	}
	api, err := atproto.NewSessionAPIClient(client, identity, identity.Handle, session)
	if err != nil {
		closeAll()
		return nil, selection, func() {}, err
	}
	dependencies.Trust = service.StateTrustSource{State: store, Keyring: keyring}
	dependencies.Session = manualReadSession{identity: identity}
	dependencies.Remote = service.VaultReader{Reader: atproto.VaultReader{
		Transport: atproto.NewATClientTransport(api), ObservationStore: store, Budgets: atproto.DefaultBudgets(), Clock: time.Now,
	}}
	coordinator, err = service.NewCoordinator(dependencies)
	if err != nil {
		closeAll()
		return nil, selection, func() {}, err
	}
	return coordinator, selection, closeAll, nil
}

type manualReadSession struct {
	identity atproto.Identity
}

func (session manualReadSession) ReadRequest(_ context.Context, selection service.VaultSelection, device vault.DeviceMaterial, anchor [32]byte, previousPolicy, previousControl []byte) (atproto.ReadRequest, error) {
	if session.identity.DID == "" || session.identity.DIDDocumentID == "" || len(session.identity.VerificationMethods) == 0 {
		return atproto.ReadRequest{}, errors.New("discovered account verification evidence is unavailable")
	}
	return atproto.ReadRequest{
		DID: session.identity.DID, DIDDocumentID: session.identity.DIDDocumentID,
		VerificationMethods: append([]atproto.VerificationMethod(nil), session.identity.VerificationMethods...),
		Vault:               selection.Vault, TrustAnchor: anchor, PreviousPolicy: append([]byte(nil), previousPolicy...),
		PreviousControl: append([]byte(nil), previousControl...), DeviceKeyID: append([]byte(nil), device.KeyID...), DeviceKey: device.Recipient,
	}, nil
}

func newAuthorizedAccountClient(keyring accountKeyring, env func(string) string) (*atproto.Client, error) {
	store, ok := keyring.(atproto.SessionStore)
	if !ok {
		return nil, errors.New("keyring cannot load account sessions")
	}
	return atproto.NewClient(accountClientID, store, atproto.WithSessionLock(accountFileSessionLock(env)))
}

func renderManualStatus(status service.Status) string {
	var output strings.Builder
	for _, target := range status.Targets {
		fmt.Fprintf(&output, "%s\t%s\t%s\t%s\titems=%d", escapeField(target.ID), escapeField(target.Source), escapeField(string(target.Mode)), escapeField(string(target.State)), target.Items)
		if target.Reason != "" {
			fmt.Fprintf(&output, "\treason=%s", escapeField(target.Reason))
		}
		output.WriteByte('\n')
	}
	if len(status.Targets) == 0 {
		output.WriteString("no targets selected\n")
	}
	return output.String()
}

func renderPull(result service.ReadOutcome) string {
	return fmt.Sprintf("read: verified\nepoch: %d\nfreshness: %s\ncheckpoint: %s\nentries: %d\nuntracked: %d\ninspect-only: %t\n", result.Read.EpochSeq, escapeField(string(result.Freshness)), escapeField(string(result.Currency.Outcome)), len(result.Snapshot.Entries), len(result.Untracked), result.InspectOnly)
}

func renderCandidate(candidate service.Candidate) string {
	var output strings.Builder
	fmt.Fprintf(&output, "candidate digest: %s\ncheckpoint: %s\nfreshness: %s\n", candidate.Digest, escapeField(string(candidate.Currency)), escapeField(string(candidate.Freshness)))
	for _, target := range candidate.Preview.Targets {
		fmt.Fprintf(&output, "target %s\n", escapeField(target.ID))
		for _, entry := range target.Entries {
			label := string(entry.Action)
			if label == "" {
				label = string(entry.State)
			}
			fmt.Fprintf(&output, "  %s\t%s\tbytes=%d\treason=%s\n", escapeField(label), escapeField(previewEntryName(entry.Key)), entry.Size, escapeField(string(entry.Reason)))
		}
	}
	return output.String()
}

func renderRestore(report service.RestoreReport) string {
	var output strings.Builder
	if report.Source == "archive" {
		fmt.Fprintf(&output, "source: archive\nrestored position: checkpoint epoch %d\nprovider contacted: %t\narchive may not be the newest state: %t\n", report.PositionEpoch, report.ProviderContacted, report.ArchiveMayNotBeNewest)
	}
	fmt.Fprintf(&output, "candidate digest: %s\napplied: %d\nno actions: %t\nbase recording failed: %t\n", report.CandidateDigest, len(report.Applied), report.NoActions, report.BaseRecordingFailed)
	for _, item := range report.Items {
		fmt.Fprintf(&output, "%s\t%s\n", escapeField(item.Status), escapeField(previewEntryName(item.Key)))
	}
	return output.String()
}

func renderRecovery(report syncengine.RecoveryReport) string {
	var output strings.Builder
	fmt.Fprintf(&output, "recovered entries: %d\n", len(report.Entries))
	for _, entry := range report.Entries {
		fmt.Fprintf(&output, "%s\t%s\t%s\n", escapeField(entry.JournalID), escapeField(entry.Outcome), escapeField(entry.Reason))
	}
	return output.String()
}
