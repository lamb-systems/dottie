package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	urfave "github.com/urfave/cli/v3"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/service"
)

const (
	pullFindingMatches    = "matches"
	pullFindingAbsent     = "absent"
	pullFindingDiverges   = "diverges"
	pullFindingUnreadable = "unreadable"
)

const (
	pullDivergenceRecordCID   = "record_cid"
	pullDivergencePayloadSize = "payload_size"
)

const (
	pullReasonFloorAbsent = "floor_absent"
	pullReasonPosition    = "position"
	pullReasonRecord      = "record"
	pullReasonView        = "view"
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
	Close  func()
}

type pullRemoteFactory func(context.Context, *urfave.Command, pushSession, publicationstate.Binding) (pullRemote, error)

type pullViewReasoner interface {
	Reason() string
}

func runPull(args []string, stdout, stderr io.Writer, openKeyring accountKeyringFactory, env func(string) string) int {
	code := 0
	command := newPullCommand(stdout, stderr, &code,
		productionPushSessionFactory(openKeyring, env), productionPullRemoteFactory(openKeyring, env), env)
	arguments := append([]string{"dottie"}, args...)
	ctx := context.Background()
	if err := command.Run(ctx, arguments); err != nil && code == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	return code
}

func newPullCommand(stdout, stderr io.Writer, exitCode *int, sessions pushSessionFactory, remotes pullRemoteFactory, env func(string) string) *urfave.Command {
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
		},
		Action: func(ctx context.Context, command *urfave.Command) error {
			return runPullCommand(ctx, command, sessions, remotes, env)
		},
	})
	root := configure(&urfave.Command{Name: "dottie", Commands: []*urfave.Command{pull}, Writer: stdout, ErrWriter: stderr})
	root.ExitErrHandler = func(_ context.Context, command *urfave.Command, err error) {
		code := 1
		var exitError urfave.ExitCoder
		if errors.As(err, &exitError) {
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

func runPullCommand(ctx context.Context, command *urfave.Command, sessions pushSessionFactory, remotes pullRemoteFactory, env func(string) string) error {
	if command.NArg() != 0 {
		return usageExit("pull takes no positional arguments")
	}
	if command.String("did") == "" {
		return usageExit("pull requires --did DID")
	}
	if command.IsSet("handle") {
		return usageExit("pull requires --did; a handle cannot be resolved before the publication scope check")
	}
	did, err := syntax.ParseDID(command.String("did"))
	if err != nil {
		return usageExit("--did must be a valid account DID")
	}
	paths, err := platform.Resolve(env)
	if err != nil {
		return urfave.Exit("pull refused: the local publication state location is unavailable", 3)
	}
	vault := [32]byte{}
	if command.IsSet("vault") {
		parsed, parseErr := parseVaultFingerprint(command.String("vault"))
		if parseErr != nil || parsed == [32]byte{} {
			return usageExit("--vault must be a 32-byte hexadecimal identifier")
		}
		vault = parsed
	} else {
		stored, bindingErr := publicationstate.ReadBinding(paths.PublicationStateDir())
		if bindingErr != nil {
			return pullUnreadableExit(command, pullStoreReason(bindingErr))
		}
		vault = stored.Vault
	}
	session, err := sessions(ctx, command)
	if err != nil {
		return urfave.Exit("pull refused: account session is unavailable", 3)
	}
	if err := session.Session.RequirePublicationScopes(); err != nil {
		return urfave.Exit(pullScopeRefusal(err, did.String()), 3)
	}
	if session.Session.DID != did.String() {
		return urfave.Exit("pull refused: the authorized account differs from the --did publication binding; account "+escapeField(did.String())+" is unchanged", 3)
	}
	binding := publicationstate.Binding{
		AccountDID: did.String(), Backend: publicationstate.BackendPublicRepo,
		Repository: "at://" + did.String(), Vault: vault,
	}
	inspection, err := publicationstate.Inspect(ctx, paths.PublicationStateDir(), binding)
	if err != nil {
		return pullUnreadableExit(command, pullStoreReason(err))
	}
	if !inspection.Present {
		return pullUnreadableExit(command, pullReasonFloorAbsent)
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
	return pullFindingExit(command, comparePullPosition(inspection.Floor, view))
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
	if err := writeCommandOutput(command, renderPullFinding(pullFinding{Kind: pullFindingUnreadable, Reason: reason})); err != nil {
		return err
	}
	return urfave.Exit("pull refused: the local position store cannot be inspected read-only; nothing was changed", 3)
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

func pullScopeRefusal(err error, did string) string {
	var scopeError *atproto.PublicationScopeError
	if errors.As(err, &scopeError) {
		return "pull refused: the account authorization does not cover the v2 publication profile; run dottie account login --handle HANDLE to sign in again and grant it; account " + escapeField(did) + " is unchanged"
	}
	return "pull refused: the account session cannot prove the v2 publication scope; account " + escapeField(did) + " is unchanged"
}

func pullRemoteFailure(err error) string {
	if errors.Is(err, service.ErrPublicationReaderInput) || errors.Is(err, service.ErrPublicationReaderIdentity) {
		return "pull refused: the account identity or publication binding does not match the authorized session"
	}
	return "pull refused: the account identity or provider transport is unavailable"
}

func productionPullRemoteFactory(openKeyring accountKeyringFactory, env func(string) string) pullRemoteFactory {
	return func(ctx context.Context, _ *urfave.Command, session pushSession, binding publicationstate.Binding) (pullRemote, error) {
		keyring, err := openKeyring()
		if err != nil {
			return pullRemote{}, err
		}
		fail := func(err error) (pullRemote, error) {
			_ = keyring.Close()
			return pullRemote{}, err
		}
		client, err := newAuthorizedAccountClient(keyring, env)
		if err != nil {
			return fail(err)
		}
		identity, err := client.Discover(ctx, session.Session.Handle)
		if err != nil || identity.DID != session.Session.DID || identity.DIDDocumentID == "" || len(identity.VerificationMethods) == 0 {
			return fail(errors.New("account identity is unavailable"))
		}
		api, err := atproto.NewSessionAPIClient(client, identity, identity.Handle, session.Session)
		if err != nil {
			return fail(err)
		}
		transport := atproto.NewATClientTransport(api)
		adapter, err := service.NewATProtoMaterialTransport(service.ATProtoMaterialConfig{
			Binding: binding, DID: identity.DID,
			Reader:          atproto.RevisionReader{Transport: transport, Budgets: atproto.DefaultBudgets(), DIDDocumentID: identity.DIDDocumentID, VerificationMethods: append([]atproto.VerificationMethod(nil), identity.VerificationMethods...)},
			Transport:       transport,
			BlobUploadLimit: int64(publication.MaxBlobBytes),
		})
		if err != nil {
			return fail(err)
		}
		reader, err := service.NewPublicationReader(service.PublicationReaderConfig{
			Binding: binding, DID: identity.DID, Session: session.Session, Adapter: adapter,
			Blobs: atproto.VaultReader{Transport: transport, Budgets: atproto.DefaultBudgets()},
		})
		if err != nil {
			return fail(err)
		}
		return pullRemote{Reader: reader, Close: func() { _ = keyring.Close() }}, nil
	}
}
