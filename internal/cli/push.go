package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
)

type pushSession struct {
	Session *atproto.Session
}

type publicationPushSources struct {
	Paths         platform.Paths
	Binding       publicationstate.Binding
	Coordinator   *service.Coordinator
	Reader        service.PublicationAcceptedSource
	Transport     service.MaterialTransport
	Reviews       service.ReviewSource
	Records       service.PublicationProposalStore
	Configuration config.Config
	Close         func()
}

type pushSessionFactory func(context.Context, *urfave.Command) (pushSession, error)

type pushSourcesFactory func(context.Context, *urfave.Command, pushSession) (publicationPushSources, error)

func runPush(args []string, stdout, stderr io.Writer, openKeyring accountKeyringFactory, env func(string) string) int {
	code := 0
	command := newPushCommand(stdout, stderr, &code,
		productionPushSessionFactory(openKeyring, env), productionPushSourcesFactory(openKeyring, env),
		productionSessionDIDSource(openKeyring, env))
	arguments := append([]string{"dottie"}, args...)
	ctx := context.Background()
	if err := command.Run(ctx, arguments); err != nil && code == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	return code
}

func newPushCommand(
	stdout, stderr io.Writer,
	exitCode *int,
	sessions pushSessionFactory,
	sources pushSourcesFactory,
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
	push := configure(&urfave.Command{
		Name: "push",
		Flags: []urfave.Flag{
			&urfave.StringFlag{Name: "vault", Usage: "local vault fingerprint", OnlyOnce: true},
			&urfave.StringFlag{Name: "device-id", Usage: "local device identifier", OnlyOnce: true},
			&urfave.StringFlag{Name: "did", Usage: "signed-in account DID", OnlyOnce: true},
			&urfave.StringFlag{Name: "handle", Usage: "signed-in account handle", OnlyOnce: true},
			&urfave.StringFlag{Name: "confirm", Usage: "confirmation printed by an earlier review", OnlyOnce: true},
		},
		Action: func(ctx context.Context, command *urfave.Command) error {
			return runPushCommand(ctx, command, sessions, sources, dids)
		},
	})
	root := configure(
		&urfave.Command{Name: "dottie", Commands: []*urfave.Command{push}, Writer: stdout, ErrWriter: stderr},
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

func runPushCommand(
	ctx context.Context,
	command *urfave.Command,
	sessions pushSessionFactory,
	sources pushSourcesFactory,
	dids sessionDIDSource,
) error {
	if command.NArg() != 0 {
		return usageExit("push takes no positional arguments")
	}
	if command.IsSet("handle") {
		return usageExit("push requires --did; a handle cannot be resolved before the publication scope check")
	}
	if command.IsSet("vault") && command.String("vault") == "" ||
		command.IsSet("device-id") && command.String("device-id") == "" {
		return usageExit("vault or device selector value is missing")
	}
	resolved, err := resolveAccountDID(ctx, command, dids)
	if err != nil {
		return accountDIDRefusal("push", err)
	}
	if err := writeResolvedAccount(command, resolved); err != nil {
		return err
	}
	var confirmation [32]byte
	if command.IsSet("confirm") {
		decoded, err := decodeFixedHex(command.String("confirm"), 32)
		if err != nil {
			return usageExit("--confirm must be the 32-byte hexadecimal confirmation printed by dottie push")
		}
		copy(confirmation[:], decoded)
	}
	session, err := sessions(ctx, command)
	if err != nil {
		return urfave.Exit("push refused: account session is unavailable", 3)
	}
	if err := session.Session.RequirePublicationScopes(); err != nil {
		return urfave.Exit(pushScopeRefusal(err, command.String("did")), 3)
	}
	ports, err := sources(ctx, command, session)
	if err != nil {
		return urfave.Exit(escapeErrorMessage(pushSourceFailure(err)), 3)
	}
	defer ports.Close()
	if ports.Binding.AccountDID != session.Session.DID {
		return urfave.Exit("push refused: the publication binding does not match the authorized account", 3)
	}
	store, err := openPublicationPositionStore(ports.Paths.PublicationStateDir(), ports.Binding)
	if err != nil {
		return urfave.Exit(escapeErrorMessage(pushStoreFailure(err)), 3)
	}
	defer func() { _ = store.Close() }()
	records, err := ports.Records.List(ctx)
	if err != nil {
		return urfave.Exit(escapeErrorMessage(err.Error()), 3)
	}
	retained, err := selectPublicationProposal(records, ports.Binding, command.IsSet("confirm"), confirmation)
	if err != nil {
		return urfave.Exit(escapeErrorMessage(err.Error()), 3)
	}
	publicationID := [16]byte{}
	if retained != nil {
		publicationID = retained.PublicationID
	}
	if !command.IsSet("confirm") && retained == nil {
		if _, err := rand.Read(publicationID[:]); err != nil || publicationID == ([16]byte{}) {
			return urfave.Exit("push refused: a fresh publication identity is unavailable", 3)
		}
	}
	request := service.PublicationPushRequest{
		Store: store, Transport: ports.Transport, Reader: ports.Reader, Records: ports.Records,
		Binding: ports.Binding, Configuration: ports.Configuration, Reviews: ports.Reviews,
		PublicationID: publicationID, Record: retained,
	}
	preparation, err := ports.Coordinator.PreparePublicationPush(ctx, request)
	if err != nil {
		return pushPreparationFailure(command, ports.Paths, err)
	}
	if preparation.NoOp {
		output := "push: no-op\nnothing to publish; the accepted position already holds the reviewed snapshot\n"
		if preparation.Present {
			output += fmt.Sprintf(
				"floor: revision=%d generation=%d sequence=%d\n",
				preparation.Floor.Revision,
				preparation.Floor.Generation,
				preparation.Floor.Sequence,
			)
		}
		return writeCommandOutput(command, output)
	}
	output := renderPushProposal(preparation)
	if !command.IsSet("confirm") {
		if err := writeCommandOutput(command, output); err != nil {
			return err
		}
		return urfave.Exit(
			"review the publication above, then repeat with --confirm "+hex.EncodeToString(
				preparation.Proposal.Confirmation[:],
			),
			3,
		)
	}
	if preparation.Proposal.Confirmation != confirmation {
		if err := writeCommandOutput(command, output); err != nil {
			return err
		}
		return urfave.Exit(
			"push refused: the reviewed proposal is stale; state changed since review; re-run dottie push",
			3,
		)
	}
	result, publishErr := ports.Coordinator.ConfirmPublicationPush(ctx, request, preparation, confirmation)
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
		if errors.Is(publishErr, service.ErrMaterialSubmissionRejected) {
			output += renderPushRejection(result)
		}
	} else {
		output += renderPush(status)
	}
	if err := writeCommandOutput(command, output); err != nil {
		if status == service.StatusCommitted {
			fmt.Fprintln(
				command.Root().ErrWriter,
				"dottie: the publication committed but its result could not be written",
			)
			return urfave.Exit("publication committed but its output could not be written", 4)
		}
		return err
	}
	if publishErr != nil && errors.Is(publishErr, service.ErrMaterialSubmissionRejected) {
		return urfave.Exit("push did not publish: the provider refused the submission and no record was written", 4)
	}
	return pushExit(status)
}

func selectPublicationProposal(
	records []service.PublicationProposalRecord,
	binding publicationstate.Binding,
	confirmed bool,
	_ [32]byte,
) (*service.PublicationProposalRecord, error) {
	if confirmed {
		var retained *service.PublicationProposalRecord
		matches := 0
		consumed := 0
		for index := range records {
			record := records[index]
			if record.Binding != binding {
				continue
			}
			if record.Consumed {
				consumed++
				continue
			}
			matches++
			if matches > 1 {
				return nil, service.ErrPublicationProposal
			}
			retained = &records[index]
		}
		if retained == nil {
			if consumed > 0 {
				return nil, service.ErrPublicationProposalConsumed
			}
			return nil, service.ErrPublicationProposalAbsent
		}
		return retained, nil
	}
	candidates := make([]service.PublicationProposalRecord, 0, len(records))
	for _, record := range records {
		if record.Binding != binding {
			continue
		}
		if record.Consumed {
			continue
		}
		candidates = append(candidates, record)
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	if len(candidates) > 1 {
		return nil, service.ErrPublicationProposal
	}
	retained := candidates[0]
	return &retained, nil
}

func pushScopeRefusal(err error, did string) string {
	message := "push refused: " + escapeErrorMessage(err.Error())
	if _, ok := errors.AsType[*atproto.PublicationScopeError](err); ok {
		message = "push refused: the account authorization does not cover the v2 publication profile; run dottie account login --handle HANDLE to sign in again and grant it"
	}
	return message + "; account " + escapeField(did) + " is unchanged"
}

func pushSourceFailure(err error) string {
	if errors.Is(err, errPublicationStoreUnsafe) {
		return "push refused: " + errPublicationStoreUnsafe.Error() + "; it was left unchanged"
	}
	if errors.Is(err, service.ErrNoVaultSelection) || errors.Is(err, service.ErrAmbiguousVaultSelection) {
		return "push refused: local vault selection is unavailable; pass --vault and --device-id"
	}
	return "push refused: the local publication position, account identity or transport is unavailable"
}

func pushStoreFailure(err error) string {
	if errors.Is(err, errPublicationStoreUnsafe) || errors.Is(err, errPublicationStoreCreation) {
		return "push refused: " + err.Error() + "; it was left unchanged"
	}
	var storeFailure publicationStoreFailure
	if errors.As(err, &storeFailure) {
		return "push refused: the local publication position store is unusable (" + escapeField(
			string(storeFailure.Reason()),
		) + "); it was left unchanged"
	}
	return "push refused: the local publication position store cannot be opened; it was left unchanged"
}

func pushPreparationFailure(command *urfave.Command, paths platform.Paths, err error) error {
	switch {
	case errors.Is(err, service.ErrPublicationProposalConsumed):
		return urfave.Exit(escapeErrorMessage(err.Error()), 3)
	case errors.Is(err, service.ErrPublicationProposalActive), errors.Is(err, service.ErrPublicationProposalUnresolved):
		writeUnresolvedAttemptHint(command, paths.PublicationStateDir())
		return urfave.Exit(escapeErrorMessage(err.Error()), 3)
	case errors.Is(err, service.ErrPublicationProposalStale):
		return urfave.Exit(escapeErrorMessage(err.Error()), 3)
	case errors.Is(err, service.ErrPublicationProposal),
		errors.Is(err, service.ErrReviewMismatch),
		errors.Is(err, service.ErrConfigChangedSincePrepare):
		return urfave.Exit("push refused: the publication cannot be prepared from the current configuration", 3)
	}
	status := pushMaterialStatus(err)
	if writeErr := writeCommandOutput(command, renderPushFailure(status, err)); writeErr != nil {
		return writeErr
	}
	if status == service.StatusRejected || status == service.StatusConflicted {
		return urfave.Exit("push refused", 3)
	}
	return urfave.Exit("push did not complete", 4)
}

type publicationStoreFailure interface {
	Reason() publicationstate.Reason
}

type materialSubmissionFailure interface {
	Stage() string
}

func pushMaterialStatus(err error) service.StatusState {
	if err == nil {
		return service.StatusCommitted
	}
	if errors.Is(err, service.ErrMaterialSubmissionRejected) {
		return service.StatusRejected
	}
	var submissionFailure materialSubmissionFailure
	if errors.As(err, &submissionFailure) && submissionFailure.Stage() == "submission" {
		return service.StatusUnavailable
	}
	switch {
	case errors.Is(err, service.ErrPublicationProposalConsumed),
		errors.Is(err, service.ErrPublicationProposalAbsent),
		errors.Is(err, service.ErrPublicationProposalStale),
		errors.Is(err, service.ErrPublicationProposalActive),
		errors.Is(err, service.ErrReviewMismatch),
		errors.Is(err, service.ErrConfigChangedSincePrepare),
		errors.Is(err, atproto.ErrInsufficientPublicationScope):
		return service.StatusRejected
	case errors.Is(err, atproto.ErrBatchRejected), errors.Is(err, atproto.ErrPublicationQueued):
		return service.StatusRejected
	case errors.Is(err, atproto.ErrFenceLost):
		return service.StatusFenceLost
	}
	var storeFailure publicationStoreFailure
	if errors.As(err, &storeFailure) {
		switch storeFailure.Reason() {
		case publicationstate.ReasonActiveAttempt,
			publicationstate.ReasonConfirmation,
			publicationstate.ReasonTransition:
			return service.StatusRejected
		case publicationstate.ReasonCommitUnknown:
			return service.StatusUnavailable
		}
	}
	return service.StatusUnavailable
}

func renderPushProposal(preparation service.PublicationPushPreparation) string {
	var output strings.Builder
	if preparation.Issued {
		output.WriteString("push: review required\n")
	} else {
		output.WriteString("push: review required (retained proposal)\n")
	}
	fmt.Fprintf(&output, "targets: %d\nentries: %d\n", preparation.Targets, preparation.Entries)
	if preparation.Present {
		fmt.Fprintf(
			&output,
			"accepted floor: revision=%d generation=%d sequence=%d\n",
			preparation.Floor.Revision,
			preparation.Floor.Generation,
			preparation.Floor.Sequence,
		)
	} else {
		output.WriteString("accepted floor: none (first publication)\n")
	}
	fmt.Fprintf(
		&output,
		"candidate record: %x\ncandidate payload: %x size=%d\n",
		preparation.Proposal.Proposal.CandidateRecordCID,
		preparation.Proposal.Proposal.CandidateBlobCID,
		preparation.Proposal.Blob.Size,
	)
	fmt.Fprintf(&output, "review: selection-digest=%x selection-revision=%d approval-digest=%x approval-revision=%d\n",
		preparation.Proposal.Review.SelectionDigest, preparation.Proposal.Review.SelectionRevision,
		preparation.Proposal.Review.ApprovalDigest, preparation.Proposal.Review.ApprovalRevision)
	fmt.Fprintf(&output, "confirmation: %x\n", preparation.Proposal.Confirmation)
	return output.String()
}

func productionPushSessionFactory(openKeyring accountKeyringFactory, env func(string) string) pushSessionFactory {
	return func(ctx context.Context, command *urfave.Command) (pushSession, error) {
		keyring, err := openKeyring()
		if err != nil {
			return pushSession{}, err
		}
		defer keyring.Close()
		client, err := newAuthorizedAccountClient(keyring, env)
		if err != nil {
			return pushSession{}, err
		}
		session, err := client.LoadSession(ctx, command.String("did"))
		if err != nil {
			return pushSession{}, err
		}
		return pushSession{Session: session}, nil
	}
}

func productionPushSourcesFactory(openKeyring accountKeyringFactory, env func(string) string) pushSourcesFactory {
	return func(ctx context.Context, command *urfave.Command, session pushSession) (publicationPushSources, error) {
		selection := service.VaultSelection{DeviceID: command.String("device-id")}
		if command.IsSet("vault") {
			vaultID, parseErr := parseVaultFingerprint(command.String("vault"))
			if parseErr != nil {
				return publicationPushSources{}, parseErr
			}
			selection.Vault = vaultID
		}
		return openPublicationPushSources(ctx, command, session, selection, openKeyring, env)
	}
}

func openPublicationPushSources(
	ctx context.Context,
	_ *urfave.Command,
	session pushSession,
	selection service.VaultSelection,
	openKeyring accountKeyringFactory,
	env func(string) string,
) (publicationPushSources, error) {
	{
		paths, err := platform.Resolve(env)
		if err != nil {
			return publicationPushSources{}, err
		}
		directory := paths.PublicationStateDir()
		if err := checkPublicationStoreDirectory(directory); err != nil {
			return publicationPushSources{}, err
		}
		store, err := state.Open(paths)
		if err != nil {
			return publicationPushSources{}, err
		}
		keyring, err := openKeyring()
		if err != nil {
			_ = store.Close()
			return publicationPushSources{}, err
		}
		closeResources := func() { _ = keyring.Close(); _ = store.Close() }
		configuration := service.FileConfigPort{Paths: paths}
		coordinator, err := service.NewCoordinator(service.Dependencies{
			Config: configuration, State: store, Settings: manualGNOMESettings(), Paths: paths, Clock: time.Now,
		})
		if err != nil {
			closeResources()
			return publicationPushSources{}, err
		}
		selected, err := coordinator.ResolveSelection(ctx, selection)
		if err != nil {
			closeResources()
			return publicationPushSources{}, err
		}
		loaded, err := configuration.Load(ctx)
		if err != nil {
			closeResources()
			return publicationPushSources{}, err
		}
		if err := loaded.Validate(); err != nil {
			closeResources()
			return publicationPushSources{}, err
		}
		binding := publicationstate.Binding{
			AccountDID: session.Session.DID, Backend: publicationstate.BackendPublicRepo,
			Repository: "at://" + session.Session.DID, Vault: selected.Vault,
		}
		client, err := newAuthorizedAccountClient(keyring, env)
		if err != nil {
			closeResources()
			return publicationPushSources{}, err
		}
		identity, err := client.Discover(ctx, session.Session.Handle)
		if err != nil || identity.DID != session.Session.DID {
			closeResources()
			return publicationPushSources{}, errors.New("account identity is unavailable")
		}
		api, err := atproto.NewSessionAPIClient(client, identity, identity.Handle, session.Session)
		if err != nil {
			closeResources()
			return publicationPushSources{}, err
		}
		transport := atproto.NewATClientTransport(api)
		limit, err := atproto.DescribeBlobUploadLimit(ctx, transport)
		if err != nil {
			closeResources()
			return publicationPushSources{}, err
		}
		adapter, err := service.NewATProtoMaterialTransport(service.ATProtoMaterialConfig{
			Binding: binding,
			DID:     identity.DID,
			Reader: atproto.RevisionReader{
				Transport:           transport,
				Budgets:             atproto.DefaultBudgets(),
				DIDDocumentID:       identity.DIDDocumentID,
				VerificationMethods: append([]atproto.VerificationMethod(nil), identity.VerificationMethods...),
			},
			Transport:       transport,
			BlobUploadLimit: limit,
		})
		if err != nil {
			closeResources()
			return publicationPushSources{}, err
		}
		reader, err := service.NewPublicationReader(service.PublicationReaderConfig{
			Binding: binding,
			DID:     identity.DID,
			Session: session.Session,
			Adapter: adapter,
			Blobs: atproto.VaultReader{
				Transport:        transport,
				ObservationStore: store,
				Budgets:          atproto.DefaultBudgets(),
				Clock:            time.Now,
			},
		})
		if err != nil {
			closeResources()
			return publicationPushSources{}, err
		}
		return publicationPushSources{
			Paths: paths, Binding: binding, Coordinator: coordinator, Reader: reader,
			Transport: adapter, Reviews: configuration, Records: newPublicationProposalStore(directory),
			Configuration: loaded, Close: closeResources,
		}, nil
	}
}

func renderPushRejection(result service.MaterialPublishResult) string {
	rendered := "push: the provider refused the submission and wrote no record; the candidate payload may still be retrievable by CID\n"
	if result.Attempt.Lifecycle == publicationstate.AttemptRetiredAbandoned {
		return rendered + "push: the unresolved attempt was retired locally and no longer blocks a review; re-run dottie push to review again\n"
	}
	return rendered + "push: the unresolved attempt was left active and still blocks a review; re-run dottie push for the recovery steps\n"
}

func writeUnresolvedAttemptHint(command *urfave.Command, directory string) {
	writer := command.Root().ErrWriter
	fmt.Fprintln(writer, "dottie: push: a publication attempt is unresolved past submission and blocks this review")
	fmt.Fprintf(writer, "dottie: local state: %s\n", escapeField(directory))
	fmt.Fprintln(
		writer,
		"dottie: the local state cannot prove whether that attempt published a record; its provider outcome is unknown",
	)
	fmt.Fprintln(
		writer,
		"dottie: local, not provider, surgery: deleting that directory clears the blocking attempt and retracts nothing at the provider",
	)
	fmt.Fprintln(
		writer,
		"dottie: it discards the pending review, the accepted position and the attempt history held there",
	)
	fmt.Fprintln(
		writer,
		"dottie: after deleting it, run dottie pull to re-record the provider position, then dottie push to review a fresh candidate",
	)
}

func renderPush(status service.StatusState) string {
	return "push: " + escapeField(string(status)) + "\n"
}

func renderPushFailure(status service.StatusState, err error) string {
	rendered := "push: " + escapeField(string(status))
	if detail := publicationFailureDetail(err); detail != "" {
		rendered += " (" + detail + ")"
	}
	return rendered + "\n"
}

func publicationFailureDetail(err error) string {
	if err == nil {
		return ""
	}
	fields := make([]string, 0, 3)
	if staged, ok := err.(interface{ Stage() string }); ok {
		fields = append(fields, "stage="+escapeField(staged.Stage()))
	}
	if reasoned, ok := err.(interface{ Reason() string }); ok {
		fields = append(fields, "reason="+escapeField(reasoned.Reason()))
	}
	if class := publicationFailureClass(err); class != "" {
		fields = append(fields, "class="+class)
	}
	if provider := publicationFailureProvider(err); provider != "" {
		fields = append(fields, "provider="+provider)
	}
	return strings.Join(fields, " ")
}

func publicationFailureProvider(err error) string {
	var refused interface {
		Class() error
		Reason() string
	}
	if !errors.As(err, &refused) {
		return ""
	}
	return escapeField(refused.Reason())
}

func publicationFailureClass(err error) string {
	switch {
	case errors.Is(err, atproto.ErrInsufficientPublicationScope):
		return "insufficient_publication_scope"
	case errors.Is(err, atproto.ErrBatchRejected):
		return "batch_rejected"
	case errors.Is(err, atproto.ErrPublicationQueued):
		return "publication_queued"
	case errors.Is(err, atproto.ErrFenceLost):
		return "fence_lost"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "canceled"
	}
	return ""
}

func pushExit(status service.StatusState) error {
	switch status {
	case service.StatusCommitted, service.StatusNoOp:
		return nil
	case service.StatusRejected, service.StatusConflicted:
		return urfave.Exit("push refused", 3)
	default:
		return urfave.Exit("push did not complete", 4)
	}
}
