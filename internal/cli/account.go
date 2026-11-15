package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
)

type accountKeyring interface {
	StoreDeviceKeys(context.Context, [32]byte, vault.DeviceMaterial) error
	LoadDeviceKeys(context.Context, [32]byte, string) (vault.DeviceMaterial, error)
	Close() error
}

type accountKeyringFactory func() (accountKeyring, error)

type bootstrapCoordinator interface {
	PreflightVault(context.Context) error
	InitializeVault(context.Context, service.BootstrapRequest) (service.BootstrapResult, error)
	FinalizeVaultTrust(context.Context, [32]byte) (service.FinalizeResult, error)
}

type bootstrapFactory func(context.Context, *urfave.Command) (bootstrapCoordinator, func(), error)

func runAccount(args []string, stdout, stderr io.Writer, openKeyring accountKeyringFactory) int {
	exitCode := 0
	root := newAccountCommand(stdout, stderr, openKeyring, &exitCode)
	arguments := append([]string{"account"}, args...)
	ctx := context.Background()
	if err := root.Run(ctx, arguments); err != nil && exitCode == 0 {
		root.ExitErrHandler(ctx, root, err)
	}
	return exitCode
}

func newAccountCommand(stdout, stderr io.Writer, openKeyring accountKeyringFactory, exitCode *int) *urfave.Command {
	return newAccountCommandWithSession(stdout, stderr, openKeyring, exitCode, accountSessionOptions{browser: openAuthorizationURL, env: os.Getenv})
}

func newAccountCommandWithSession(stdout, stderr io.Writer, openKeyring accountKeyringFactory, exitCode *int, sessionOptions accountSessionOptions) *urfave.Command {
	if sessionOptions.env == nil {
		sessionOptions.env = os.Getenv
	}
	return newAccountCommandWithFactories(stdout, stderr, openKeyring, exitCode, sessionOptions,
		productionBootstrapFactory(openKeyring, sessionOptions.env))
}

func newAccountCommandWithFactories(stdout, stderr io.Writer, openKeyring accountKeyringFactory, exitCode *int, sessionOptions accountSessionOptions, bootstrapFactory bootstrapFactory) *urfave.Command {
	if sessionOptions.env == nil {
		sessionOptions.env = os.Getenv
	}
	usageHandler := func(_ context.Context, _ *urfave.Command, err error, _ bool) error {
		return urfave.Exit("usage: "+escapeField(err.Error()), 2)
	}
	configure := func(command *urfave.Command) *urfave.Command {
		command.Suggest = false
		command.DefaultCommand = ""
		command.UseShortOptionHandling = false
		command.EnableShellCompletion = false
		command.ReadArgsFromStdin = false
		command.OnUsageError = usageHandler
		return command
	}
	deviceIDFlag := &urfave.StringFlag{Name: "device-id", Usage: "device identifier", OnlyOnce: true}
	vaultNameFlag := &urfave.StringFlag{Name: "vault-name", Usage: "vault name", OnlyOnce: true}

	bootstrap := configure(&urfave.Command{
		Name: "bootstrap",
		Flags: []urfave.Flag{
			vaultNameFlag, deviceIDFlag,
			&urfave.StringFlag{Name: "did", Usage: "signed-in account DID", OnlyOnce: true},
			&urfave.StringFlag{Name: "handle", Usage: "signed-in account handle", OnlyOnce: true},
		},
		Action: func(ctx context.Context, command *urfave.Command) error {
			if command.NArg() != 0 || command.String("vault-name") == "" || command.String("device-id") == "" {
				return usageExit("account bootstrap requires --vault-name, --device-id and one of --did or --handle")
			}
			if command.IsSet("did") == command.IsSet("handle") || command.IsSet("did") && command.String("did") == "" || command.IsSet("handle") && command.String("handle") == "" {
				return usageExit("account bootstrap requires exactly one non-empty --did or --handle")
			}
			coordinator, closeResources, err := bootstrapFactory(ctx, command)
			if err != nil {
				return urfave.Exit("cannot prepare authenticated bootstrap provider", 1)
			}
			defer closeResources()
			if err := coordinator.PreflightVault(ctx); err != nil {
				if errors.Is(err, atproto.ErrGenesisRepositoryNotEmpty) {
					return urfave.Exit("genesis requires an empty verified repository; this account already contains repository records", 3)
				}
				return urfave.Exit("genesis preflight could not verify an empty repository", 3)
			}
			kit, err := vault.GenerateRecoveryKit()
			if err != nil {
				return urfave.Exit("cannot generate recovery kit", 1)
			}
			defer clear(kit)
			signing, recipient, err := vault.GenerateDeviceKeys()
			if err != nil {
				return urfave.Exit("cannot generate device keys", 1)
			}
			defer clear(signing)
			material := vault.DeviceMaterial{DeviceID: command.String("device-id"), KeyID: deviceKeyID(signing.Public().(ed25519.PublicKey)), Signing: signing, Recipient: recipient}
			result, initializeErr := coordinator.InitializeVault(ctx, service.BootstrapRequest{
				VaultName: command.String("vault-name"), Kit: kit, Device: material,
				DeliverKit: func(bootstrap vault.BootstrapResult, recoveryKit []byte) error {
					kitPublic, err := vault.RecoveryKitSigningPublicKey(recoveryKit, bootstrap.Vault)
					if err != nil {
						return errors.New("cannot derive recovery kit signing key")
					}
					checkpointFingerprint := sha256.Sum256(bootstrap.Checkpoint)
					kitPublicFingerprint := sha256.Sum256(kitPublic)
					output := fmt.Sprintf("recovery kit (keep offline): %s\nvault fingerprint: %x\nanchor fingerprint: %x\ncheckpoint fingerprint: %x\nkit public-key fingerprint: %x\n", groupRecoveryKit(recoveryKit), bootstrap.Vault, bootstrap.Anchor, checkpointFingerprint, kitPublicFingerprint)
					return writeAndFlushKit(command, output)
				},
			})
			if initializeErr != nil {
				if result.Outcome == service.BootstrapUnresolved {
					if err := writeCommandOutput(command, renderBootstrapOutcome(result)); err != nil {
						return err
					}
					return urfave.Exit("genesis publication is unresolved; device keys were retained for verification", 4)
				}
				if result.Outcome == service.BootstrapFinalizationError {
					if err := writeCommandOutput(command, renderBootstrapOutcome(result)); err != nil {
						return err
					}
					return urfave.Exit("genesis was verified but local trust finalization failed; device keys were retained", 4)
				}
				if result.Outcome == service.BootstrapPrecommitFailure || result.Outcome == service.BootstrapVerifiedAbsence {
					if err := writeCommandOutput(command, renderBootstrapOutcome(result)); err != nil {
						return err
					}
					return urfave.Exit("genesis was not committed; pending device keys were deleted best-effort", 3)
				}
				return urfave.Exit("bootstrap could not proceed", 1)
			}
			if result.Outcome != service.BootstrapVerifiedCommit {
				return urfave.Exit("bootstrap did not produce a verified committed vault", 4)
			}
			return writeCommandOutput(command, renderBootstrapOutcome(result))
		},
	})

	finalize := configure(&urfave.Command{
		Name: "finalize",
		Flags: []urfave.Flag{
			&urfave.StringFlag{Name: "vault", Usage: "vault fingerprint (64 hexadecimal characters)", OnlyOnce: true},
			&urfave.StringFlag{Name: "did", Usage: "signed-in account DID", OnlyOnce: true},
			&urfave.StringFlag{Name: "handle", Usage: "signed-in account handle", OnlyOnce: true},
		},
		Action: func(ctx context.Context, command *urfave.Command) error {
			if command.NArg() != 0 || !command.IsSet("vault") || command.String("vault") == "" {
				return usageExit("account finalize requires --vault")
			}
			if command.IsSet("did") == command.IsSet("handle") || command.IsSet("did") && command.String("did") == "" || command.IsSet("handle") && command.String("handle") == "" {
				return usageExit("account finalize requires exactly one non-empty --did or --handle")
			}
			vaultID, err := parseVaultFingerprint(command.String("vault"))
			if err != nil {
				return usageExit("--vault must be a 32-byte hexadecimal fingerprint")
			}
			coordinator, closeResources, err := bootstrapFactory(ctx, command)
			if err != nil {
				return urfave.Exit("cannot prepare authenticated finalization provider", 4)
			}
			defer closeResources()
			result, err := coordinator.FinalizeVaultTrust(ctx, vaultID)
			if err != nil {
				if errors.Is(err, service.ErrFinalizeKeysMissing) {
					return urfave.Exit("device keys for this vault are missing from Secret Service; finalization cannot authenticate the vault", 3)
				}
				if errors.Is(err, service.ErrFinalizeStateConflict) || errors.Is(err, service.ErrFinalizeStateIncomplete) {
					return urfave.Exit(escapeErrorMessage(err.Error()), 3)
				}
				if errors.Is(err, atproto.ErrReadVaultAuthentication) || errors.Is(err, atproto.ErrReadRecordSignature) || errors.Is(err, atproto.ErrReadEnvelopeSignature) {
					return urfave.Exit("remote vault position did not authenticate with the retained device keys", 3)
				}
				return urfave.Exit("vault finalization could not be verified or recorded", 4)
			}
			return writeCommandOutput(command, renderFinalizeResult(result))
		},
	})

	sessionCommands := accountSessionCommands(openKeyring, sessionOptions)
	for _, command := range sessionCommands {
		configure(command)
	}

	root := configure(&urfave.Command{
		Name:     "account",
		Commands: append([]*urfave.Command{bootstrap, finalize}, sessionCommands...),
		Action: func(_ context.Context, _ *urfave.Command) error {
			return usageExit("expected login, logout, status, bootstrap or finalize")
		},
		Writer: stdout, ErrWriter: stderr,
	})
	root.Writer = stdout
	root.ErrWriter = stderr
	root.ExitErrHandler = func(_ context.Context, command *urfave.Command, err error) {
		code := 1
		var exitError urfave.ExitCoder
		if errors.As(err, &exitError) {
			code = exitError.ExitCode()
		}
		if code != 1 && code != 2 && code != 3 && code != 4 {
			code = 1
		}
		if message := escapeErrorMessage(err.Error()); message != "" {
			fmt.Fprintf(command.ErrWriter, "dottie: %s\n", message)
		}
		*exitCode = code
	}
	return root
}

func productionBootstrapFactory(openKeyring accountKeyringFactory, env func(string) string) bootstrapFactory {
	return func(ctx context.Context, command *urfave.Command) (bootstrapCoordinator, func(), error) {
		paths, err := platform.Resolve(env)
		if err != nil {
			return nil, func() {}, err
		}
		store, err := state.Open(paths)
		if err != nil {
			return nil, func() {}, err
		}
		keyring, err := openKeyring()
		if err != nil {
			_ = store.Close()
			return nil, func() {}, err
		}
		closeResources := func() { _ = keyring.Close(); _ = store.Close() }
		client, err := newAuthorizedAccountClient(keyring, env)
		if err != nil {
			closeResources()
			return nil, func() {}, err
		}
		var identity atproto.Identity
		if command.IsSet("handle") {
			identity, err = client.Discover(ctx, command.String("handle"))
		} else {
			var session *atproto.Session
			session, err = client.LoadSession(ctx, command.String("did"))
			if err == nil {
				identity, err = client.Discover(ctx, session.Handle)
				if err == nil && identity.DID != command.String("did") {
					err = errors.New("discovered identity differs from requested DID")
				}
			}
		}
		if err != nil || identity.DID == "" {
			closeResources()
			if err == nil {
				err = errors.New("account identity is unavailable")
			}
			return nil, func() {}, err
		}
		session, err := client.LoadSession(ctx, identity.DID)
		if err != nil {
			closeResources()
			return nil, func() {}, err
		}
		api, err := atproto.NewSessionAPIClient(client, identity, identity.Handle, session)
		if err != nil {
			closeResources()
			return nil, func() {}, err
		}
		transport := atproto.NewATClientTransport(api)
		port := sessionGenesisPort{identity: identity, transport: transport, observations: store}
		coordinator, err := service.NewCoordinator(service.Dependencies{
			State: store, DeviceKeys: keyring, Genesis: port,
			Trust:   service.StateTrustSource{State: store, Keyring: keyring},
			Session: manualReadSession{identity: identity},
			Remote:  service.VaultReader{Reader: atproto.VaultReader{Transport: transport, ObservationStore: store, Budgets: atproto.DefaultBudgets(), Clock: time.Now}},
			Clock:   time.Now,
		})
		if err != nil {
			closeResources()
			return nil, func() {}, err
		}
		return coordinator, closeResources, nil
	}
}

type sessionGenesisPort struct {
	identity     atproto.Identity
	transport    atproto.Transport
	observations atproto.PublicationObservationStore
}

func (port sessionGenesisPort) Preflight(ctx context.Context) error {
	if port.identity.DID == "" || port.identity.DIDDocumentID == "" || len(port.identity.VerificationMethods) == 0 || port.transport == nil {
		return errors.New("authenticated genesis provider wiring is unavailable")
	}
	return atproto.CheckGenesisRepositoryEmpty(ctx, atproto.RevisionReader{
		Transport: port.transport, Budgets: atproto.DefaultBudgets(), DIDDocumentID: port.identity.DIDDocumentID,
		VerificationMethods: append([]atproto.VerificationMethod(nil), port.identity.VerificationMethods...),
	}, port.transport, port.identity.DID)
}

func (port sessionGenesisPort) BlobUploadLimit(ctx context.Context) (int64, error) {
	limit, err := atproto.DescribeBlobUploadLimit(ctx, port.transport)
	if err != nil {
		return 0, err
	}
	if limit > int64(vault.MaxEnvelopeBytes) {
		limit = int64(vault.MaxEnvelopeBytes)
	}
	return limit, nil
}

func (port sessionGenesisPort) CommitGenesis(ctx context.Context, blobLimit int64, kit []byte, root vault.DeviceMaterial, genesis vault.Genesis) (atproto.GenesisCommitResult, error) {
	if port.identity.DID == "" || port.identity.DIDDocumentID == "" || len(port.identity.VerificationMethods) == 0 || port.transport == nil || port.observations == nil {
		return atproto.GenesisCommitResult{}, errors.New("authenticated genesis provider wiring is unavailable")
	}
	return atproto.CommitGenesis(ctx, atproto.GenesisIO{
		Reader: atproto.RevisionReader{
			Transport: port.transport, Budgets: atproto.DefaultBudgets(), DIDDocumentID: port.identity.DIDDocumentID,
			VerificationMethods: append([]atproto.VerificationMethod(nil), port.identity.VerificationMethods...),
		},
		Transport: port.transport, BlobUploadLimit: blobLimit, DID: port.identity.DID,
		ObservationStore: port.observations, Clock: time.Now,
	}, kit, root, genesis)
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

func writeAndFlushKit(command *urfave.Command, output string) error {
	writer := command.Root().Writer
	written, err := io.WriteString(writer, output)
	if err != nil || written != len(output) {
		return urfave.Exit("cannot deliver recovery kit before publication", 1)
	}
	if flusher, ok := writer.(interface{ Flush() error }); ok {
		if err := flusher.Flush(); err != nil {
			return urfave.Exit("cannot flush recovery kit before publication", 1)
		}
	}
	return nil
}

func renderFinalizeResult(result service.FinalizeResult) string {
	checkpointFingerprint := sha256.Sum256(result.CheckpointPosition)
	status := "trust recorded"
	if result.NoOp {
		status = "trust already finalized; no change"
	}
	return fmt.Sprintf("finalization: %s\nvault fingerprint: %x\nanchor fingerprint: %x\ncheckpoint fingerprint: %x\nepoch: %d\n",
		escapeField(status), result.Checkpoint.Vault, result.Checkpoint.Anchor, checkpointFingerprint, result.Checkpoint.Epoch)
}

func renderBootstrapOutcome(result service.BootstrapResult) string {
	var output strings.Builder
	fmt.Fprintf(&output, "genesis: %s\n", escapeField(string(result.Outcome)))
	if result.Bootstrap.Vault != ([32]byte{}) {
		fmt.Fprintf(&output, "vault fingerprint: %x\n", result.Bootstrap.Vault)
	}
	if result.Genesis.Phase != "" {
		fmt.Fprintf(&output, "publication phase: %s\n", escapeField(string(result.Genesis.Phase)))
	}
	if result.Outcome == service.BootstrapUnresolved {
		for _, target := range result.RecordTargets {
			fmt.Fprintf(&output, "record target: %s/%s cid=%s\n", escapeField(target.Collection), escapeField(target.RKey), escapeField(target.CID))
		}
		output.WriteString("inspect instructions: inspect these six repository targets on the selected account; do not retry bootstrap until publication is resolved\n")
	}
	if result.Outcome == service.BootstrapVerifiedCommit {
		fmt.Fprintf(&output, "commit: %s\ncheckpoint: %s\n", escapeField(result.Genesis.CommitCID), escapeField(result.Genesis.CheckpointCID))
	}
	return output.String()
}

func groupRecoveryKit(kit []byte) string {
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(kit)
	var grouped strings.Builder
	for offset := 0; offset < len(encoded); offset += 4 {
		if offset > 0 {
			grouped.WriteByte('-')
		}
		end := offset + 4
		if end > len(encoded) {
			end = len(encoded)
		}
		grouped.WriteString(encoded[offset:end])
	}
	return grouped.String()
}

func deviceKeyID(public ed25519.PublicKey) []byte {
	keyID := sha256.Sum256(public)
	return append([]byte(nil), keyID[:]...)
}

func parseVaultFingerprint(value string) ([32]byte, error) {
	var fingerprint [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(fingerprint) {
		return fingerprint, errors.New("invalid vault fingerprint")
	}
	copy(fingerprint[:], decoded)
	return fingerprint, nil
}

func decodeFixedHex(value string, length int) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != length {
		return nil, errors.New("invalid hexadecimal value")
	}
	return decoded, nil
}

func keyringError(err error) string {
	switch {
	case errors.Is(err, platform.ErrKeyringLocked):
		return "keyring is locked"
	case errors.Is(err, platform.ErrKeyringItemNotFound):
		return "device key item was not found"
	case errors.Is(err, platform.ErrKeyringUnavailable):
		return "keyring is unavailable"
	default:
		return "keyring operation failed"
	}
}
