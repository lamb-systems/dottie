package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
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
				if errors.Is(err, atproto.ErrDottiePublicationPresent) {
					return urfave.Exit("account bootstrap requires an account with no existing Dottie publication; this account already holds one", 3)
				}
				return urfave.Exit("account bootstrap could not verify whether the account holds a Dottie publication", 3)
			}
			signing, recipient, err := vault.GenerateDeviceKeys()
			if err != nil {
				return urfave.Exit("cannot generate device keys", 1)
			}
			defer clear(signing)
			material := vault.DeviceMaterial{DeviceID: command.String("device-id"), KeyID: deviceKeyID(signing.Public().(ed25519.PublicKey)), Signing: signing, Recipient: recipient}
			result, initializeErr := coordinator.InitializeVault(ctx, service.BootstrapRequest{
				VaultName: command.String("vault-name"), Device: material,
			})
			if initializeErr != nil {
				if result.Outcome == service.BootstrapNotRecorded {
					if err := writeCommandOutput(command, renderBootstrapOutcome(result)); err != nil {
						return err
					}
					return urfave.Exit("bootstrap recorded no local vault; pending device keys were deleted best-effort; nothing was published", 3)
				}
				return urfave.Exit("bootstrap could not proceed", 1)
			}
			if result.Outcome != service.BootstrapLocalIdentityRecorded {
				return urfave.Exit("bootstrap did not record the local vault identity", 4)
			}
			return writeCommandOutput(command, renderBootstrapOutcome(result))
		},
	})

	sessionCommands := accountSessionCommands(openKeyring, sessionOptions)
	for _, command := range sessionCommands {
		configure(command)
	}

	root := configure(&urfave.Command{
		Name:     "account",
		Commands: append([]*urfave.Command{bootstrap}, sessionCommands...),
		Action: func(_ context.Context, _ *urfave.Command) error {
			return usageExit("expected login, logout, status or bootstrap")
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
		port := sessionGenesisPreflight{identity: identity, transport: transport}
		coordinator, err := service.NewCoordinator(service.Dependencies{
			State: store, DeviceKeys: keyring, GenesisPreflight: port,
			Clock: time.Now,
		})
		if err != nil {
			closeResources()
			return nil, func() {}, err
		}
		return coordinator, closeResources, nil
	}
}

type sessionGenesisPreflight struct {
	identity  atproto.Identity
	transport atproto.Transport
}

func (port sessionGenesisPreflight) Preflight(ctx context.Context) error {
	if port.identity.DID == "" || port.identity.DIDDocumentID == "" || len(port.identity.VerificationMethods) == 0 || port.transport == nil {
		return errors.New("authenticated genesis provider wiring is unavailable")
	}
	return atproto.CheckNoDottiePublication(ctx, atproto.RevisionReader{
		Transport: port.transport, Budgets: atproto.DefaultBudgets(), DIDDocumentID: port.identity.DIDDocumentID,
		VerificationMethods: append([]atproto.VerificationMethod(nil), port.identity.VerificationMethods...),
	}, port.transport, port.identity.DID)
}

func renderBootstrapOutcome(result service.BootstrapResult) string {
	return fmt.Sprintf("bootstrap: %s\nvault fingerprint: %x\n", escapeField(string(result.Outcome)), result.Bootstrap.Vault)
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
