package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/vault"
)

type accountKeyring interface {
	StoreDeviceKeys(context.Context, [32]byte, vault.DeviceMaterial) error
	LoadDeviceKeys(context.Context, [32]byte, string) (vault.DeviceMaterial, error)
	Close() error
}

type accountKeyringFactory func() (accountKeyring, error)

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
	return newAccountCommandWithImportFactory(stdout, stderr, openKeyring, exitCode, sessionOptions, productionOrchestrationFactory(openKeyring, sessionOptions.env))
}

func newAccountCommandWithImportFactory(stdout, stderr io.Writer, openKeyring accountKeyringFactory, exitCode *int, sessionOptions accountSessionOptions, importFactory orchestrationFactory) *urfave.Command {
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
		Name:  "bootstrap",
		Flags: []urfave.Flag{vaultNameFlag, deviceIDFlag},
		Action: func(ctx context.Context, command *urfave.Command) error {
			if command.NArg() != 0 || command.String("vault-name") == "" || command.String("device-id") == "" {
				return usageExit("account bootstrap requires --vault-name and --device-id")
			}
			kit := make([]byte, 32)
			if _, err := rand.Read(kit); err != nil {
				return urfave.Exit("cannot generate recovery kit", 1)
			}
			signing, recipient, err := vault.GenerateDeviceKeys()
			if err != nil {
				return urfave.Exit("cannot generate device keys", 1)
			}
			keyID := deviceKeyID(signing.Public().(ed25519.PublicKey))
			material := vault.DeviceMaterial{DeviceID: command.String("device-id"), KeyID: keyID, Signing: signing, Recipient: recipient}
			bootstrapped, err := vault.Bootstrap(kit, command.String("vault-name"), material)
			if err != nil {
				return urfave.Exit(err.Error(), 1)
			}
			keyring, err := openKeyring()
			if err != nil {
				return urfave.Exit(keyringError(err), 1)
			}
			defer keyring.Close()
			if _, err := keyring.LoadDeviceKeys(ctx, bootstrapped.Vault, material.DeviceID); err == nil {
				return urfave.Exit("device keys already exist for this vault and device", 1)
			} else if !errors.Is(err, platform.ErrKeyringItemNotFound) {
				return urfave.Exit(keyringError(err), 1)
			}
			if err := keyring.StoreDeviceKeys(ctx, bootstrapped.Vault, material); err != nil {
				return urfave.Exit(keyringError(err), 1)
			}
			if err := recordVaultSelection(ctx, sessionOptions.env, bootstrapped.Vault, material.DeviceID); err != nil {
				return urfave.Exit("device keys were stored but local vault selection could not be recorded", 1)
			}
			kitPublic, err := vault.RecoveryKitSigningPublicKey(kit, bootstrapped.Vault)
			if err != nil {
				return urfave.Exit("cannot derive recovery kit signing key", 1)
			}
			checkpointFingerprint := sha256.Sum256(bootstrapped.Checkpoint)
			kitPublicFingerprint := sha256.Sum256(kitPublic)
			output := fmt.Sprintf("recovery kit (keep offline): %s\nvault fingerprint: %x\nanchor fingerprint: %x\ncheckpoint fingerprint: %x\nkit public-key fingerprint: %x\n", groupRecoveryKit(kit), bootstrapped.Vault, bootstrapped.Anchor, checkpointFingerprint, kitPublicFingerprint)
			return writeCommandOutput(command, output)
		},
	})

	roleFlag := &urfave.StringFlag{Name: "role", Usage: "requested role (publisher or restore_only)", OnlyOnce: true}
	vaultFlag := &urfave.StringFlag{Name: "vault", Usage: "vault fingerprint (64 hexadecimal characters)", OnlyOnce: true}
	confirmFlag := &urfave.StringFlag{Name: "confirm", Usage: "expected transcript fingerprint", OnlyOnce: true}
	requestFlag := &urfave.StringFlag{Name: "request", Usage: "write public enrollment request JSON after confirmation", OnlyOnce: true}
	enroll := configure(&urfave.Command{
		Name:  "enroll",
		Flags: []urfave.Flag{vaultFlag, deviceIDFlag, roleFlag, confirmFlag, requestFlag},
		Action: func(ctx context.Context, command *urfave.Command) error {
			if command.NArg() != 0 || command.String("vault") == "" || command.String("device-id") == "" || command.String("role") == "" {
				return usageExit("account enroll requires --vault, --device-id and --role")
			}
			if command.IsSet("request") && command.String("request") == "" {
				return usageExit("--request requires a file path")
			}
			vaultID, err := parseVaultFingerprint(command.String("vault"))
			if err != nil {
				return usageExit("--vault must be a 32-byte hexadecimal fingerprint")
			}
			role, err := parseEnrollmentRole(command.String("role"))
			if err != nil {
				return usageExit("--role must be publisher or restore_only")
			}
			keyring, err := openKeyring()
			if err != nil {
				return urfave.Exit(keyringError(err), 1)
			}
			defer keyring.Close()
			material, err := keyring.LoadDeviceKeys(ctx, vaultID, command.String("device-id"))
			if errors.Is(err, platform.ErrKeyringItemNotFound) {
				signing, recipient, generateErr := vault.GenerateDeviceKeys()
				if generateErr != nil {
					return urfave.Exit("cannot generate device keys", 1)
				}
				material = vault.DeviceMaterial{
					DeviceID: command.String("device-id"),
					KeyID:    deviceKeyID(signing.Public().(ed25519.PublicKey)), Signing: signing, Recipient: recipient,
				}
				if err := keyring.StoreDeviceKeys(ctx, vaultID, material); err != nil {
					return urfave.Exit(keyringError(err), 1)
				}
			} else if err != nil {
				return urfave.Exit(keyringError(err), 1)
			}
			if material.Recipient == nil || len(material.Signing) != ed25519.PrivateKeySize {
				return urfave.Exit("device key item is invalid", 1)
			}
			output, fingerprint := enrollmentTranscript(vaultID, material, role)
			if command.IsSet("confirm") {
				confirmation, err := parseTranscriptFingerprint(command.String("confirm"))
				if err != nil || !bytes.Equal(confirmation, fingerprint[:]) {
					if writeErr := writeCommandOutput(command, output); writeErr != nil {
						return writeErr
					}
					return urfave.Exit("transcript fingerprint confirmation mismatch", 1)
				}
				if command.IsSet("request") {
					requestBytes, _, requestErr := makeEnrollmentRequest(vaultID, material, role)
					if requestErr != nil {
						return urfave.Exit("cannot prepare public enrollment request", 1)
					}
					defer clear(requestBytes)
					if writeErr := writePublicRequestFile(command.String("request"), requestBytes); writeErr != nil {
						return urfave.Exit(escapeErrorMessage(writeErr.Error()), 1)
					}
					output += "public enrollment request: written\n"
				}
				if err := recordVaultSelection(ctx, sessionOptions.env, vaultID, material.DeviceID); err != nil {
					return urfave.Exit("device keys were prepared but local vault selection could not be recorded", 1)
				}
				output += "transcript confirmed; no certificate or remote operation was performed\n"
			} else {
				if err := writeCommandOutput(command, output); err != nil {
					return err
				}
				return urfave.Exit("transcript fingerprint confirmation required; repeat with --confirm=<transcript-fingerprint>", 1)
			}
			return writeCommandOutput(command, output)
		},
	})

	importBundle := configure(&urfave.Command{
		Name: "import-bundle", Flags: importBundleFlags(), Action: importBundleAction(importFactory),
	})

	recovery := configure(&urfave.Command{
		Name:  "recovery",
		Flags: []urfave.Flag{&urfave.StringFlag{Name: "vault-name", Usage: "vault name", OnlyOnce: true}, &urfave.StringFlag{Name: "checkpoint", Usage: "local signed checkpoint object", OnlyOnce: true}},
		Action: func(_ context.Context, command *urfave.Command) error {
			return runAccountRecovery(command)
		},
	})

	verify := configure(&urfave.Command{
		Name:  "verify",
		Flags: []urfave.Flag{&urfave.StringFlag{Name: "bundle", Usage: "local verification bundle path", OnlyOnce: true}, &urfave.StringFlag{Name: "trust-anchor", Usage: "operator-supplied 32-byte hexadecimal root fingerprint when no local checkpoint exists", OnlyOnce: true}, &urfave.BoolFlag{Name: "record", Usage: "advance the local checkpoint after current or descendant verification", OnlyOnce: true}, &urfave.BoolFlag{Name: "consent", Usage: "confirm inspection/export-only continuation for unverifiable state", OnlyOnce: true}},
		Action: func(ctx context.Context, command *urfave.Command) error {
			return runAccountVerify(ctx, command)
		},
	})

	sessionCommands := accountSessionCommands(openKeyring, sessionOptions)
	for _, command := range sessionCommands {
		configure(command)
	}

	root := configure(&urfave.Command{
		Name:     "account",
		Commands: append([]*urfave.Command{bootstrap, enroll, importBundle, recovery, verify}, sessionCommands...),
		Action: func(_ context.Context, _ *urfave.Command) error {
			return usageExit("expected login, logout, status, bootstrap, enroll, import-bundle, recovery or verify")
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

func parseTranscriptFingerprint(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("invalid transcript fingerprint")
	}
	return decoded, nil
}

func parseEnrollmentRole(value string) (vault.Role, error) {
	switch value {
	case "publisher":
		return vault.RolePublisher, nil
	case "restore_only":
		return vault.RoleRestoreOnly, nil
	default:
		return 0, errors.New("invalid enrollment role")
	}
}

func enrollmentTranscript(vaultID [32]byte, material vault.DeviceMaterial, role vault.Role) (string, [32]byte) {
	signingPublic := material.Signing.Public().(ed25519.PublicKey)
	recipientPublic := material.Recipient.PublicKey().Bytes()
	fingerprint := vault.EnrollmentTranscriptFingerprint(vaultID, material.DeviceID, material.KeyID, role, signingPublic, recipientPublic)
	signingFingerprint := sha256.Sum256(signingPublic)
	recipientFingerprint := sha256.Sum256(recipientPublic)
	var output strings.Builder
	fmt.Fprintf(&output, "vault: %x\n", vaultID)
	fmt.Fprintf(&output, "device id: %s\n", escapeField(material.DeviceID))
	fmt.Fprintf(&output, "key id: %x\n", material.KeyID)
	fmt.Fprintf(&output, "requested role: %s\n", roleName(role))
	fmt.Fprintf(&output, "signing public key fingerprint: %x\n", signingFingerprint)
	fmt.Fprintf(&output, "recipient public key fingerprint: %x\n", recipientFingerprint)
	fmt.Fprintf(&output, "transcript fingerprint: %x\n", fingerprint)
	return output.String(), fingerprint
}

func roleName(role vault.Role) string {
	switch role {
	case vault.RolePublisher:
		return "publisher"
	case vault.RoleRestoreOnly:
		return "restore_only"
	default:
		return "invalid"
	}
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
