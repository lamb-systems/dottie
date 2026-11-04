package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
)

const maxEnrollmentRequestBytes = 16 << 10

type orchestrationCoordinator interface {
	ResolveSelection(context.Context, service.VaultSelection) (service.VaultSelection, error)
	Pull(context.Context, service.VaultSelection) (service.ReadOutcome, error)
	Push(context.Context, service.VaultSelection) (service.PushResult, error)
	Enroll(context.Context, service.EnrollRequest) (service.AdministrativeResult, error)
	RevokeApproval(context.Context, service.VaultSelection, string, []byte) (service.RevokeApprovalTranscript, error)
	Revoke(context.Context, service.RevokeRequest) (service.AdministrativeResult, error)
	ImportOnboarding(context.Context, []byte, [32]byte, [32]byte, string) error
}

type orchestrationFactory func(context.Context, *urfave.Command, bool) (orchestrationCoordinator, service.VaultSelection, func(), error)

type enrollmentRequestFile struct {
	Version             uint64 `json:"version"`
	Vault               string `json:"vault"`
	DeviceID            string `json:"device_id"`
	KeyID               string `json:"key_id"`
	SigningPublicKey    string `json:"signing_public_key"`
	RecipientPublicKey  string `json:"recipient_public_key"`
	RequestedRole       string `json:"requested_role"`
	ApprovalFingerprint string `json:"approval_fingerprint"`
}

func runOrchestration(args []string, stdout, stderr io.Writer, openKeyring accountKeyringFactory, env func(string) string) int {
	code := 0
	command := newOrchestrationCommand(stdout, stderr, &code, productionOrchestrationFactory(openKeyring, env))
	arguments := append([]string{"dottie"}, args...)
	ctx := context.Background()
	if err := command.Run(ctx, arguments); err != nil && code == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	return code
}

func newOrchestrationCommand(stdout, stderr io.Writer, exitCode *int, factory orchestrationFactory) *urfave.Command {
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
	selectorFlags := func() []urfave.Flag {
		return []urfave.Flag{
			&urfave.StringFlag{Name: "vault", Usage: "local vault fingerprint", OnlyOnce: true},
			&urfave.StringFlag{Name: "device-id", Usage: "selected local device identifier", OnlyOnce: true},
			&urfave.StringFlag{Name: "did", Usage: "signed-in account DID", OnlyOnce: true},
			&urfave.StringFlag{Name: "handle", Usage: "signed-in account handle", OnlyOnce: true},
		}
	}
	push := configure(&urfave.Command{Name: "push", Flags: selectorFlags(), Action: func(ctx context.Context, command *urfave.Command) error {
		if command.NArg() != 0 {
			return usageExit("push takes no positional arguments")
		}
		if err := validateOrchestrationRemoteFlags(command); err != nil {
			return err
		}
		coordinator, selection, closeResources, err := factory(ctx, command, true)
		if err != nil {
			if writeErr := writeCommandOutput(command, renderPush(service.StatusRejected)); writeErr != nil {
				return writeErr
			}
			return urfave.Exit("push refused: account, local selection or coordinator unavailable", 3)
		}
		defer closeResources()
		result, pushErr := coordinator.Push(ctx, selection)
		status := classifyPushResult(result, pushErr)
		if err := writeCommandOutput(command, renderPush(status)); err != nil {
			return err
		}
		return pushExit(status)
	}})
	syncCommand := configure(&urfave.Command{Name: "sync", Flags: selectorFlags(), Action: func(ctx context.Context, command *urfave.Command) error {
		if command.NArg() != 0 {
			return usageExit("sync takes no positional arguments")
		}
		if err := validateOrchestrationRemoteFlags(command); err != nil {
			return err
		}
		coordinator, selection, closeResources, err := factory(ctx, command, true)
		if err != nil {
			if writeErr := writeCommandOutput(command, "pull: not run; coordinator unavailable\npush: not run\n"); writeErr != nil {
				return writeErr
			}
			return urfave.Exit("sync refused: account, local selection or coordinator unavailable", 3)
		}
		defer closeResources()
		pulled, pullErr := coordinator.Pull(ctx, selection)
		if pullErr != nil {
			if err := writeCommandOutput(command, "pull: refused\npush: not run\n"); err != nil {
				return err
			}
			return urfave.Exit("sync pull refused; push was not run", 3)
		}
		var output strings.Builder
		fmt.Fprintf(&output, "pull: verified\nepoch: %d\nremote entries: %d\ndownloads: pending explicit restore review; nothing applied\n", pulled.Read.EpochSeq, len(pulled.Snapshot.Entries))
		pushed, pushErr := coordinator.Push(ctx, selection)
		status := classifyPushResult(pushed, pushErr)
		output.WriteString(renderPush(status))
		if err := writeCommandOutput(command, output.String()); err != nil {
			return err
		}
		return pushExit(status)
	}})

	list := configure(&urfave.Command{Name: "list", Flags: selectorFlags(), Action: func(ctx context.Context, command *urfave.Command) error {
		if command.NArg() != 0 {
			return usageExit("devices list takes no positional arguments")
		}
		if err := validateOrchestrationRemoteFlags(command); err != nil {
			return err
		}
		coordinator, selection, closeResources, err := factory(ctx, command, true)
		if err != nil {
			return urfave.Exit("devices list refused: account, local selection or coordinator unavailable", 3)
		}
		defer closeResources()
		result, err := coordinator.Pull(ctx, selection)
		if err != nil {
			return urfave.Exit("verified device list is unavailable", 3)
		}
		return writeCommandOutput(command, renderDevices(result))
	}})

	enroll := configure(&urfave.Command{Name: "enroll", Flags: []urfave.Flag{
		&urfave.StringFlag{Name: "vault", Usage: "expected vault fingerprint", OnlyOnce: true},
		&urfave.StringFlag{Name: "root-device-id", Usage: "selected administrative root device", OnlyOnce: true},
		&urfave.StringFlag{Name: "did", Usage: "signed-in account DID", OnlyOnce: true},
		&urfave.StringFlag{Name: "handle", Usage: "signed-in account handle", OnlyOnce: true},
		&urfave.StringFlag{Name: "request", Usage: "public enrollment request file", OnlyOnce: true},
		&urfave.StringFlag{Name: "kit-file", Usage: "private recovery kit file (mode 0600)", OnlyOnce: true},
		&urfave.StringFlag{Name: "bundle-out", Usage: "new public onboarding bundle output", OnlyOnce: true},
		&urfave.BoolFlag{Name: "overwrite", Usage: "replace an existing regular bundle output", OnlyOnce: true},
	}, Action: func(ctx context.Context, command *urfave.Command) error {
		if command.NArg() != 0 || command.String("request") == "" || command.String("kit-file") == "" || command.String("bundle-out") == "" {
			return usageExit("devices enroll requires --request, --kit-file and --bundle-out")
		}
		if err := validateAdminRemoteFlags(command); err != nil {
			return err
		}
		if err := checkBundleOutput(command.String("bundle-out"), command.Bool("overwrite")); err != nil {
			return urfave.Exit(err.Error(), 3)
		}
		requestBytes, err := readRegularFile(command.String("request"), maxEnrollmentRequestBytes)
		if err != nil {
			return urfave.Exit("cannot read public enrollment request file", 3)
		}
		request, err := decodeEnrollmentRequest(requestBytes)
		clear(requestBytes)
		if err != nil {
			return urfave.Exit(escapeErrorMessage(err.Error()), 3)
		}
		if command.IsSet("vault") {
			vaultID, parseErr := parseVaultFingerprint(command.String("vault"))
			if parseErr != nil || vaultID != request.Vault {
				return urfave.Exit("--vault does not match the enrollment request", 3)
			}
		}
		kit, err := readRecoveryKitFile(command.String("kit-file"))
		if err != nil {
			return urfave.Exit(escapeErrorMessage(err.Error()), 3)
		}
		defer clear(kit)
		coordinator, selection, closeResources, err := factory(ctx, command, true)
		if err != nil {
			return urfave.Exit("administrative enrollment refused: account or local coordinator unavailable", 3)
		}
		defer closeResources()
		if selection.Vault == ([32]byte{}) {
			selection.Vault = request.Vault
		}
		selected, err := coordinator.ResolveSelection(ctx, selection)
		if err != nil {
			return urfave.Exit("administrative enrollment refused: local root selection is unavailable", 3)
		}
		if selected.Vault != request.Vault {
			return urfave.Exit("administrative enrollment refused: request vault differs from selected root vault", 3)
		}
		result, err := coordinator.Enroll(ctx, service.EnrollRequest{
			Selection: selected, Device: request.Device, Role: request.Role,
			ApprovalFingerprint: request.ApprovalFingerprint, Kit: kit,
		})
		status := administrativeStatus(result, err)
		if status != service.StatusCommitted {
			if writeErr := writeCommandOutput(command, renderAdministrative("enroll", status, selected.Vault, request.Device.DeviceID, request.Role, request.ApprovalFingerprint, result)); writeErr != nil {
				return writeErr
			}
			return administrativeExit(status)
		}
		if len(result.EncodedBundle) == 0 {
			if writeErr := writeCommandOutput(command, renderAdministrative("enroll", service.StatusUnavailable, selected.Vault, request.Device.DeviceID, request.Role, request.ApprovalFingerprint, result)+"bundle output: unavailable\n"); writeErr != nil {
				return writeErr
			}
			return urfave.Exit("enrollment committed but public bundle is unavailable", 4)
		}
		if err := writeBundleFile(command.String("bundle-out"), result.EncodedBundle, command.Bool("overwrite")); err != nil {
			if writeErr := writeCommandOutput(command, renderAdministrative("enroll", service.StatusCommitted, selected.Vault, request.Device.DeviceID, request.Role, request.ApprovalFingerprint, result)+"bundle output: failed\n"); writeErr != nil {
				return writeErr
			}
			return urfave.Exit("enrollment committed but bundle output could not be written", 4)
		}
		if err := writeCommandOutput(command, renderAdministrative("enroll", status, selected.Vault, request.Device.DeviceID, request.Role, request.ApprovalFingerprint, result)+"bundle output: written\n"); err != nil {
			return err
		}
		return nil
	}})

	revoke := configure(&urfave.Command{Name: "revoke", Flags: []urfave.Flag{
		&urfave.StringFlag{Name: "vault", Usage: "local vault fingerprint", OnlyOnce: true},
		&urfave.StringFlag{Name: "root-device-id", Usage: "selected administrative root device", OnlyOnce: true},
		&urfave.StringFlag{Name: "device-id", Usage: "device identifier to revoke", OnlyOnce: true},
		&urfave.StringFlag{Name: "did", Usage: "signed-in account DID", OnlyOnce: true},
		&urfave.StringFlag{Name: "handle", Usage: "signed-in account handle", OnlyOnce: true},
		&urfave.StringFlag{Name: "kit-file", Usage: "private recovery kit file (mode 0600)", OnlyOnce: true},
		&urfave.StringFlag{Name: "bundle-out", Usage: "optional public successor onboarding bundle", OnlyOnce: true},
		&urfave.StringFlag{Name: "confirm", Usage: "fingerprint-bound revocation approval", OnlyOnce: true},
		&urfave.BoolFlag{Name: "overwrite", Usage: "replace an existing regular bundle output", OnlyOnce: true},
	}, Action: func(ctx context.Context, command *urfave.Command) error {
		if command.NArg() != 0 || command.String("device-id") == "" || command.String("kit-file") == "" {
			return usageExit("devices revoke requires --device-id and --kit-file")
		}
		if err := validateAdminRemoteFlags(command); err != nil {
			return err
		}
		if command.Bool("overwrite") && command.String("bundle-out") == "" {
			return usageExit("--overwrite requires --bundle-out")
		}
		if command.String("bundle-out") != "" {
			if err := checkBundleOutput(command.String("bundle-out"), command.Bool("overwrite")); err != nil {
				return urfave.Exit(err.Error(), 3)
			}
		}
		kit, err := readRecoveryKitFile(command.String("kit-file"))
		if err != nil {
			return urfave.Exit(escapeErrorMessage(err.Error()), 3)
		}
		defer clear(kit)
		coordinator, selection, closeResources, err := factory(ctx, command, true)
		if err != nil {
			return urfave.Exit("administrative revocation refused: account or local coordinator unavailable", 3)
		}
		defer closeResources()
		selected, err := coordinator.ResolveSelection(ctx, selection)
		if err != nil {
			return urfave.Exit("administrative revocation refused: local root selection is unavailable", 3)
		}
		transcript, err := coordinator.RevokeApproval(ctx, selected, command.String("device-id"), kit)
		if err != nil {
			return urfave.Exit("revocation approval transcript is unavailable", 3)
		}
		transcriptOutput := renderRevokeApprovalTranscript(transcript)
		if !command.IsSet("confirm") {
			if writeErr := writeCommandOutput(command, transcriptOutput); writeErr != nil {
				return writeErr
			}
			return urfave.Exit("repeat with --confirm="+hex.EncodeToString(transcript.ApprovalFingerprint[:]), 3)
		}
		confirmation, err := decodeFixedHex(command.String("confirm"), 32)
		if err != nil {
			return usageExit("--confirm must be a 32-byte hexadecimal approval fingerprint")
		}
		if !bytes.Equal(confirmation, transcript.ApprovalFingerprint[:]) {
			if writeErr := writeCommandOutput(command, transcriptOutput); writeErr != nil {
				return writeErr
			}
			return urfave.Exit("revocation approval fingerprint mismatch; no transition was attempted", 3)
		}
		result, err := coordinator.Revoke(ctx, service.RevokeRequest{Selection: selected, DeviceID: command.String("device-id"), Kit: kit, ApprovalFingerprint: transcript.ApprovalFingerprint})
		status := administrativeStatus(result, err)
		output := transcriptOutput + renderAdministrative("revoke", status, selected.Vault, command.String("device-id"), 0, [32]byte{}, result)
		if status == service.StatusCommitted && command.String("bundle-out") != "" {
			if len(result.EncodedBundle) == 0 || writeBundleFile(command.String("bundle-out"), result.EncodedBundle, command.Bool("overwrite")) != nil {
				output += "bundle output: failed\n"
				if writeErr := writeCommandOutput(command, output); writeErr != nil {
					return writeErr
				}
				return urfave.Exit("revocation committed but bundle output could not be written", 4)
			}
			output += "bundle output: written\n"
		}
		output += "historical ciphertext: previously published ciphertext may remain available; revocation cannot erase copies or keys already obtained\n"
		if err := writeCommandOutput(command, output); err != nil {
			return err
		}
		return administrativeExit(status)
	}})

	devices := configure(&urfave.Command{Name: "devices", Commands: []*urfave.Command{list, enroll, revoke}, Action: func(_ context.Context, _ *urfave.Command) error {
		return usageExit("expected list, enroll or revoke")
	}})
	root := configure(&urfave.Command{Name: "dottie", Commands: []*urfave.Command{push, syncCommand, devices}, Writer: stdout, ErrWriter: stderr})
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

func productionOrchestrationFactory(openKeyring accountKeyringFactory, env func(string) string) orchestrationFactory {
	return func(ctx context.Context, command *urfave.Command, needsRemote bool) (orchestrationCoordinator, service.VaultSelection, func(), error) {
		paths, err := platform.Resolve(env)
		if err != nil {
			return nil, service.VaultSelection{}, func() {}, err
		}
		store, err := state.Open(paths)
		if err != nil {
			return nil, service.VaultSelection{}, func() {}, err
		}
		keyring, err := openKeyring()
		if err != nil {
			_ = store.Close()
			return nil, service.VaultSelection{}, func() {}, err
		}
		closeResources := func() { _ = keyring.Close(); _ = store.Close() }
		dependencies := service.Dependencies{
			Config: service.FileConfigPort{Paths: paths}, State: store, DeviceKeys: keyring,
			Settings: manualGNOMESettings(), Paths: paths, Clock: time.Now,
		}
		var identity atproto.Identity
		if needsRemote {
			client, clientErr := newAuthorizedAccountClient(keyring, env)
			if clientErr != nil {
				closeResources()
				return nil, service.VaultSelection{}, func() {}, clientErr
			}
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
			if err != nil || identity.DID == "" {
				closeResources()
				if err == nil {
					err = errors.New("account identity is unavailable")
				}
				return nil, service.VaultSelection{}, func() {}, err
			}
			session, sessionErr := client.LoadSession(ctx, identity.DID)
			if sessionErr != nil {
				closeResources()
				return nil, service.VaultSelection{}, func() {}, sessionErr
			}
			api, apiErr := atproto.NewSessionAPIClient(client, identity, identity.Handle, session)
			if apiErr != nil {
				closeResources()
				return nil, service.VaultSelection{}, func() {}, apiErr
			}
			transport := atproto.NewATClientTransport(api)
			dependencies.Trust = service.StateTrustSource{State: store, Keyring: keyring}
			dependencies.Session = manualReadSession{identity: identity}
			dependencies.Remote = service.VaultReader{Reader: atproto.VaultReader{Transport: transport, ObservationStore: store, Budgets: atproto.DefaultBudgets(), Clock: time.Now}}
			dependencies.Publisher = sessionPublicationPort{identity: identity, transport: transport}
		}
		coordinator, err := service.NewCoordinator(dependencies)
		if err != nil {
			closeResources()
			return nil, service.VaultSelection{}, func() {}, err
		}
		selection := service.VaultSelection{}
		if command.Name == "enroll" || command.Name == "revoke" {
			selection.DeviceID = command.String("root-device-id")
		} else {
			selection.DeviceID = command.String("device-id")
		}
		if command.IsSet("vault") {
			selection.Vault, err = parseVaultFingerprint(command.String("vault"))
			if err != nil {
				closeResources()
				return nil, service.VaultSelection{}, func() {}, errors.New("vault selector is invalid")
			}
		}
		return coordinator, selection, closeResources, nil
	}
}

type sessionPublicationPort struct {
	identity  atproto.Identity
	transport atproto.Transport
}

func (port sessionPublicationPort) PublicationIO(_ context.Context, _ service.VaultSelection, _ service.TrustMaterial, _ service.ReadOutcome) (atproto.ATProtoPublicationIO, error) {
	if port.identity.DID == "" || port.identity.DIDDocumentID == "" || len(port.identity.VerificationMethods) == 0 || port.transport == nil {
		return atproto.ATProtoPublicationIO{}, errors.New("publication session evidence is unavailable")
	}
	return atproto.ATProtoPublicationIO{
		Reader: atproto.RevisionReader{Transport: port.transport, Budgets: atproto.DefaultBudgets(), DIDDocumentID: port.identity.DIDDocumentID,
			VerificationMethods: append([]atproto.VerificationMethod(nil), port.identity.VerificationMethods...)},
		Transport: port.transport, BlobUploadLimit: vault.MaxEnvelopeBytes, DID: port.identity.DID,
	}, nil
}

func validateOrchestrationRemoteFlags(command *urfave.Command) error {
	if command.IsSet("did") == command.IsSet("handle") {
		return usageExit("supply exactly one of --did or --handle")
	}
	if command.IsSet("did") && command.String("did") == "" || command.IsSet("handle") && command.String("handle") == "" {
		return usageExit("account selector value is missing")
	}
	if command.IsSet("vault") && command.String("vault") == "" || command.IsSet("device-id") && command.String("device-id") == "" {
		return usageExit("vault or device selector value is missing")
	}
	return nil
}

func validateAdminRemoteFlags(command *urfave.Command) error {
	if command.IsSet("did") == command.IsSet("handle") {
		return usageExit("supply exactly one of --did or --handle")
	}
	if command.IsSet("did") && command.String("did") == "" || command.IsSet("handle") && command.String("handle") == "" {
		return usageExit("account selector value is missing")
	}
	if command.IsSet("vault") && command.String("vault") == "" || command.IsSet("root-device-id") && command.String("root-device-id") == "" {
		return usageExit("vault or root-device selector value is missing")
	}
	return nil
}

func classifyPushResult(result service.PushResult, err error) service.StatusState {
	if err != nil && (result.Status == service.StatusCommitted || result.Status == service.StatusNoOp) {
		return service.StatusUnavailable
	}
	if result.Status != "" {
		return result.Status
	}
	switch {
	case errors.Is(err, service.ErrPushBlocked):
		return service.StatusConflicted
	case errors.Is(err, service.ErrBaseRecordingFailed):
		return service.StatusBaseRecordingFailed
	case errors.Is(err, atproto.ErrPublicationQueued):
		return service.StatusQueued
	case errors.Is(err, atproto.ErrPublicationStarved):
		return service.StatusStarved
	case errors.Is(err, atproto.ErrPublicationRetryFenceLost), errors.Is(err, atproto.ErrFenceLost):
		return service.StatusFenceLost
	case errors.Is(err, atproto.ErrPublicationSuperseded):
		return service.StatusSuperseded
	case errors.Is(err, atproto.ErrPublicationUnavailable):
		return service.StatusUnavailable
	case errors.Is(err, atproto.ErrPublicationRejected), errors.Is(err, atproto.ErrBatchRejected):
		return service.StatusRejected
	case err != nil:
		return service.StatusRejected
	default:
		return service.StatusUnavailable
	}
}

func renderPush(status service.StatusState) string {
	return "push: " + escapeField(string(status)) + "\n"
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

func administrativeStatus(result service.AdministrativeResult, err error) service.StatusState {
	if result.Status != "" {
		return result.Status
	}
	if err != nil {
		return service.StatusRejected
	}
	return service.StatusUnavailable
}

func administrativeExit(status service.StatusState) error {
	switch status {
	case service.StatusCommitted:
		return nil
	case service.StatusQueued, service.StatusStarved, service.StatusFenceLost, service.StatusSuperseded, service.StatusUnavailable, service.StatusBaseRecordingFailed:
		return urfave.Exit("administrative operation did not complete", 4)
	default:
		return urfave.Exit("administrative operation refused", 3)
	}
}

func renderRevokeApprovalTranscript(transcript service.RevokeApprovalTranscript) string {
	return fmt.Sprintf("revocation approval transcript\nvault: %x\ndevice id: %s\ncurrent role: %s\ncurrent signing-key fingerprint: %x\ncurrent recipient-key fingerprint: %x\ncurrent epoch: %d\nsuccessor epoch: %d\nkit signing-key fingerprint: %x\napproval fingerprint: %x\n",
		transcript.Vault, escapeField(transcript.DeviceID), escapeField(deviceRoleName(transcript.Role)),
		transcript.SigningKeyFingerprint, transcript.RecipientKeyFingerprint, transcript.CurrentEpoch,
		transcript.SuccessorEpoch, transcript.KitSigningKeyFingerprint, transcript.ApprovalFingerprint)
}

func renderAdministrative(operation string, status service.StatusState, vaultID [32]byte, deviceID string, role vault.Role, approval [32]byte, result service.AdministrativeResult) string {
	var output strings.Builder
	fmt.Fprintf(&output, "operation: %s\nstatus: %s\nvault: %x\ndevice id: %s\n", escapeField(operation), escapeField(string(status)), vaultID, escapeField(deviceID))
	if role != 0 {
		fmt.Fprintf(&output, "requested role: %s\napproval fingerprint: %x\n", escapeField(roleName(role)), approval)
	}
	if checkpoint, err := vault.DecodeCheckpoint(result.Bundle.Checkpoint); err == nil {
		fingerprint := sha256.Sum256(result.Bundle.Checkpoint)
		fmt.Fprintf(&output, "successor epoch: %d\ncheckpoint fingerprint: %x\n", checkpoint.EpochSeq, fingerprint)
	} else {
		output.WriteString("successor epoch: unavailable\ncheckpoint fingerprint: unavailable\n")
	}
	return output.String()
}

func decodeEnrollmentRequest(encoded []byte) (parsedEnrollmentRequest, error) {
	var request enrollmentRequestFile
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return parsedEnrollmentRequest{}, errors.New("public enrollment request is not valid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return parsedEnrollmentRequest{}, errors.New("public enrollment request has trailing data")
	}
	if request.Version != 1 || request.Vault == "" || request.DeviceID == "" || request.KeyID == "" || request.SigningPublicKey == "" || request.RecipientPublicKey == "" || request.RequestedRole == "" || request.ApprovalFingerprint == "" {
		return parsedEnrollmentRequest{}, errors.New("public enrollment request is missing required fields")
	}
	vaultID, err := parseVaultFingerprint(request.Vault)
	if err != nil {
		return parsedEnrollmentRequest{}, errors.New("public enrollment request vault must be a 32-byte hexadecimal identifier")
	}
	keyID, err := decodeFixedHex(request.KeyID, 32)
	if err != nil {
		return parsedEnrollmentRequest{}, errors.New("public enrollment request key id is invalid")
	}
	signingPublic, err := decodeFixedHex(request.SigningPublicKey, 32)
	if err != nil {
		return parsedEnrollmentRequest{}, errors.New("public enrollment request signing public key is invalid")
	}
	recipientPublic, err := decodeFixedHex(request.RecipientPublicKey, 32)
	if err != nil {
		return parsedEnrollmentRequest{}, errors.New("public enrollment request recipient public key is invalid")
	}
	approval, err := decodeFixedHex(request.ApprovalFingerprint, 32)
	if err != nil {
		return parsedEnrollmentRequest{}, errors.New("public enrollment request approval fingerprint is invalid")
	}
	role, err := parseEnrollmentRole(request.RequestedRole)
	if err != nil {
		return parsedEnrollmentRequest{}, errors.New("public enrollment request role is invalid")
	}
	keyDigest := sha256.Sum256(signingPublic)
	if !bytes.Equal(keyID, keyDigest[:]) {
		return parsedEnrollmentRequest{}, errors.New("public enrollment request key id does not match its signing public key")
	}
	fingerprint := vault.EnrollmentTranscriptFingerprint(vaultID, request.DeviceID, keyID, role, signingPublic, recipientPublic)
	if !bytes.Equal(approval, fingerprint[:]) {
		return parsedEnrollmentRequest{}, errors.New("public enrollment request approval fingerprint does not match its public fields")
	}
	return parsedEnrollmentRequest{
		Vault: vaultID, Device: vault.PublicDeviceInput{DeviceID: request.DeviceID, KeyID: keyID, SigningPublicKey: signingPublic, RecipientPublicKey: recipientPublic},
		Role: role, ApprovalFingerprint: fingerprint,
	}, nil
}

type parsedEnrollmentRequest struct {
	Vault               [32]byte
	Device              vault.PublicDeviceInput
	Role                vault.Role
	ApprovalFingerprint [32]byte
}

func makeEnrollmentRequest(vaultID [32]byte, material vault.DeviceMaterial, role vault.Role) ([]byte, [32]byte, error) {
	if len(material.Signing) != ed25519.PrivateKeySize || material.Recipient == nil || len(material.KeyID) != sha256.Size {
		return nil, [32]byte{}, errors.New("device key item is invalid")
	}
	signingPublic := material.Signing.Public().(ed25519.PublicKey)
	recipientPublic := material.Recipient.PublicKey().Bytes()
	fingerprint := vault.EnrollmentTranscriptFingerprint(vaultID, material.DeviceID, material.KeyID, role, signingPublic, recipientPublic)
	request := enrollmentRequestFile{
		Version: 1, Vault: hex.EncodeToString(vaultID[:]), DeviceID: material.DeviceID,
		KeyID: hex.EncodeToString(material.KeyID), SigningPublicKey: hex.EncodeToString(signingPublic),
		RecipientPublicKey: hex.EncodeToString(recipientPublic), RequestedRole: roleName(role),
		ApprovalFingerprint: hex.EncodeToString(fingerprint[:]),
	}
	encoded, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return nil, [32]byte{}, errors.New("cannot encode public enrollment request")
	}
	return append(encoded, '\n'), fingerprint, nil
}

func decodeFixedHex(value string, length int) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != length {
		return nil, errors.New("invalid fixed-length hexadecimal value")
	}
	return decoded, nil
}

func deviceRoleName(role vault.Role) string {
	switch role {
	case vault.RoleRoot:
		return "root"
	case vault.RolePublisher:
		return "publisher"
	case vault.RoleRestoreOnly:
		return "restore_only"
	default:
		return "unknown"
	}
}

func renderDevices(result service.ReadOutcome) string {
	type listedDevice struct {
		id          string
		role        string
		fingerprint string
		revoked     bool
	}
	devices := make(map[string]listedDevice)
	for _, binding := range result.Read.Policy.Roles {
		item := devices[binding.DeviceID]
		item.id = binding.DeviceID
		item.role = deviceRoleName(vault.Role(binding.Role))
		devices[binding.DeviceID] = item
	}
	for _, recipient := range result.Read.Policy.Recipients {
		item := devices[recipient.DeviceID]
		item.id = recipient.DeviceID
		if len(recipient.PublicKey) != 0 {
			fingerprint := sha256.Sum256(recipient.PublicKey)
			item.fingerprint = hex.EncodeToString(fingerprint[:])
		}
		devices[recipient.DeviceID] = item
	}
	for _, revoked := range result.Read.Control.Revoked {
		item := devices[revoked.DeviceID]
		item.id = revoked.DeviceID
		item.revoked = true
		devices[revoked.DeviceID] = item
	}
	ids := make([]string, 0, len(devices))
	for id := range devices {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var output strings.Builder
	fmt.Fprintf(&output, "read: verified\nepoch: %d\n", result.Read.EpochSeq)
	if len(ids) == 0 {
		output.WriteString("no devices listed\n")
		return output.String()
	}
	for _, id := range ids {
		item := devices[id]
		if item.role == "" {
			item.role = "unknown"
		}
		fingerprint := item.fingerprint
		if fingerprint == "" {
			fingerprint = "unavailable"
		}
		fmt.Fprintf(&output, "device id: %s\trole: %s\tepoch: %d\trevoked: %t\tkey fingerprint: %s\n",
			escapeField(item.id), escapeField(item.role), result.Read.EpochSeq, item.revoked, fingerprint)
	}
	return output.String()
}

func readRecoveryKitFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, errors.New("kit file must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("kit file cannot be opened")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) {
		return nil, errors.New("kit file must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("kit file grants group or world access; run chmod 600 %s", escapeField(path))
	}
	encoded, err := io.ReadAll(io.LimitReader(file, 513))
	if err != nil || len(encoded) > 512 {
		clear(encoded)
		return nil, errors.New("kit file exceeds its size limit")
	}
	defer clear(encoded)
	kit, err := vault.ParseRecoveryKit(string(encoded))
	if err != nil || len(kit) != 32 {
		clear(kit)
		return nil, errors.New("kit file must decode to exactly 32 bytes of recovery kit text")
	}
	return kit, nil
}

func readRegularFile(path string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, errors.New("input is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("input cannot be opened")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("input is not a regular file")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(encoded)) > maximum {
		clear(encoded)
		return nil, errors.New("input exceeds its size limit")
	}
	return encoded, nil
}

func checkBundleOutput(path string, overwrite bool) error {
	if path == "" {
		return errors.New("bundle output path is required")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("bundle output cannot be inspected")
	}
	if !overwrite {
		return errors.New("bundle output already exists; choose another path or pass --overwrite")
	}
	if !info.Mode().IsRegular() {
		return errors.New("bundle output overwrite is limited to regular files")
	}
	return nil
}

func writeBundleFile(path string, data []byte, overwrite bool) error {
	if err := checkBundleOutput(path, overwrite); err != nil {
		return err
	}
	if overwrite {
		return writeAtomicReplace(path, data)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("bundle output could not be created without replacing an existing file")
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return errors.New("bundle output write failed")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return errors.New("bundle output sync failed")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return errors.New("bundle output close failed")
	}
	return nil
}

func writeAtomicReplace(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".dottie-bundle-*")
	if err != nil {
		return errors.New("bundle output temporary file could not be created")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return errors.New("bundle output permissions could not be restricted")
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return errors.New("bundle output write failed")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errors.New("bundle output sync failed")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("bundle output close failed")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return errors.New("bundle output replacement failed")
	}
	return nil
}

func writePublicRequestFile(path string, data []byte) error {
	if path == "" {
		return errors.New("request output path is required")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("request output could not be created without replacing an existing file")
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return errors.New("request output write failed")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return errors.New("request output sync failed")
	}
	return file.Close()
}

func runImportBundle(ctx context.Context, command *urfave.Command, factory orchestrationFactory) error {
	if command.NArg() != 0 || command.String("bundle") == "" || command.String("anchor") == "" {
		return usageExit("account import-bundle requires --bundle and explicit --anchor")
	}
	encoded, err := readRegularFile(command.String("bundle"), vault.MaxOnboardingBundleBytes)
	if err != nil {
		return urfave.Exit("cannot read onboarding bundle file", 3)
	}
	defer clear(encoded)
	var bundleHeader struct {
		Version uint64 `json:"version"`
		Vault   string `json:"vault_id"`
	}
	if err := json.Unmarshal(encoded, &bundleHeader); err != nil || bundleHeader.Version != vault.OnboardingBundleVersion {
		return urfave.Exit("onboarding bundle header is invalid", 3)
	}
	bundleVault, err := parseVaultFingerprint(bundleHeader.Vault)
	if err != nil {
		return urfave.Exit("onboarding bundle vault is invalid", 3)
	}
	anchor, err := parseVaultFingerprint(command.String("anchor"))
	if err != nil {
		return usageExit("--anchor must be a 32-byte hexadecimal fingerprint supplied independently of the bundle")
	}
	vaultID := bundleVault
	if command.IsSet("vault") {
		explicitVault, parseErr := parseVaultFingerprint(command.String("vault"))
		if parseErr != nil {
			return usageExit("--vault must be a 32-byte hexadecimal identifier")
		}
		if explicitVault != bundleVault {
			return urfave.Exit("--vault does not match onboarding bundle", 3)
		}
		vaultID = explicitVault
	}
	coordinator, selection, closeResources, err := factory(ctx, command, false)
	if err != nil {
		return urfave.Exit("onboarding import refused: local key or state unavailable", 3)
	}
	defer closeResources()
	selection.Vault = vaultID
	if command.IsSet("device-id") {
		selection.DeviceID = command.String("device-id")
	}
	selected, err := coordinator.ResolveSelection(ctx, selection)
	if err != nil {
		return urfave.Exit("onboarding import refused: local device selection is unavailable", 3)
	}
	if err := coordinator.ImportOnboarding(ctx, encoded, vaultID, anchor, selected.DeviceID); err != nil {
		return urfave.Exit("onboarding import refused", 3)
	}
	output := "selection: persisted\ncheckpoint: persisted\nevidence: persisted\nfirst pull: authenticates the chain before any downloaded data can be used\n"
	return writeCommandOutput(command, output)
}

func importBundleFlags() []urfave.Flag {
	return []urfave.Flag{
		&urfave.StringFlag{Name: "bundle", Usage: "public onboarding bundle file", OnlyOnce: true},
		&urfave.StringFlag{Name: "anchor", Usage: "independently supplied 32-byte hexadecimal root fingerprint", OnlyOnce: true},
		&urfave.StringFlag{Name: "vault", Usage: "expected vault fingerprint", OnlyOnce: true},
		&urfave.StringFlag{Name: "device-id", Usage: "local selected device identifier", OnlyOnce: true},
	}
}

func importBundleAction(factory orchestrationFactory) func(context.Context, *urfave.Command) error {
	return func(ctx context.Context, command *urfave.Command) error {
		return runImportBundle(ctx, command, factory)
	}
}
