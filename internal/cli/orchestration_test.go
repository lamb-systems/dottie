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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipfs/go-cid"
	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeOrchestrationCoordinator struct {
	selection             service.VaultSelection
	resolveErr            error
	pullResult            service.ReadOutcome
	pullErr               error
	pushResult            service.PushResult
	pushErr               error
	enrollResult          service.AdministrativeResult
	enrollErr             error
	revokeResult          service.AdministrativeResult
	revokeErr             error
	revokeApprovalResults []service.RevokeApprovalTranscript
	revokeApprovalErr     error
	revokeApprovalCalls   int
	importErr             error
	calls                 []string
	enrollRequest         service.EnrollRequest
	revokeRequest         service.RevokeRequest
	importBundle          []byte
	importVault           [32]byte
	importAnchor          [32]byte
	importDeviceID        string
}

func (fake *fakeOrchestrationCoordinator) ResolveSelection(_ context.Context, requested service.VaultSelection) (service.VaultSelection, error) {
	fake.calls = append(fake.calls, "resolve")
	if fake.resolveErr != nil {
		return service.VaultSelection{}, fake.resolveErr
	}
	if fake.selection.Vault != ([32]byte{}) {
		return fake.selection, nil
	}
	return requested, nil
}

func (fake *fakeOrchestrationCoordinator) Pull(context.Context, service.VaultSelection) (service.ReadOutcome, error) {
	fake.calls = append(fake.calls, "pull")
	return fake.pullResult, fake.pullErr
}

func (fake *fakeOrchestrationCoordinator) Push(context.Context, service.VaultSelection) (service.PushResult, error) {
	fake.calls = append(fake.calls, "push")
	return fake.pushResult, fake.pushErr
}

func (fake *fakeOrchestrationCoordinator) Enroll(_ context.Context, request service.EnrollRequest) (service.AdministrativeResult, error) {
	fake.calls = append(fake.calls, "enroll")
	fake.enrollRequest = request
	fake.enrollRequest.Kit = bytes.Clone(request.Kit)
	return fake.enrollResult, fake.enrollErr
}

func (fake *fakeOrchestrationCoordinator) RevokeApproval(_ context.Context, _ service.VaultSelection, _ string, _ []byte) (service.RevokeApprovalTranscript, error) {
	fake.calls = append(fake.calls, "revoke-approval")
	index := fake.revokeApprovalCalls
	fake.revokeApprovalCalls++
	if fake.revokeApprovalErr != nil {
		return service.RevokeApprovalTranscript{}, fake.revokeApprovalErr
	}
	if len(fake.revokeApprovalResults) == 0 {
		return service.RevokeApprovalTranscript{}, errors.New("missing synthetic revocation transcript")
	}
	if index >= len(fake.revokeApprovalResults) {
		index = len(fake.revokeApprovalResults) - 1
	}
	return fake.revokeApprovalResults[index], nil
}

func (fake *fakeOrchestrationCoordinator) Revoke(_ context.Context, request service.RevokeRequest) (service.AdministrativeResult, error) {
	fake.calls = append(fake.calls, "revoke")
	fake.revokeRequest = request
	fake.revokeRequest.Kit = bytes.Clone(request.Kit)
	return fake.revokeResult, fake.revokeErr
}

func (fake *fakeOrchestrationCoordinator) ImportOnboarding(_ context.Context, encoded []byte, expectedVault, expectedAnchor [32]byte, deviceID string) error {
	fake.calls = append(fake.calls, "import")
	fake.importBundle = bytes.Clone(encoded)
	fake.importVault = expectedVault
	fake.importAnchor = expectedAnchor
	fake.importDeviceID = deviceID
	return fake.importErr
}

func orchestrationTestFactory(fake orchestrationCoordinator, selection service.VaultSelection, err error, calls *int) orchestrationFactory {
	return func(_ context.Context, _ *urfave.Command, _ bool) (orchestrationCoordinator, service.VaultSelection, func(), error) {
		if calls != nil {
			*calls = *calls + 1
		}
		return fake, selection, func() {}, err
	}
}

func runOrchestrationForTest(command *urfave.Command, exitCode *int, args ...string) int {
	ctx := context.Background()
	if err := command.Run(ctx, append([]string{"dottie"}, args...)); err != nil && *exitCode == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	return *exitCode
}

func runAccountCommandForOrchestrationTest(root *urfave.Command, exitCode *int, args ...string) int {
	ctx := context.Background()
	if err := root.Run(ctx, append([]string{"account"}, args...)); err != nil && *exitCode == 0 {
		root.ExitErrHandler(ctx, root, err)
	}
	return *exitCode
}

func TestPushExitStatusesAndRedactedOutput(t *testing.T) {
	for _, test := range []struct {
		name   string
		status service.StatusState
		code   int
	}{
		{name: "committed", status: service.StatusCommitted, code: 0},
		{name: "no-op", status: service.StatusNoOp, code: 0},
		{name: "rejected", status: service.StatusRejected, code: 3},
		{name: "conflicted", status: service.StatusConflicted, code: 3},
		{name: "queued", status: service.StatusQueued, code: 4},
		{name: "starved", status: service.StatusStarved, code: 4},
		{name: "fence lost", status: service.StatusFenceLost, code: 4},
		{name: "superseded", status: service.StatusSuperseded, code: 4},
		{name: "unavailable", status: service.StatusUnavailable, code: 4},
		{name: "base recording failed", status: service.StatusBaseRecordingFailed, code: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeOrchestrationCoordinator{pushResult: service.PushResult{Status: test.status}}
			var stdout, stderr bytes.Buffer
			code := 0
			command := newOrchestrationCommand(&stdout, &stderr, &code, orchestrationTestFactory(fake, service.VaultSelection{}, nil, nil))
			code = runOrchestrationForTest(command, &code, "push", "--did", "did:plc:example")
			require.Equal(t, test.code, code)
			assert.Contains(t, stdout.String(), "push: "+string(test.status))
			if test.code == 0 {
				assert.Empty(t, stderr.String())
			} else if test.code == 3 {
				assert.Contains(t, stderr.String(), "push refused")
			} else {
				assert.Contains(t, stderr.String(), "push did not complete")
			}
			assert.Equal(t, []string{"push"}, fake.calls)
		})
	}
}

func TestPushErrorIsRedactedAndEscaped(t *testing.T) {
	fake := &fakeOrchestrationCoordinator{pushErr: errors.New("/home/private\nsecret\x1b")}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newOrchestrationCommand(&stdout, &stderr, &code, orchestrationTestFactory(fake, service.VaultSelection{}, nil, nil))
	code = runOrchestrationForTest(command, &code, "push", "--did", "did:plc:example")
	require.Equal(t, 3, code)
	assert.Equal(t, "push: rejected\n", stdout.String())
	assert.NotContains(t, stderr.String(), "/home/private")
	assert.NotContains(t, stderr.String(), "secret")
	assert.NotContains(t, stderr.String(), "\x1b")
}

func TestPushRequiresAccountSelectorBeforeFactory(t *testing.T) {
	calls := 0
	var stdout, stderr bytes.Buffer
	code := 0
	command := newOrchestrationCommand(&stdout, &stderr, &code, orchestrationTestFactory(nil, service.VaultSelection{}, nil, &calls))
	code = runOrchestrationForTest(command, &code, "push")
	require.Equal(t, 2, code)
	assert.Zero(t, calls)
	assert.Contains(t, stderr.String(), "exactly one of --did or --handle")
}

func TestPushFactoryRefusalHasRedactedStatus(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := 0
	factory := orchestrationTestFactory(nil, service.VaultSelection{}, errors.New("/home/private\nsecret"), nil)
	command := newOrchestrationCommand(&stdout, &stderr, &code, factory)
	code = runOrchestrationForTest(command, &code, "push", "--did", "did:plc:example")
	require.Equal(t, 3, code)
	assert.Equal(t, "push: rejected\n", stdout.String())
	assert.NotContains(t, stderr.String(), "/home/private")
	assert.NotContains(t, stderr.String(), "secret")
}

func TestPushCoordinatorErrorsMapToDistinctOutcomes(t *testing.T) {
	for _, test := range []struct {
		err    error
		status service.StatusState
	}{
		{err: service.ErrPushBlocked, status: service.StatusConflicted},
		{err: service.ErrBaseRecordingFailed, status: service.StatusBaseRecordingFailed},
		{err: atproto.ErrPublicationQueued, status: service.StatusQueued},
		{err: atproto.ErrPublicationStarved, status: service.StatusStarved},
		{err: atproto.ErrPublicationRetryFenceLost, status: service.StatusFenceLost},
		{err: atproto.ErrPublicationSuperseded, status: service.StatusSuperseded},
		{err: atproto.ErrPublicationUnavailable, status: service.StatusUnavailable},
		{err: atproto.ErrPublicationRejected, status: service.StatusRejected},
	} {
		assert.Equal(t, test.status, classifyPushResult(service.PushResult{}, test.err))
	}
}

func TestSyncPullThenPushAndNeverAppliesDownloads(t *testing.T) {
	fake := &fakeOrchestrationCoordinator{
		pullResult: service.ReadOutcome{Read: atproto.ReadResult{EpochSeq: 7}, Snapshot: model.Snapshot{Entries: []model.Entry{{}}}},
		pushResult: service.PushResult{Status: service.StatusNoOp, NoOp: true},
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newOrchestrationCommand(&stdout, &stderr, &code, orchestrationTestFactory(fake, service.VaultSelection{}, nil, nil))
	code = runOrchestrationForTest(command, &code, "sync", "--did", "did:plc:example")
	require.Equal(t, 0, code)
	assert.Equal(t, []string{"pull", "push"}, fake.calls)
	assert.Contains(t, stdout.String(), "pull: verified")
	assert.Contains(t, stdout.String(), "downloads: pending explicit restore review; nothing applied")
	assert.Contains(t, stdout.String(), "push: no-op")
	assert.NotContains(t, stdout.String(), "applied: true")
	assert.Empty(t, stderr.String())
}

func TestSyncPullRefusalDoesNotPush(t *testing.T) {
	fake := &fakeOrchestrationCoordinator{pullErr: errors.New("private transport detail")}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newOrchestrationCommand(&stdout, &stderr, &code, orchestrationTestFactory(fake, service.VaultSelection{}, nil, nil))
	code = runOrchestrationForTest(command, &code, "sync", "--did", "did:plc:example")
	require.Equal(t, 3, code)
	assert.Equal(t, "pull: refused\npush: not run\n", stdout.String())
	assert.Equal(t, []string{"pull"}, fake.calls)
	assert.NotContains(t, stderr.String(), "private transport")
}

func TestDevicesListRendersVerifiedPublicFieldsAndEscapesDeviceIDs(t *testing.T) {
	publicKey := bytes.Repeat([]byte{0x5a}, 32)
	fingerprint := sha256.Sum256(publicKey)
	deviceID := "root\n\x1b[2J"
	fake := &fakeOrchestrationCoordinator{pullResult: service.ReadOutcome{Read: atproto.ReadResult{
		EpochSeq: 9,
		Policy: atproto.PolicyRecord{
			Roles:      []atproto.PolicyRoleRecord{{DeviceID: deviceID, Role: uint8(vault.RoleRoot)}},
			Recipients: []atproto.PolicyRecipientRecord{{DeviceID: deviceID, PublicKey: publicKey}},
		},
		Control: atproto.ControlRecord{Revoked: []atproto.RevokedDeviceRecord{{DeviceID: "retired\x1b"}}},
	}}}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newOrchestrationCommand(&stdout, &stderr, &code, orchestrationTestFactory(fake, service.VaultSelection{}, nil, nil))
	code = runOrchestrationForTest(command, &code, "devices", "list", "--did", "did:plc:example")
	require.Equal(t, 0, code)
	assert.Contains(t, stdout.String(), "read: verified")
	assert.Contains(t, stdout.String(), "epoch: 9")
	assert.Contains(t, stdout.String(), "device id: root\\x0A\\x1B[2J\trole: root\tepoch: 9\trevoked: false\tkey fingerprint: "+hex.EncodeToString(fingerprint[:]))
	assert.Contains(t, stdout.String(), "device id: retired\\x1B\trole: unknown\tepoch: 9\trevoked: true\tkey fingerprint: unavailable")
	assert.NotContains(t, stdout.String(), hex.EncodeToString(publicKey))
	assert.NotContains(t, stdout.String(), "/home/")
	assert.NotContains(t, stdout.String(), "\x1b[2J")
	assert.Empty(t, stderr.String())
}

func TestDevicesListRefusesPullErrors(t *testing.T) {
	fake := &fakeOrchestrationCoordinator{pullErr: errors.New("private path detail")}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newOrchestrationCommand(&stdout, &stderr, &code, orchestrationTestFactory(fake, service.VaultSelection{}, nil, nil))
	code = runOrchestrationForTest(command, &code, "devices", "list", "--did", "did:plc:example")
	require.Equal(t, 3, code)
	assert.Empty(t, stdout.String())
	assert.NotContains(t, stderr.String(), "private path detail")
	assert.Contains(t, stderr.String(), "verified device list is unavailable")
}

func TestEnrollmentRequestContainsOnlyPublicKeysAndParses(t *testing.T) {
	vaultID := bytesTo32(0x42)
	material := generatedDeviceMaterial(t, "new-device")
	encoded, fingerprint, err := makeEnrollmentRequest(vaultID, material, vault.RolePublisher)
	require.NoError(t, err)
	request, err := decodeEnrollmentRequest(encoded)
	require.NoError(t, err)
	assert.Equal(t, vaultID, request.Vault)
	assert.Equal(t, material.DeviceID, request.Device.DeviceID)
	assert.Equal(t, material.KeyID, request.Device.KeyID)
	assert.Equal(t, []byte(material.Signing.Public().(ed25519.PublicKey)), request.Device.SigningPublicKey)
	assert.Equal(t, material.Recipient.PublicKey().Bytes(), request.Device.RecipientPublicKey)
	assert.Equal(t, vault.RolePublisher, request.Role)
	assert.Equal(t, fingerprint, request.ApprovalFingerprint)
	assert.NotContains(t, string(encoded), "private")
	assert.NotContains(t, string(encoded), hex.EncodeToString(material.Signing))
	var fields map[string]any
	require.NoError(t, json.Unmarshal(encoded, &fields))
	assert.Contains(t, fields, "signing_public_key")
	assert.Contains(t, fields, "recipient_public_key")
	assert.NotContains(t, fields, "signing_private_key")
	assert.NotContains(t, fields, "recipient_private_key")
}

func TestEnrollmentRequestRejectsUnknownPrivateFields(t *testing.T) {
	material := generatedDeviceMaterial(t, "device")
	encoded, _, err := makeEnrollmentRequest(bytesTo32(0x33), material, vault.RolePublisher)
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(encoded, &fields))
	fields["signing_private_key"] = strings.Repeat("a", 64)
	malformed, err := json.Marshal(fields)
	require.NoError(t, err)
	_, err = decodeEnrollmentRequest(malformed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid JSON")
}

func TestAccountEnrollWritesPublicRequestAfterConfirmation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	keyring := &memoryAccountKeyring{items: map[string]vault.DeviceMaterial{}}
	vaultID := bytesTo32(0x32)
	baseArgs := []string{"enroll", "--vault", hex.EncodeToString(vaultID[:]), "--device-id", "new-device", "--role", "restore_only"}
	var firstOut, firstErr bytes.Buffer
	code := runAccount(baseArgs, &firstOut, &firstErr, func() (accountKeyring, error) { return keyring, nil })
	require.Equal(t, 1, code)
	assert.Contains(t, firstErr.String(), "confirmation required")
	fingerprint := strings.Fields(strings.SplitN(firstOut.String(), "transcript fingerprint: ", 2)[1])[0]
	requestPath := filepath.Join(t.TempDir(), "enrollment-request.json")
	args := append(append([]string(nil), baseArgs...), "--confirm", fingerprint, "--request", requestPath)
	var stdout, stderr bytes.Buffer
	code = runAccount(args, &stdout, &stderr, func() (accountKeyring, error) { return keyring, nil })
	require.Equal(t, 0, code)
	assert.Contains(t, stdout.String(), "public enrollment request: written")
	requestBytes, err := os.ReadFile(requestPath)
	require.NoError(t, err)
	request, err := decodeEnrollmentRequest(requestBytes)
	require.NoError(t, err)
	assert.Equal(t, vaultID, request.Vault)
	assert.Equal(t, "new-device", request.Device.DeviceID)
	assert.Equal(t, vault.RoleRestoreOnly, request.Role)
	assert.NotContains(t, string(requestBytes), "private")
	assert.Empty(t, stderr.String())
}

func TestDevicesEnrollWritesPublicBundleAndApprovalTranscript(t *testing.T) {
	vaultID := bytesTo32(0x41)
	kit := bytes.Repeat([]byte{0x31}, 32)
	material := generatedDeviceMaterial(t, "new-device")
	requestBytes, approval, err := makeEnrollmentRequest(vaultID, material, vault.RolePublisher)
	require.NoError(t, err)
	root := t.TempDir()
	requestPath := filepath.Join(root, "request.json")
	kitPath := writeKitFile(t, root, kit, 0o600)
	bundlePath := filepath.Join(root, "bundle.json")
	require.NoError(t, os.WriteFile(requestPath, requestBytes, 0o600))
	checkpoint := testRecoveryCheckpoint(t, kit, vaultID)
	fake := &fakeOrchestrationCoordinator{
		selection:    service.VaultSelection{Vault: vaultID, DeviceID: "root-device"},
		enrollResult: service.AdministrativeResult{Status: service.StatusCommitted, Bundle: vault.OnboardingBundle{Version: 1, Checkpoint: checkpoint}, EncodedBundle: []byte(`{"public":true}`)},
	}
	var stdout, stderr bytes.Buffer
	code := 0
	command := newOrchestrationCommand(&stdout, &stderr, &code, orchestrationTestFactory(fake, service.VaultSelection{Vault: vaultID}, nil, nil))
	code = runOrchestrationForTest(command, &code, "devices", "enroll", "--request", requestPath, "--kit-file", kitPath, "--bundle-out", bundlePath, "--did", "did:plc:example")
	require.Equal(t, 0, code)
	assert.Contains(t, stdout.String(), "status: committed")
	assert.Contains(t, stdout.String(), "approval fingerprint: "+hex.EncodeToString(approval[:]))
	assert.Contains(t, stdout.String(), "successor epoch: 2")
	assert.Contains(t, stdout.String(), "checkpoint fingerprint:")
	renderedKit, err := vault.RenderRecoveryKit(kit)
	require.NoError(t, err)
	assert.NotContains(t, stdout.String(), renderedKit)
	assert.Equal(t, []string{"resolve", "enroll"}, fake.calls)
	assert.Equal(t, material.DeviceID, fake.enrollRequest.Device.DeviceID)
	assert.Equal(t, vault.RolePublisher, fake.enrollRequest.Role)
	assert.Equal(t, approval, fake.enrollRequest.ApprovalFingerprint)
	assert.Equal(t, kit, fake.enrollRequest.Kit)
	bundle, err := os.ReadFile(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, `{"public":true}`, string(bundle))
	info, err := os.Stat(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	assert.Empty(t, stderr.String())
}

func TestDevicesEnrollRefusesExistingBundleOutputBeforeCoordinator(t *testing.T) {
	root := t.TempDir()
	requestPath := filepath.Join(root, "request.json")
	kitPath := filepath.Join(root, "kit.txt")
	bundlePath := filepath.Join(root, "existing.json")
	require.NoError(t, os.WriteFile(requestPath, []byte("{}"), 0o600))
	require.NoError(t, os.WriteFile(kitPath, []byte("not read"), 0o600))
	require.NoError(t, os.WriteFile(bundlePath, []byte("keep"), 0o600))
	factoryCalls := 0
	var stdout, stderr bytes.Buffer
	code := 0
	command := newOrchestrationCommand(&stdout, &stderr, &code, orchestrationTestFactory(nil, service.VaultSelection{}, nil, &factoryCalls))
	code = runOrchestrationForTest(command, &code, "devices", "enroll", "--request", requestPath, "--kit-file", kitPath, "--bundle-out", bundlePath, "--did", "did:plc:example")
	require.Equal(t, 3, code)
	assert.Zero(t, factoryCalls)
	contents, err := os.ReadFile(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, "keep", string(contents))
	assert.Contains(t, stderr.String(), "already exists")
}

func TestDevicesEnrollRejectsMissingRequestFields(t *testing.T) {
	root := t.TempDir()
	vaultID := bytesTo32(0x44)
	requestPath := filepath.Join(root, "request.json")
	kitPath := writeKitFile(t, root, bytes.Repeat([]byte{0x12}, 32), 0o600)
	bundlePath := filepath.Join(root, "bundle.json")
	require.NoError(t, os.WriteFile(requestPath, []byte(`{"version":1,"vault":"`+hex.EncodeToString(vaultID[:])+`"}`), 0o600))
	factoryCalls := 0
	var stdout, stderr bytes.Buffer
	code := 0
	command := newOrchestrationCommand(&stdout, &stderr, &code, orchestrationTestFactory(nil, service.VaultSelection{}, nil, &factoryCalls))
	code = runOrchestrationForTest(command, &code, "devices", "enroll", "--request", requestPath, "--kit-file", kitPath, "--bundle-out", bundlePath, "--did", "did:plc:example")
	require.Equal(t, 3, code)
	assert.Zero(t, factoryCalls)
	assert.Contains(t, stderr.String(), "missing required fields")
}

func TestDevicesEnrollRefusesRootAndKitFailures(t *testing.T) {
	vaultID := bytesTo32(0x43)
	kit := bytes.Repeat([]byte{0x2a}, 32)
	material := generatedDeviceMaterial(t, "device")
	requestBytes, _, err := makeEnrollmentRequest(vaultID, material, vault.RolePublisher)
	require.NoError(t, err)
	root := t.TempDir()
	requestPath := filepath.Join(root, "request.json")
	kitPath := writeKitFile(t, root, kit, 0o600)
	require.NoError(t, os.WriteFile(requestPath, requestBytes, 0o600))
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "non-root or restore-only", err: service.ErrAdministrativeRootRequired},
		{name: "wrong kit", err: service.ErrRecoveryKitMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeOrchestrationCoordinator{selection: service.VaultSelection{Vault: vaultID, DeviceID: "selected"}, enrollErr: test.err}
			var stdout, stderr bytes.Buffer
			code := 0
			bundlePath := filepath.Join(t.TempDir(), "bundle.json")
			command := newOrchestrationCommand(&stdout, &stderr, &code, orchestrationTestFactory(fake, service.VaultSelection{Vault: vaultID}, nil, nil))
			code = runOrchestrationForTest(command, &code, "devices", "enroll", "--request", requestPath, "--kit-file", kitPath, "--bundle-out", bundlePath, "--did", "did:plc:example")
			require.Equal(t, 3, code)
			assert.Contains(t, stdout.String(), "status: rejected")
			rendered, renderErr := vault.RenderRecoveryKit(kit)
			require.NoError(t, renderErr)
			assert.NotContains(t, stdout.String(), rendered)
			assert.NotContains(t, stderr.String(), rendered)
			_, err := os.Stat(bundlePath)
			assert.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestRecoveryKitFilePermissionLengthAndRegularFileRefusals(t *testing.T) {
	root := t.TempDir()
	worldReadable := writeKitFile(t, root, bytes.Repeat([]byte{0x12}, 32), 0o644)
	_, err := readRecoveryKitFile(worldReadable)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chmod 600")
	wrongSize := filepath.Join(root, "wrong-size.txt")
	require.NoError(t, os.WriteFile(wrongSize, []byte("ABCD"), 0o600))
	_, err = readRecoveryKitFile(wrongSize)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly 32 bytes")
	directory := filepath.Join(root, "directory")
	require.NoError(t, os.Mkdir(directory, 0o700))
	_, err = readRecoveryKitFile(directory)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "regular file")
	linkPath := filepath.Join(root, "kit-link")
	require.NoError(t, os.Symlink(worldReadable, linkPath))
	_, err = readRecoveryKitFile(linkPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "regular file")
}

func TestDevicesRevokeRequiresTwoPhaseFingerprintConfirmation(t *testing.T) {
	vaultID := bytesTo32(0x51)
	kit := bytes.Repeat([]byte{0x27}, 32)
	kitPath := writeKitFile(t, t.TempDir(), kit, 0o600)
	checkpoint := testRecoveryCheckpoint(t, kit, vaultID)
	transcript := sampleRevokeTranscript(vaultID, "old-device", vault.RolePublisher, 1, 2, bytesTo32(0x52))
	fake := &fakeOrchestrationCoordinator{
		selection:             service.VaultSelection{Vault: vaultID, DeviceID: "root"},
		revokeApprovalResults: []service.RevokeApprovalTranscript{transcript},
		revokeResult:          service.AdministrativeResult{Status: service.StatusCommitted, Bundle: vault.OnboardingBundle{Version: 1, Checkpoint: checkpoint}},
	}
	args := []string{"devices", "revoke", "--device-id", "old-device", "--kit-file", kitPath, "--did", "did:plc:example"}
	var previewOut, previewErr bytes.Buffer
	code := 0
	command := newOrchestrationCommand(&previewOut, &previewErr, &code, orchestrationTestFactory(fake, service.VaultSelection{Vault: vaultID}, nil, nil))
	code = runOrchestrationForTest(command, &code, args...)
	require.Equal(t, 3, code)
	assert.Contains(t, previewOut.String(), "current role: publisher")
	assert.Contains(t, previewOut.String(), "current epoch: 1")
	assert.Contains(t, previewOut.String(), "successor epoch: 2")
	assert.Contains(t, previewOut.String(), "approval fingerprint: "+hex.EncodeToString(transcript.ApprovalFingerprint[:]))
	assert.Contains(t, previewErr.String(), "repeat with --confirm=")
	renderedPreviewKit, err := vault.RenderRecoveryKit(kit)
	require.NoError(t, err)
	assert.NotContains(t, previewOut.String(), hex.EncodeToString(kit))
	assert.NotContains(t, previewOut.String(), renderedPreviewKit)
	assert.NotContains(t, fake.calls, "revoke")

	wrong := transcript.ApprovalFingerprint
	wrong[0] ^= 0x80
	var wrongOut, wrongErr bytes.Buffer
	code = 0
	command = newOrchestrationCommand(&wrongOut, &wrongErr, &code, orchestrationTestFactory(fake, service.VaultSelection{Vault: vaultID}, nil, nil))
	wrongArgs := append(append([]string(nil), args...), "--confirm", hex.EncodeToString(wrong[:]))
	code = runOrchestrationForTest(command, &code, wrongArgs...)
	require.Equal(t, 3, code)
	assert.Contains(t, wrongErr.String(), "fingerprint mismatch")
	assert.NotContains(t, fake.calls, "revoke")

	var stdout, stderr bytes.Buffer
	code = 0
	command = newOrchestrationCommand(&stdout, &stderr, &code, orchestrationTestFactory(fake, service.VaultSelection{Vault: vaultID}, nil, nil))
	confirmedArgs := append(append([]string(nil), args...), "--confirm", hex.EncodeToString(transcript.ApprovalFingerprint[:]))
	code = runOrchestrationForTest(command, &code, confirmedArgs...)
	require.Equal(t, 0, code)
	assert.Contains(t, stdout.String(), "operation: revoke")
	assert.Contains(t, stdout.String(), "successor epoch: 2")
	assert.Contains(t, stdout.String(), "historical ciphertext: previously published ciphertext may remain available")
	assert.Equal(t, "old-device", fake.revokeRequest.DeviceID)
	assert.Equal(t, transcript.ApprovalFingerprint, fake.revokeRequest.ApprovalFingerprint)
	assert.Equal(t, kit, fake.revokeRequest.Kit)
	rendered, err := vault.RenderRecoveryKit(kit)
	require.NoError(t, err)
	assert.NotContains(t, stdout.String(), rendered)
	assert.Empty(t, stderr.String())
}

func TestDevicesRevokeRefusesWrongOrChangedTranscriptBeforeTransition(t *testing.T) {
	vaultID := bytesTo32(0x53)
	kit := bytes.Repeat([]byte{0x29}, 32)
	kitPath := writeKitFile(t, t.TempDir(), kit, 0o600)
	target := "old\n\x1b[2J"
	first := sampleRevokeTranscript(vaultID, target, vault.RolePublisher, 4, 5, bytesTo32(0x54))
	changed := sampleRevokeTranscript(vaultID, target, vault.RoleRestoreOnly, 5, 6, bytesTo32(0x55))
	fake := &fakeOrchestrationCoordinator{selection: service.VaultSelection{Vault: vaultID, DeviceID: "root"}, revokeApprovalResults: []service.RevokeApprovalTranscript{first, changed}}
	args := []string{"devices", "revoke", "--device-id", target, "--kit-file", kitPath, "--did", "did:plc:example"}
	var previewOut, previewErr bytes.Buffer
	code := 0
	command := newOrchestrationCommand(&previewOut, &previewErr, &code, orchestrationTestFactory(fake, service.VaultSelection{Vault: vaultID}, nil, nil))
	code = runOrchestrationForTest(command, &code, args...)
	require.Equal(t, 3, code)
	assert.Contains(t, previewOut.String(), "device id: old\\x0A\\x1B[2J")
	assert.NotContains(t, previewOut.String(), "\x1b[2J")
	assert.Contains(t, previewOut.String(), "current signing-key fingerprint:")
	assert.Contains(t, previewOut.String(), "current recipient-key fingerprint:")
	assert.Contains(t, previewOut.String(), "kit signing-key fingerprint:")
	renderedKit, renderErr := vault.RenderRecoveryKit(kit)
	require.NoError(t, renderErr)
	assert.NotContains(t, previewOut.String(), renderedKit)

	var stdout, stderr bytes.Buffer
	code = 0
	command = newOrchestrationCommand(&stdout, &stderr, &code, orchestrationTestFactory(fake, service.VaultSelection{Vault: vaultID}, nil, nil))
	confirmed := append(append([]string(nil), args...), "--confirm", hex.EncodeToString(first.ApprovalFingerprint[:]))
	code = runOrchestrationForTest(command, &code, confirmed...)
	require.Equal(t, 3, code)
	assert.Contains(t, stdout.String(), "current role: restore_only")
	assert.Contains(t, stdout.String(), "current epoch: 5")
	assert.Contains(t, stderr.String(), "fingerprint mismatch")
	assert.NotContains(t, fake.calls, "revoke")
}

func TestAccountImportBundleUsesIndependentAnchorAndPersistsEvidence(t *testing.T) {
	vaultID := bytesTo32(0x61)
	anchor := bytesTo32(0x62)
	bundlePath := filepath.Join(t.TempDir(), "bundle.json")
	bundle := []byte(fmt.Sprintf(`{"version":1,"vault_id":%q,"public":"evidence"}`, hex.EncodeToString(vaultID[:])))
	require.NoError(t, os.WriteFile(bundlePath, bundle, 0o600))
	fake := &fakeOrchestrationCoordinator{selection: service.VaultSelection{Vault: vaultID, DeviceID: "new-device"}}
	keyring := &memoryAccountKeyring{items: map[string]vault.DeviceMaterial{}}
	var stdout, stderr bytes.Buffer
	code := 0
	root := newAccountCommandWithImportFactory(&stdout, &stderr, func() (accountKeyring, error) { return keyring, nil }, &code,
		accountSessionOptions{}, orchestrationTestFactory(fake, service.VaultSelection{Vault: vaultID}, nil, nil))
	code = runAccountCommandForOrchestrationTest(root, &code, "import-bundle", "--bundle", bundlePath, "--anchor", hex.EncodeToString(anchor[:]))
	require.Equal(t, 0, code)
	assert.Equal(t, []string{"resolve", "import"}, fake.calls)
	assert.Equal(t, vaultID, fake.importVault)
	assert.Equal(t, anchor, fake.importAnchor)
	assert.Equal(t, "new-device", fake.importDeviceID)
	assert.Equal(t, bundle, fake.importBundle)
	assert.Contains(t, stdout.String(), "selection: persisted")
	assert.Contains(t, stdout.String(), "checkpoint: persisted")
	assert.Contains(t, stdout.String(), "evidence: persisted")
	assert.Contains(t, stdout.String(), "first pull: authenticates the chain")
	assert.Empty(t, stderr.String())
}

func TestAccountImportBundleRequiresAnchorAndReportsCoordinatorRefusal(t *testing.T) {
	vaultID := bytesTo32(0x71)
	bundlePath := filepath.Join(t.TempDir(), "bundle.json")
	bundle := []byte(fmt.Sprintf(`{"version":1,"vault_id":%q}`, hex.EncodeToString(vaultID[:])))
	require.NoError(t, os.WriteFile(bundlePath, bundle, 0o600))
	factoryCalls := 0
	keyring := &memoryAccountKeyring{items: map[string]vault.DeviceMaterial{}}
	var stdout, stderr bytes.Buffer
	code := 0
	root := newAccountCommandWithImportFactory(&stdout, &stderr, func() (accountKeyring, error) { return keyring, nil }, &code, accountSessionOptions{}, orchestrationTestFactory(nil, service.VaultSelection{}, nil, &factoryCalls))
	code = runAccountCommandForOrchestrationTest(root, &code, "import-bundle", "--bundle", bundlePath)
	require.Equal(t, 2, code)
	assert.Zero(t, factoryCalls)
	assert.Contains(t, stderr.String(), "explicit --anchor")

	anchor := bytesTo32(0x72)
	fake := &fakeOrchestrationCoordinator{selection: service.VaultSelection{Vault: vaultID, DeviceID: "new-device"}, importErr: service.ErrOnboardingChain}
	var refusalOut, refusalErr bytes.Buffer
	code = 0
	root = newAccountCommandWithImportFactory(&refusalOut, &refusalErr, func() (accountKeyring, error) { return keyring, nil }, &code, accountSessionOptions{}, orchestrationTestFactory(fake, service.VaultSelection{}, nil, nil))
	code = runAccountCommandForOrchestrationTest(root, &code, "import-bundle", "--bundle", bundlePath, "--anchor", hex.EncodeToString(anchor[:]))
	require.Equal(t, 3, code)
	assert.NotContains(t, refusalOut.String(), "selection: persisted")
	assert.Contains(t, refusalErr.String(), "onboarding import refused")
}

func TestRootHelpIncludesOrchestrationCommandsAndPolicies(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"help"}, &stdout, &stderr)
	require.Equal(t, 0, code)
	for _, text := range []string{"dottie push", "dottie sync", "devices list", "devices enroll", "devices revoke", "account import-bundle", "exit 4", "never apply downloads", "chmod 600"} {
		assert.Contains(t, stdout.String(), text)
	}
	assert.Empty(t, stderr.String())
}

func sampleRevokeTranscript(vaultID [32]byte, deviceID string, role vault.Role, currentEpoch, successorEpoch uint64, fingerprint [32]byte) service.RevokeApprovalTranscript {
	return service.RevokeApprovalTranscript{
		Vault: vaultID, DeviceID: deviceID, Role: role, CurrentEpoch: currentEpoch, SuccessorEpoch: successorEpoch,
		SigningKeyFingerprint: bytesTo32(0x31), RecipientKeyFingerprint: bytesTo32(0x32),
		KitSigningKeyFingerprint: bytesTo32(0x33), ApprovalFingerprint: fingerprint,
	}
}

func generatedDeviceMaterial(t *testing.T, deviceID string) vault.DeviceMaterial {
	t.Helper()
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	return vault.DeviceMaterial{DeviceID: deviceID, KeyID: deviceKeyID(signing.Public().(ed25519.PublicKey)), Signing: signing, Recipient: recipient}
}

func writeKitFile(t *testing.T, root string, kit []byte, mode os.FileMode) string {
	t.Helper()
	text, err := vault.RenderRecoveryKit(kit)
	require.NoError(t, err)
	path := filepath.Join(root, fmt.Sprintf("kit-%x.txt", kit[:2]))
	require.NoError(t, os.WriteFile(path, []byte(text), mode))
	require.NoError(t, os.Chmod(path, mode))
	return path
}

func testRecoveryCheckpoint(t *testing.T, kit []byte, vaultID [32]byte) []byte {
	t.Helper()
	controlHash, err := multihash.Sum([]byte("synthetic control"), multihash.SHA2_256, -1)
	require.NoError(t, err)
	snapshotHash, err := multihash.Sum([]byte("synthetic snapshot"), multihash.SHA2_256, -1)
	require.NoError(t, err)
	checkpoint, err := vault.SignRecoveryKitCheckpoint(kit, vaultID, bytesTo32(0x25), 2, bytesTo32(0x26), cid.NewCidV1(cid.Raw, controlHash).Bytes(), cid.NewCidV1(cid.Raw, snapshotHash).Bytes())
	require.NoError(t, err)
	return checkpoint
}

func bytesTo32(value byte) (result [32]byte) {
	for index := range result {
		result[index] = value
	}
	return result
}
