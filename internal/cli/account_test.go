package cli

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/multiformats/go-multihash"
)

type memoryAccountKeyring struct {
	items map[string]vault.DeviceMaterial
	err   error
}

func (k *memoryAccountKeyring) StoreDeviceKeys(_ context.Context, vaultID [32]byte, material vault.DeviceMaterial) error {
	if k.err != nil {
		return k.err
	}
	cloned, err := cloneAccountMaterial(material)
	if err != nil {
		return err
	}
	k.items[accountItemKey(vaultID, material.DeviceID)] = cloned
	return nil
}

func (k *memoryAccountKeyring) LoadDeviceKeys(_ context.Context, vaultID [32]byte, deviceID string) (vault.DeviceMaterial, error) {
	if k.err != nil {
		return vault.DeviceMaterial{}, k.err
	}
	material, ok := k.items[accountItemKey(vaultID, deviceID)]
	if !ok {
		return vault.DeviceMaterial{}, platform.ErrKeyringItemNotFound
	}
	return cloneAccountMaterial(material)
}

func (k *memoryAccountKeyring) Close() error {
	return nil
}

func cloneAccountMaterial(material vault.DeviceMaterial) (vault.DeviceMaterial, error) {
	recipient, err := ecdh.X25519().NewPrivateKey(material.Recipient.Bytes())
	if err != nil {
		return vault.DeviceMaterial{}, err
	}
	return vault.DeviceMaterial{
		DeviceID: material.DeviceID, KeyID: bytes.Clone(material.KeyID),
		Signing: bytes.Clone(material.Signing), Recipient: recipient,
	}, nil
}

func accountItemKey(vaultID [32]byte, deviceID string) string {
	return hex.EncodeToString(vaultID[:]) + ":" + deviceID
}

func TestAccountBootstrapStoresKeysAndPrintsFingerprints(t *testing.T) {
	keyring := &memoryAccountKeyring{items: map[string]vault.DeviceMaterial{}}
	open := func() (accountKeyring, error) { return keyring, nil }
	var stdout, stderr bytes.Buffer
	code := runAccount([]string{"bootstrap", "--vault-name", "personal", "--device-id", "root-device"}, &stdout, &stderr, open)
	require.Equal(t, 0, code, "exit code")
	assert.Empty(t, stderr.String(), "stderr")
	assert.Contains(t, stdout.String(), "vault fingerprint:", "vault fingerprint")
	assert.Contains(t, stdout.String(), "anchor fingerprint:", "anchor fingerprint")
	assert.Contains(t, stdout.String(), "checkpoint fingerprint:", "checkpoint fingerprint")
	assert.Contains(t, stdout.String(), "kit public-key fingerprint:", "kit public-key fingerprint")
	kitLine := strings.SplitN(stdout.String(), "recovery kit (keep offline): ", 2)
	require.Len(t, kitLine, 2, "recovery kit was not displayed")
	groupedKit := strings.Fields(kitLine[1])[0]
	decodedKit, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(groupedKit, "-", ""))
	require.NoError(t, err)
	require.Len(t, decodedKit, 32, "displayed recovery kit size")
	require.Len(t, keyring.items, 1, "root device keys were not stored")
}

func TestAccountEnrollRequiresMatchingTranscriptFingerprint(t *testing.T) {
	keyring := &memoryAccountKeyring{items: map[string]vault.DeviceMaterial{}}
	open := func() (accountKeyring, error) { return keyring, nil }
	vaultID := bytes.Repeat([]byte{0x55}, 32)
	baseArgs := []string{"enroll", "--vault", hex.EncodeToString(vaultID), "--device-id", "new-device", "--role", "publisher"}
	var firstOut, firstErr bytes.Buffer
	code := runAccount(baseArgs, &firstOut, &firstErr, open)
	require.Equal(t, 1, code, "an unconfirmed transcript must not succeed")
	assert.Contains(t, firstOut.String(), "device id: new-device", "device id transcript")
	assert.Contains(t, firstOut.String(), "key id:", "key id transcript")
	assert.Contains(t, firstOut.String(), "requested role: publisher", "role transcript")
	assert.Contains(t, firstOut.String(), "signing public key fingerprint:", "signing fingerprint")
	assert.Contains(t, firstOut.String(), "recipient public key fingerprint:", "recipient fingerprint")
	assert.Contains(t, firstErr.String(), "transcript fingerprint confirmation required", "missing confirmation")
	fingerprintParts := strings.SplitN(firstOut.String(), "transcript fingerprint: ", 2)
	require.Len(t, fingerprintParts, 2, "transcript fingerprint line")
	fingerprint := strings.Fields(fingerprintParts[1])[0]

	confirmedArgs := append(append([]string(nil), baseArgs...), "--confirm", fingerprint)
	var confirmedOut, confirmedErr bytes.Buffer
	code = runAccount(confirmedArgs, &confirmedOut, &confirmedErr, open)
	require.Equal(t, 0, code, "matching confirmation must pass")
	assert.Contains(t, confirmedOut.String(), "transcript confirmed", "confirmation result")
	assert.Empty(t, confirmedErr.String(), "stderr")

	wrong := strings.Repeat("0", 64)
	if wrong == fingerprint {
		wrong = strings.Repeat("1", 64)
	}
	substitutedArgs := append(append([]string(nil), baseArgs...), "--confirm", wrong)
	var substitutedOut, substitutedErr bytes.Buffer
	code = runAccount(substitutedArgs, &substitutedOut, &substitutedErr, open)
	require.Equal(t, 1, code, "substituted transcript confirmation must fail")
	assert.Contains(t, substitutedErr.String(), "confirmation mismatch", "substitution error")
}

func TestAccountDoesNotDegradeWhenKeyringIsUnavailable(t *testing.T) {
	open := func() (accountKeyring, error) { return nil, platform.ErrKeyringUnavailable }
	var stdout, stderr bytes.Buffer
	code := runAccount([]string{"enroll", "--vault", strings.Repeat("1", 64), "--device-id", "device", "--role", "publisher"}, &stdout, &stderr, open)
	require.Equal(t, 1, code, "keyring failure exit code")
	assert.Empty(t, stdout.String(), "unavailable keyring did not print a transcript")
	assert.Contains(t, stderr.String(), "keyring is unavailable", "typed keyring failure")
}

func TestAccountRejectsRootEnrollment(t *testing.T) {
	keyring := &memoryAccountKeyring{items: map[string]vault.DeviceMaterial{}}
	open := func() (accountKeyring, error) { return keyring, nil }
	vaultID := strings.Repeat("1", 64)
	var stdout, stderr bytes.Buffer
	code := runAccount([]string{"enroll", "--vault", vaultID, "--device-id", "device", "--role", "root"}, &stdout, &stderr, open)
	require.Equal(t, 2, code, "root role usage exit code")
	assert.Contains(t, stderr.String(), "role must be publisher or restore_only", "root enrollment rejection")
}

func TestAccountRecoveryRendersSuppliedKitAndVerifiedAnchor(t *testing.T) {
	kit := bytes.Repeat([]byte{0x42}, 32)
	rendered, err := vault.RenderRecoveryKit(kit)
	require.NoError(t, err)
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	root := vault.DeviceMaterial{DeviceID: "root", KeyID: deviceKeyID(signing.Public().(ed25519.PublicKey)), Signing: signing, Recipient: recipient}
	boot, err := vault.Bootstrap(kit, "recovery-command", root)
	require.NoError(t, err)
	checkpointPath := filepath.Join(t.TempDir(), "checkpoint.bin")
	require.NoError(t, os.WriteFile(checkpointPath, boot.Checkpoint, 0o600))

	var stdout, stderr bytes.Buffer
	code := runAccountWithReader([]string{"recovery", "--vault-name", "recovery-command", "--checkpoint", checkpointPath}, strings.NewReader(rendered+"\n"), &stdout, &stderr)
	require.Equal(t, 0, code)
	assert.Empty(t, stderr.String())
	assert.Contains(t, stdout.String(), "recovery kit (keep offline): "+rendered)
	assert.Contains(t, stdout.String(), "vault fingerprint: "+hex.EncodeToString(boot.Vault[:]))
	assert.Contains(t, stdout.String(), "anchor fingerprint: "+hex.EncodeToString(boot.Anchor[:]))
	kitPublic, err := vault.RecoveryKitSigningPublicKey(kit, boot.Vault)
	require.NoError(t, err)
	publicFingerprint := sha256.Sum256(kitPublic)
	assert.Contains(t, stdout.String(), "recovery kit public-key fingerprint: "+hex.EncodeToString(publicFingerprint[:]))
}

func TestAccountRecoveryRejectsShortKit(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runAccountWithReader([]string{"recovery", "--vault-name", "vault"}, strings.NewReader("AA\n"), &stdout, &stderr)
	require.Equal(t, 1, code)
	assert.Empty(t, stdout.String())
	assert.Contains(t, stderr.String(), "exactly 32 bytes")
}

func TestAccountVerifyConsentDoesNotAdvanceCheckpoint(t *testing.T) {
	bundle, boot := accountVerifyTestBundle(t)
	bundle.Held = nil
	encoded, err := json.Marshal(bundle)
	require.NoError(t, err)
	stateHome := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", stateHome)
	bundlePath := filepath.Join(t.TempDir(), "bundle.json")
	require.NoError(t, os.WriteFile(bundlePath, encoded, 0o600))

	var stdout, stderr bytes.Buffer
	code := runAccountWithReader([]string{"verify", "--bundle", bundlePath, "--trust-anchor", hex.EncodeToString(boot.Anchor[:]), "--consent"}, strings.NewReader(""), &stdout, &stderr)
	require.Equal(t, 0, code)
	assert.Contains(t, stdout.String(), "outcome: unverifiable")
	assert.Contains(t, stdout.String(), "consequence: freshness is not established")
	assert.Contains(t, stdout.String(), "consent recorded for this verification")
	assert.NotContains(t, stdout.String(), "checkpoint recorded")
	assert.Empty(t, stderr.String())

	paths, err := platform.Resolve(os.Getenv)
	require.NoError(t, err)
	store, err := state.Open(paths)
	require.NoError(t, err)
	defer store.Close()
	vaultID, err := parseVaultFingerprint(bundle.Vault)
	require.NoError(t, err)
	_, err = store.VaultCheckpoint(context.Background(), vaultID)
	assert.ErrorIs(t, err, state.ErrVaultCheckpointNotFound)
}

func TestAccountVerifyRequiresExplicitConsentForUnverifiableState(t *testing.T) {
	bundle, boot := accountVerifyTestBundle(t)
	bundle.Held = nil
	encoded, err := json.Marshal(bundle)
	require.NoError(t, err)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	bundlePath := filepath.Join(t.TempDir(), "bundle.json")
	require.NoError(t, os.WriteFile(bundlePath, encoded, 0o600))

	var stdout, stderr bytes.Buffer
	code := runAccountWithReader([]string{"verify", "--bundle", bundlePath, "--trust-anchor", hex.EncodeToString(boot.Anchor[:])}, strings.NewReader(""), &stdout, &stderr)
	require.Equal(t, 1, code)
	assert.Contains(t, stdout.String(), "outcome: unverifiable")
	assert.Contains(t, stdout.String(), "inspection/export-only")
	assert.Contains(t, stderr.String(), "requires --consent")
}

func TestAccountVerifyRefusesInvalidSignatureBeforeConsent(t *testing.T) {
	bundle, boot := accountVerifyTestBundle(t)
	bundle.Held = nil
	control, err := hex.DecodeString(bundle.Supplied.Control)
	require.NoError(t, err)
	control[len(control)-1] ^= 0x80
	bundle.Supplied.Control = hex.EncodeToString(control)
	encoded, err := json.Marshal(bundle)
	require.NoError(t, err)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	bundlePath := filepath.Join(t.TempDir(), "bundle.json")
	require.NoError(t, os.WriteFile(bundlePath, encoded, 0o600))

	var stdout, stderr bytes.Buffer
	code := runAccountWithReader([]string{"verify", "--bundle", bundlePath, "--trust-anchor", hex.EncodeToString(boot.Anchor[:]), "--consent"}, strings.NewReader(""), &stdout, &stderr)
	require.Equal(t, 1, code)
	assert.Empty(t, stdout.String())
	assert.Contains(t, stderr.String(), "verification refused: supplied control-signature")
	assert.NotContains(t, stderr.String(), "consent")
}

func TestAccountVerifyRejectsBundleSuppliedTrustAnchor(t *testing.T) {
	bundle, boot := accountVerifyTestBundle(t)
	bundle.Held = nil
	encoded, err := json.Marshal(bundle)
	require.NoError(t, err)
	var artifact map[string]any
	require.NoError(t, json.Unmarshal(encoded, &artifact))
	artifact["trust_anchor"] = hex.EncodeToString(boot.Anchor[:])
	encoded, err = json.Marshal(artifact)
	require.NoError(t, err)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	bundlePath := filepath.Join(t.TempDir(), "bundle.json")
	require.NoError(t, os.WriteFile(bundlePath, encoded, 0o600))

	var stdout, stderr bytes.Buffer
	code := runAccountWithReader([]string{"verify", "--bundle", bundlePath, "--consent"}, strings.NewReader(""), &stdout, &stderr)
	require.Equal(t, 1, code)
	assert.Empty(t, stdout.String())
	assert.Contains(t, stderr.String(), "verification bundle is not valid JSON")
	assert.NotContains(t, stderr.String(), "consent recorded")
}

func TestAccountVerifyRecordsOnlyAuthenticatedCurrentCheckpoint(t *testing.T) {
	bundle, boot := accountVerifyTestBundle(t)
	stateHome := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", stateHome)
	paths, err := platform.Resolve(os.Getenv)
	require.NoError(t, err)
	store, err := state.Open(paths)
	require.NoError(t, err)
	control, err := vault.DecodeControl(boot.Control)
	require.NoError(t, err)
	controlCID := testControlCID(t, boot.Control)
	policyDigest, err := vault.ComputePolicyDigest(boot.Policy)
	require.NoError(t, err)
	checkpoint := state.VaultCheckpoint{
		Vault: boot.Vault, Anchor: boot.Anchor, ControlCID: controlCID, ControlBytes: boot.Control,
		SnapshotCID: control.HeadSnapshotCID, Epoch: control.EpochSeq, PolicyDigest: policyDigest, RecordedAt: 10,
	}
	require.NoError(t, store.PutVaultCheckpoint(context.Background(), checkpoint))
	require.NoError(t, store.Close())

	encoded, err := json.Marshal(bundle)
	require.NoError(t, err)
	bundlePath := filepath.Join(t.TempDir(), "bundle.json")
	require.NoError(t, os.WriteFile(bundlePath, encoded, 0o600))
	var stdout, stderr bytes.Buffer
	code := runAccountWithReader([]string{"verify", "--bundle", bundlePath, "--record"}, strings.NewReader(""), &stdout, &stderr)
	require.Equal(t, 0, code)
	assert.Contains(t, stdout.String(), "outcome: current")
	assert.Contains(t, stdout.String(), "local checkpoint recorded")
	assert.Empty(t, stderr.String())

	store, err = state.Open(paths)
	require.NoError(t, err)
	defer store.Close()
	stored, err := store.VaultCheckpoint(context.Background(), boot.Vault)
	require.NoError(t, err)
	assert.Equal(t, checkpoint.ControlBytes, stored.ControlBytes)
}

func accountVerifyTestBundle(t *testing.T) (accountVerifyBundleJSON, vault.BootstrapResult) {
	t.Helper()
	kit := bytes.Repeat([]byte{0x52}, 32)
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	root := vault.DeviceMaterial{DeviceID: "verify-root", KeyID: deviceKeyID(signing.Public().(ed25519.PublicKey)), Signing: signing, Recipient: recipient}
	boot, err := vault.Bootstrap(kit, "verify-command", root)
	require.NoError(t, err)
	bundle := accountVerifyBundleJSON{
		Vault: hex.EncodeToString(boot.Vault[:]),
		Supplied: accountControlEvidenceJSON{
			Control: hex.EncodeToString(boot.Control), Policy: hex.EncodeToString(boot.Policy),
			Certificates: []string{hex.EncodeToString(boot.Certificate)},
		},
	}
	bundle.Held = &accountControlEvidenceJSON{
		Control: bundle.Supplied.Control, Policy: bundle.Supplied.Policy, Certificates: bundle.Supplied.Certificates,
	}
	return bundle, boot
}

func testControlCID(t *testing.T, encoded []byte) []byte {
	t.Helper()
	digest, err := multihash.Sum(encoded, multihash.SHA2_256, -1)
	require.NoError(t, err)
	return cid.NewCidV1(cid.Raw, digest).Bytes()
}

func runAccountWithReader(args []string, reader io.Reader, stdout, stderr *bytes.Buffer) int {
	exitCode := 0
	root := newAccountCommand(stdout, stderr, func() (accountKeyring, error) { return nil, nil }, &exitCode)
	root.Reader = reader
	ctx := context.Background()
	arguments := append([]string{"account"}, args...)
	if err := root.Run(ctx, arguments); err != nil && exitCode == 0 {
		root.ExitErrHandler(ctx, root, err)
	}
	return exitCode
}

func TestAccountKeyringFactoryErrorDoesNotExposeDetails(t *testing.T) {
	open := func() (accountKeyring, error) { return nil, errors.New("synthetic backend detail") }
	var stdout, stderr bytes.Buffer
	code := runAccount([]string{"bootstrap", "--vault-name", "vault", "--device-id", "root"}, &stdout, &stderr, open)
	require.Equal(t, 1, code, "keyring error exit code")
	assert.NotContains(t, stderr.String(), "synthetic backend detail", "keyring detail leaked")
}
