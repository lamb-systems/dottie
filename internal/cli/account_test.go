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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/multiformats/go-multihash"
	urfave "github.com/urfave/cli/v3"
)

type memoryAccountKeyring struct {
	items       map[string]vault.DeviceMaterial
	err         error
	storeCalls  int
	deleteCalls int
}

func (k *memoryAccountKeyring) StoreDeviceKeys(_ context.Context, vaultID [32]byte, material vault.DeviceMaterial) error {
	k.storeCalls++
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

func (k *memoryAccountKeyring) LoadDeviceKeysForVault(ctx context.Context, vaultID [32]byte) ([]vault.DeviceMaterial, error) {
	prefix := hex.EncodeToString(vaultID[:]) + ":"
	materials := make([]vault.DeviceMaterial, 0)
	for name := range k.items {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		deviceID := strings.TrimPrefix(name, prefix)
		material, err := k.LoadDeviceKeys(ctx, vaultID, deviceID)
		if err != nil {
			return nil, err
		}
		materials = append(materials, material)
	}
	if len(materials) == 0 {
		return nil, platform.ErrKeyringItemNotFound
	}
	return materials, nil
}

func (k *memoryAccountKeyring) DeleteDeviceKeys(_ context.Context, vaultID [32]byte, deviceID string) error {
	k.deleteCalls++
	if k.err != nil {
		return k.err
	}
	delete(k.items, accountItemKey(vaultID, deviceID))
	return nil
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

type bootstrapOutputFailure struct{}

func (bootstrapOutputFailure) Write([]byte) (int, error) {
	return 0, errors.New("synthetic output failure")
}

type injectedBootstrapGenesisPort struct {
	transport    atproto.Transport
	reader       atproto.RevisionReader
	did          string
	observations atproto.PublicationObservationStore
	limit        int64
	unresolved   bool
}

func (port injectedBootstrapGenesisPort) Preflight(ctx context.Context) error {
	return atproto.CheckGenesisRepositoryEmpty(ctx, port.reader, port.transport, port.did)
}

func (port injectedBootstrapGenesisPort) BlobUploadLimit(context.Context) (int64, error) {
	return port.limit, nil
}

func (port injectedBootstrapGenesisPort) CommitGenesis(ctx context.Context, limit int64, kit []byte, root vault.DeviceMaterial, genesis vault.Genesis) (atproto.GenesisCommitResult, error) {
	result, err := atproto.CommitGenesis(ctx, atproto.GenesisIO{
		Reader: port.reader, Transport: port.transport, BlobUploadLimit: limit, DID: port.did,
		ObservationStore: port.observations,
	}, kit, root, genesis)
	if err == nil && port.unresolved {
		result.Phase = atproto.GenesisSubmitted
		return result, atproto.ErrGenesisUnavailable
	}
	return result, err
}

func TestAccountBootstrapCommandPublishesWithInjectedAuthenticatedProvider(t *testing.T) {
	root := t.TempDir()
	paths := platform.Paths{
		Home: filepath.Join(root, "home"), ConfigHome: filepath.Join(root, "config"),
		StateHome: filepath.Join(root, "state"), CacheHome: filepath.Join(root, "cache"), DataHome: filepath.Join(root, "data"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
	}
	const did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
	repositoryKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err := atprototest.NewMemoryPDS(did, repositoryKey)
	require.NoError(t, err)
	method := pds.VerificationMethod()
	reader := atproto.RevisionReader{Transport: pds, DIDDocumentID: did, VerificationMethods: []atproto.VerificationMethod{{
		ID: method.ID, Type: method.Type, Controller: method.Controller, PublicKeyMultibase: method.PublicKeyMultibase,
	}}}
	keyring := &memoryAccountKeyring{items: map[string]vault.DeviceMaterial{}}
	unresolved := false
	factory := func(ctx context.Context, command *urfave.Command) (bootstrapCoordinator, func(), error) {
		if command.String("did") != did {
			return nil, func() {}, errors.New("unexpected authenticated identity")
		}
		store, err := state.Open(paths)
		if err != nil {
			return nil, func() {}, err
		}
		port := injectedBootstrapGenesisPort{transport: pds, reader: reader, did: did, observations: store, limit: 1 << 20, unresolved: unresolved}
		clock := func() time.Time { return time.Unix(1_800_000_000, 0) }
		coordinator, err := service.NewCoordinator(service.Dependencies{
			State: store, DeviceKeys: keyring, Genesis: port,
			Trust:   service.StateTrustSource{State: store, Keyring: keyring},
			Session: manualReadSession{identity: atproto.Identity{DID: did, DIDDocumentID: did, VerificationMethods: reader.VerificationMethods}},
			Remote:  service.VaultReader{Reader: atproto.VaultReader{Transport: pds, ObservationStore: store, Budgets: atproto.DefaultBudgets(), Clock: clock}},
			Clock:   clock,
		})
		if err != nil {
			_ = store.Close()
			return nil, func() {}, err
		}
		return coordinator, func() { _ = store.Close() }, nil
	}
	open := func() (accountKeyring, error) { return keyring, nil }
	importFactory := orchestrationFactory(func(context.Context, *urfave.Command, bool) (orchestrationCoordinator, service.VaultSelection, func(), error) {
		return nil, service.VaultSelection{}, func() {}, errors.New("unused import factory")
	})
	runArgs := func(args []string, stdout, stderr io.Writer) int {
		code := 0
		command := newAccountCommandWithFactories(stdout, stderr, open, &code,
			accountSessionOptions{env: func(string) string { return "" }}, importFactory, factory)
		return runAccountCommandForOrchestrationTest(command, &code, args...)
	}
	run := func(stdout, stderr io.Writer) int {
		return runArgs([]string{"bootstrap", "--vault-name", "personal", "--device-id", "root-device", "--did", did}, stdout, stderr)
	}
	var stderr bytes.Buffer
	code := run(bootstrapOutputFailure{}, &stderr)
	assert.NotZero(t, code)
	assert.Empty(t, keyring.items)
	store, err := state.Open(paths)
	require.NoError(t, err)
	selections, err := store.VaultSelections(context.Background())
	require.NoError(t, err)
	assert.Empty(t, selections)
	require.NoError(t, store.Close())
	emptyRevision, err := reader.Read(context.Background(), did)
	require.NoError(t, err)
	assert.Empty(t, emptyRevision.Membership())
	keyring.err = platform.ErrKeyringUnavailable
	var refusedOut, refusedErr bytes.Buffer
	code = run(&refusedOut, &refusedErr)
	require.Equal(t, 1, code)
	assert.NotContains(t, refusedOut.String(), "recovery kit (keep offline):")
	assert.Empty(t, keyring.items)
	revisionAfterKeyringFailure, err := reader.Read(context.Background(), did)
	require.NoError(t, err)
	assert.Equal(t, emptyRevision.CommitCID(), revisionAfterKeyringFailure.CommitCID())
	keyring.err = nil
	var stdout bytes.Buffer
	stderr.Reset()
	code = run(&stdout, &stderr)
	require.Equal(t, 0, code)
	assert.Empty(t, stderr.String())
	assert.Equal(t, 1, strings.Count(stdout.String(), "recovery kit (keep offline):"))
	assert.Contains(t, stdout.String(), "genesis: verified-commit")
	kitLine := strings.SplitN(stdout.String(), "recovery kit (keep offline): ", 2)
	require.Len(t, kitLine, 2)
	groupedKit := strings.Fields(kitLine[1])[0]
	kit, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(groupedKit, "-", ""))
	require.NoError(t, err)
	require.Len(t, kit, 32)
	assert.Len(t, keyring.items, 1)
	for _, device := range keyring.items {
		assert.False(t, bytes.Contains(device.Signing, kit))
		assert.False(t, bytes.Contains(device.Recipient.Bytes(), kit))
	}
	store, err = state.Open(paths)
	require.NoError(t, err)
	selections, err = store.VaultSelections(context.Background())
	require.NoError(t, err)
	require.Len(t, selections, 1)
	checkpoint, err := store.VaultCheckpoint(context.Background(), selections[0].Vault)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), checkpoint.Epoch)
	evidence, err := store.AuthenticatedPositionEvidenceAtEpoch(context.Background(), selections[0].Vault, 0)
	require.NoError(t, err)
	assert.NotEmpty(t, evidence.CheckpointPosition)
	require.NoError(t, store.Close())
	var finalizeOut, finalizeErr bytes.Buffer
	code = runArgs([]string{"finalize", "--vault", hex.EncodeToString(selections[0].Vault[:]), "--did", did}, &finalizeOut, &finalizeErr)
	require.Equal(t, 0, code)
	assert.Empty(t, finalizeErr.String())
	assert.Contains(t, finalizeOut.String(), "trust already finalized; no change")
	assert.NotContains(t, finalizeOut.String(), "recovery kit")
	stateBytes, err := os.ReadFile(filepath.Join(paths.AppStateDir(), "state.db"))
	require.NoError(t, err)
	assert.False(t, bytes.Contains(stateBytes, kit))
	revision, err := reader.Read(context.Background(), did)
	require.NoError(t, err)
	beforeCommit := revision.CommitCID()
	storeCallsBeforeRefusal := keyring.storeCalls
	deleteCallsBeforeRefusal := keyring.deleteCalls
	stdout.Reset()
	stderr.Reset()
	code = run(&stdout, &stderr)
	require.Equal(t, 3, code)
	assert.Contains(t, stderr.String(), "genesis requires an empty verified repository")
	assert.NotContains(t, stdout.String(), "recovery kit (keep offline):")
	assert.Len(t, keyring.items, 1)
	store, err = state.Open(paths)
	require.NoError(t, err)
	selections, err = store.VaultSelections(context.Background())
	require.NoError(t, err)
	assert.Len(t, selections, 1)
	require.NoError(t, store.Close())
	stateAfterRefusal, err := os.ReadFile(filepath.Join(paths.AppStateDir(), "state.db"))
	require.NoError(t, err)
	assert.Equal(t, stateBytes, stateAfterRefusal)
	assert.Equal(t, storeCallsBeforeRefusal, keyring.storeCalls)
	assert.Equal(t, deleteCallsBeforeRefusal, keyring.deleteCalls)
	keyName := accountItemKey(selections[0].Vault, selections[0].DeviceID)
	device, exists := keyring.items[keyName]
	require.True(t, exists)
	delete(keyring.items, keyName)
	var missingKeysOut, missingKeysErr bytes.Buffer
	code = runArgs([]string{"finalize", "--vault", hex.EncodeToString(selections[0].Vault[:]), "--did", did}, &missingKeysOut, &missingKeysErr)
	require.Equal(t, 3, code)
	assert.Contains(t, missingKeysErr.String(), "device keys for this vault are missing from Secret Service")
	assert.NotContains(t, missingKeysOut.String(), "recovery kit")
	keyring.items[keyName] = device
	revision, err = reader.Read(context.Background(), did)
	require.NoError(t, err)
	assert.Equal(t, beforeCommit, revision.CommitCID())
	assert.Len(t, revision.Records(), 6)
	assert.NotContains(t, stdout.String(), string(kit))
	secondRepositoryKey, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err = atprototest.NewMemoryPDS(did, secondRepositoryKey)
	require.NoError(t, err)
	method = pds.VerificationMethod()
	reader = atproto.RevisionReader{Transport: pds, DIDDocumentID: did, VerificationMethods: []atproto.VerificationMethod{{
		ID: method.ID, Type: method.Type, Controller: method.Controller, PublicKeyMultibase: method.PublicKeyMultibase,
	}}}
	unresolved = true
	stdout.Reset()
	stderr.Reset()
	code = runArgs([]string{"bootstrap", "--vault-name", "unresolved vault", "--device-id", "second-root", "--did", did}, &stdout, &stderr)
	require.Equal(t, 4, code)
	assert.Contains(t, stdout.String(), "genesis: unresolved")
	assert.Equal(t, 1, strings.Count(stdout.String(), "recovery kit (keep offline):"))
	assert.Equal(t, 6, strings.Count(stdout.String(), "record target:"))
	assert.Contains(t, stdout.String(), "do not retry bootstrap until publication is resolved")
	assert.Contains(t, stderr.String(), "genesis publication is unresolved")
	assert.Len(t, keyring.items, 2)
	revision, err = reader.Read(context.Background(), did)
	require.NoError(t, err)
	assert.Len(t, revision.Records(), 6)
}

func TestAccountEnrollRequiresMatchingTranscriptFingerprint(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
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
	paths, err := platform.Resolve(os.Getenv)
	require.NoError(t, err)
	stateStore, err := state.Open(paths)
	require.NoError(t, err)
	selections, err := stateStore.VaultSelections(context.Background())
	require.NoError(t, err)
	require.Len(t, selections, 1)
	assert.Equal(t, "new-device", selections[0].DeviceID)
	require.NoError(t, stateStore.Close())

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
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	open := func() (accountKeyring, error) { return nil, errors.New("synthetic backend detail") }
	var stdout, stderr bytes.Buffer
	code := runAccount([]string{"bootstrap", "--vault-name", "vault", "--device-id", "root", "--did", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"}, &stdout, &stderr, open)
	require.Equal(t, 1, code, "keyring error exit code")
	assert.NotContains(t, stderr.String(), "synthetic backend detail", "keyring detail leaked")
}
