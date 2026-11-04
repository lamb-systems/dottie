package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoordinatorEnrollRestoreOnlyImportsBundleAndReadsSuccessor(t *testing.T) {
	fixture := newPushFixture(t)
	pushed, err := fixture.coordinator.Push(context.Background(), VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.NoError(t, err)
	require.Equal(t, StatusCommitted, pushed.Status)
	newcomer, publicDevice := newAdminNewcomer(t, "admin-newcomer")
	result := enrollWithFixture(t, fixture, newcomer, publicDevice)
	require.Equal(t, StatusCommitted, result.Status)
	require.Equal(t, atproto.TransitionOutcome(atproto.TransitionOutcomeCommitted), result.TransitionOutcome)
	require.NotEmpty(t, result.EncodedBundle)
	require.False(t, bytes.Contains(result.EncodedBundle, newcomer.Signing))

	exported, err := fixture.coordinator.ExportOnboarding(context.Background(), VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}, fixture.kit)
	require.NoError(t, err)
	exportedBytes, err := vault.EncodeOnboardingBundle(exported)
	require.NoError(t, err)
	assert.Equal(t, result.EncodedBundle, exportedBytes)

	newStore, paths := openCoordinatorStateWithPaths(t)
	keyring := &pushDeviceKeyring{devices: map[string]vault.DeviceMaterial{newcomer.DeviceID: newcomer}}
	newCoordinator := newNewcomerCoordinator(t, fixture, newStore, paths, keyring)
	ctx := context.Background()
	require.NoError(t, newCoordinator.ImportOnboarding(ctx, exportedBytes, fixture.genesis.Vault, fixture.genesis.Anchor, newcomer.DeviceID))

	selections, err := newStore.VaultSelections(ctx)
	require.NoError(t, err)
	require.Equal(t, []state.VaultSelection{{Vault: fixture.genesis.Vault, DeviceID: newcomer.DeviceID, RecordedAt: fixture.clock.Unix()}}, selections)
	checkpoint, err := newStore.VaultCheckpoint(ctx, fixture.genesis.Vault)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), checkpoint.Epoch)
	predecessorDigest, err := vault.ComputePolicyDigest(exported.PredecessorPolicy)
	require.NoError(t, err)
	predecessorPosition, err := newStore.AuthenticatedPositionEvidence(ctx, fixture.genesis.Vault, 0, predecessorDigest)
	require.NoError(t, err)
	assert.Equal(t, exported.PredecessorPolicy, predecessorPosition.Policy)
	assert.Equal(t, exported.PredecessorControl, predecessorPosition.Control)
	assert.Equal(t, exported.PredecessorHead, predecessorPosition.Head)
	assert.Equal(t, exported.PredecessorSnapshot, predecessorPosition.Snapshot)
	assert.Equal(t, exported.PredecessorCertificates, predecessorPosition.Certificates)
	_, err = newStore.AuthenticatedPositionEvidence(ctx, fixture.genesis.Vault, 1, checkpoint.PolicyDigest)
	require.ErrorIs(t, err, state.ErrAuthenticatedPositionEvidenceNotFound, "the bundle import stores exactly the predecessor position")

	readBack, err := newCoordinator.Pull(ctx, VaultSelection{Vault: fixture.genesis.Vault, DeviceID: newcomer.DeviceID})
	require.NoError(t, err)
	assert.Equal(t, uint64(1), readBack.Read.EpochSeq)
	assert.Equal(t, atproto.FreshnessUnverified, readBack.Freshness)
	assert.NotEmpty(t, readBack.Read.Plaintext)
	policyBytes, err := vault.EncodePolicy(policyObject(readBack.Read.Policy))
	require.NoError(t, err)
	controlBytes, err := vault.EncodeControl(controlObject(readBack.Read.Control))
	require.NoError(t, err)
	certificates, err := certificateObjects(readBack.Read.Revision)
	require.NoError(t, err)
	digest, err := vault.ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	opened, err := vault.Open(readBack.Read.Envelope, vault.OpenRequest{
		Vault: fixture.genesis.Vault, EpochSeq: readBack.Read.EpochSeq, PolicyDigest: digest, Policy: policyBytes,
		Control: controlBytes, TrustAnchor: fixture.genesis.Anchor, Certificates: certificates,
		DeviceKeyID: newcomer.KeyID, DeviceKey: newcomer.Recipient,
	})
	require.NoError(t, err)
	assert.Equal(t, readBack.Read.Plaintext, opened)
	blob, err := snapshotBlob(readBack.Read.Plaintext)
	require.NoError(t, err)
	snapshot, err := vault.Unpack(blob)
	require.NoError(t, err)
	foundCurrent := false
	for _, entry := range snapshot.Entries {
		if entry.File != nil && entry.File.Path == "prefs.toml" {
			foundCurrent = true
			assert.Equal(t, []byte("theme = 'first'\n"), entry.File.Content)
		}
	}
	assert.True(t, foundCurrent, "enrollment re-encrypts the predecessor's current plaintext")
	successorPosition, err := newStore.AuthenticatedPositionEvidence(ctx, fixture.genesis.Vault, 1, digest)
	require.NoError(t, err)
	assert.Equal(t, readBack.Read.EpochSeq, successorPosition.Epoch)
}

func TestCoordinatorRevokeExcludesSuccessorRecipientButKeepsHistoricalDecryption(t *testing.T) {
	fixture := newPushFixture(t)
	newcomer, publicDevice := newAdminNewcomer(t, "revoke-newcomer")
	enrollment := enrollWithFixture(t, fixture, newcomer, publicDevice)
	require.NoError(t, fixture.store.PutVaultSelection(context.Background(), state.VaultSelection{Vault: fixture.genesis.Vault, DeviceID: newcomer.DeviceID, RecordedAt: 2}))
	fixture.keyring.devices[newcomer.DeviceID] = newcomer

	historical, err := fixture.coordinator.Pull(context.Background(), VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.NoError(t, err)
	historicalPolicy, err := vault.DecodePolicy(enrollment.Bundle.SuccessorPolicy)
	require.NoError(t, err)
	historicalDigest, err := vault.ComputePolicyDigest(enrollment.Bundle.SuccessorPolicy)
	require.NoError(t, err)
	historicalOpened, err := vault.Open(historical.Read.Envelope, vault.OpenRequest{
		Vault: fixture.genesis.Vault, EpochSeq: historicalPolicy.EpochSeq, PolicyDigest: historicalDigest,
		Policy: enrollment.Bundle.SuccessorPolicy, Control: enrollment.Bundle.SuccessorControl,
		TrustAnchor: fixture.genesis.Anchor, Certificates: certificateObjectsMust(t, historical.Read.Revision),
		DeviceKeyID: newcomer.KeyID, DeviceKey: newcomer.Recipient,
	})
	require.NoError(t, err, "previously delivered epoch content remains decryptable after revocation")
	require.NotEmpty(t, historicalOpened)

	result, err := fixture.coordinator.Revoke(context.Background(), RevokeRequest{
		Selection: VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}, DeviceID: newcomer.DeviceID, Kit: fixture.kit,
	})
	require.NoError(t, err)
	assert.Equal(t, StatusCommitted, result.Status)
	assert.Equal(t, atproto.TransitionOutcome(atproto.TransitionOutcomeCommitted), result.TransitionOutcome)
	assert.NotEmpty(t, result.EncodedBundle)
	revokedPolicy, err := vault.DecodePolicy(result.Bundle.SuccessorPolicy)
	require.NoError(t, err)
	for _, binding := range revokedPolicy.Roles {
		assert.NotEqual(t, newcomer.DeviceID, binding.DeviceID)
	}
	for _, recipient := range revokedPolicy.Recipients {
		assert.NotEqual(t, newcomer.DeviceID, recipient.DeviceID)
	}
	assert.Equal(t, uint64(2), mustVaultCheckpoint(t, fixture.store, fixture.genesis.Vault).Epoch)

	successor, err := fixture.coordinator.Pull(context.Background(), VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID})
	require.NoError(t, err)
	policyBytes, err := vault.EncodePolicy(policyObject(successor.Read.Policy))
	require.NoError(t, err)
	controlBytes, err := vault.EncodeControl(controlObject(successor.Read.Control))
	require.NoError(t, err)
	digest, err := vault.ComputePolicyDigest(policyBytes)
	require.NoError(t, err)
	_, err = vault.Open(successor.Read.Envelope, vault.OpenRequest{
		Vault: fixture.genesis.Vault, EpochSeq: successor.Read.EpochSeq, PolicyDigest: digest, Policy: policyBytes,
		Control: controlBytes, TrustAnchor: fixture.genesis.Anchor, Certificates: certificateObjectsMust(t, successor.Read.Revision),
		DeviceKeyID: newcomer.KeyID, DeviceKey: newcomer.Recipient,
	})
	assert.ErrorIs(t, err, vault.ErrRecipient, "the revoked recipient has no wrapper for successor content")
}

func TestCoordinatorAdministrativeRefusalsDoNotAdvanceCheckpointOrAppliedBase(t *testing.T) {
	t.Run("wrong recovery kit", func(t *testing.T) {
		fixture := newPushFixture(t)
		_, publicDevice := newAdminNewcomer(t, "wrong-kit-newcomer")
		approval := vault.EnrollmentTranscriptFingerprint(fixture.genesis.Vault, publicDevice.DeviceID, publicDevice.KeyID, vault.RoleRestoreOnly, publicDevice.SigningPublicKey, publicDevice.RecipientPublicKey)
		result, err := fixture.coordinator.Enroll(context.Background(), EnrollRequest{
			Selection: VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}, Device: publicDevice,
			Role: vault.RoleRestoreOnly, ApprovalFingerprint: approval, Kit: bytes.Repeat([]byte{7}, 32),
		})
		require.ErrorIs(t, err, ErrRecoveryKitMismatch)
		assert.Equal(t, StatusRejected, result.Status)
		assert.Equal(t, uint64(0), mustVaultCheckpoint(t, fixture.store, fixture.genesis.Vault).Epoch)
		assertEmptyBases(t, fixture.store, "wrong kit does not record an applied base")
	})

	t.Run("restore-only caller", func(t *testing.T) {
		fixture := newPushFixture(t)
		newcomer, publicDevice := newAdminNewcomer(t, "restore-only-admin")
		enrollWithFixture(t, fixture, newcomer, publicDevice)
		require.NoError(t, fixture.store.PutVaultSelection(context.Background(), state.VaultSelection{Vault: fixture.genesis.Vault, DeviceID: newcomer.DeviceID, RecordedAt: 2}))
		fixture.keyring.devices[newcomer.DeviceID] = newcomer
		_, otherPublic := newAdminNewcomer(t, "second-newcomer")
		otherApproval := vault.EnrollmentTranscriptFingerprint(fixture.genesis.Vault, otherPublic.DeviceID, otherPublic.KeyID, vault.RoleRestoreOnly, otherPublic.SigningPublicKey, otherPublic.RecipientPublicKey)
		result, err := fixture.coordinator.Enroll(context.Background(), EnrollRequest{
			Selection: VaultSelection{Vault: fixture.genesis.Vault, DeviceID: newcomer.DeviceID}, Device: otherPublic,
			Role: vault.RoleRestoreOnly, ApprovalFingerprint: otherApproval, Kit: fixture.kit,
		})
		require.ErrorIs(t, err, ErrAdministrativeRootRequired)
		assert.Equal(t, StatusRejected, result.Status)
		assert.Equal(t, uint64(1), mustVaultCheckpoint(t, fixture.store, fixture.genesis.Vault).Epoch)
		assertEmptyBases(t, fixture.store, "restore-only administration does not record an applied base")
	})

	t.Run("stale predecessor", func(t *testing.T) {
		fixture := newPushFixture(t)
		_, publicDevice := newAdminNewcomer(t, "stale-admin-newcomer")
		approval := vault.EnrollmentTranscriptFingerprint(fixture.genesis.Vault, publicDevice.DeviceID, publicDevice.KeyID, vault.RoleRestoreOnly, publicDevice.SigningPublicKey, publicDevice.RecipientPublicKey)
		fixture.provider.before = func() { fixture.publishRemoteFileDirect(t, []byte("competing state")) }
		result, err := fixture.coordinator.Enroll(context.Background(), EnrollRequest{
			Selection: VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}, Device: publicDevice,
			Role: vault.RoleRestoreOnly, ApprovalFingerprint: approval, Kit: fixture.kit,
		})
		require.Error(t, err)
		assert.Equal(t, StatusRejected, result.Status)
		assert.Equal(t, uint64(0), mustVaultCheckpoint(t, fixture.store, fixture.genesis.Vault).Epoch)
		assertEmptyBases(t, fixture.store, "stale preparation does not record an applied base")
	})
}

func TestCoordinatorTransitionFenceLostAndUnverifiedReadBackDoNotAdvanceCheckpoint(t *testing.T) {
	for _, test := range []struct {
		name       string
		transport  func(*pushFixture) atproto.Transport
		wantStatus StatusState
	}{
		{
			name: "fence lost",
			transport: func(fixture *pushFixture) atproto.Transport {
				return &adminRaceTransport{base: fixture.pds, beforeApply: func() { fixture.publishRemoteFileDirect(t, []byte("competing head")) }}
			},
			wantStatus: StatusFenceLost,
		},
		{
			name: "unverified commit resolution",
			transport: func(fixture *pushFixture) atproto.Transport {
				return &adminReadbackFailureTransport{base: fixture.pds}
			},
			wantStatus: StatusUnavailable,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPushFixture(t)
			fixture.provider.io.Transport = test.transport(fixture)
			_, publicDevice := newAdminNewcomer(t, "fence-admin-newcomer")
			approval := vault.EnrollmentTranscriptFingerprint(fixture.genesis.Vault, publicDevice.DeviceID, publicDevice.KeyID, vault.RoleRestoreOnly, publicDevice.SigningPublicKey, publicDevice.RecipientPublicKey)
			result, err := fixture.coordinator.Enroll(context.Background(), EnrollRequest{
				Selection: VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}, Device: publicDevice,
				Role: vault.RoleRestoreOnly, ApprovalFingerprint: approval, Kit: fixture.kit,
			})
			require.Error(t, err)
			assert.Equal(t, test.wantStatus, result.Status)
			assert.Equal(t, uint64(0), mustVaultCheckpoint(t, fixture.store, fixture.genesis.Vault).Epoch)
			assertEmptyBases(t, fixture.store, "indeterminate administrative outcome does not record an applied base")
		})
	}
}

func TestCoordinatorImportOnboardingRefusalsAreAtomic(t *testing.T) {
	fixture := newPushFixture(t)
	newcomer, publicDevice := newAdminNewcomer(t, "atomic-import-newcomer")
	enrollment := enrollWithFixture(t, fixture, newcomer, publicDevice)
	bundleBytes := enrollment.EncodedBundle

	for _, test := range []struct {
		name        string
		missingHead bool
		want        error
		setupState  func(*testing.T, *state.Store)
	}{
		{name: "wrong vault", want: ErrOnboardingVaultMismatch},
		{name: "wrong explicit anchor", want: ErrOnboardingAnchorMismatch},
		{name: "missing device key", want: ErrDeviceKeyMissing},
		{name: "mismatched device key", want: ErrOnboardingDeviceMismatch},
		{name: "missing predecessor head", missingHead: true, want: vault.ErrFormat},
		{
			name: "existing conflicting selection", want: ErrOnboardingStateConflict,
			setupState: func(t *testing.T, store *state.Store) {
				require.NoError(t, store.PutVaultSelection(context.Background(), state.VaultSelection{Vault: fixture.genesis.Vault, DeviceID: "another-device", RecordedAt: 9}))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, paths := openCoordinatorStateWithPaths(t)
			if test.setupState != nil {
				test.setupState(t, store)
			}
			devices := map[string]vault.DeviceMaterial{}
			if test.name != "missing device key" {
				devices[newcomer.DeviceID] = newcomer
			}
			if test.name == "mismatched device key" {
				_, wrongRecipient, err := vault.GenerateDeviceKeys()
				require.NoError(t, err)
				devices[newcomer.DeviceID] = vault.DeviceMaterial{DeviceID: newcomer.DeviceID, KeyID: bytes.Clone(newcomer.KeyID), Recipient: wrongRecipient}
			}
			keyring := &pushDeviceKeyring{devices: devices}
			coordinator := newNewcomerCoordinator(t, fixture, store, paths, keyring)
			input := bytes.Clone(bundleBytes)
			var err error
			switch test.name {
			case "wrong vault":
				wrong := fixture.genesis.Vault
				wrong[0] ^= 1
				err = coordinator.ImportOnboarding(context.Background(), input, wrong, fixture.genesis.Anchor, newcomer.DeviceID)
			case "wrong explicit anchor":
				wrong := fixture.genesis.Anchor
				wrong[0] ^= 1
				err = coordinator.ImportOnboarding(context.Background(), input, fixture.genesis.Vault, wrong, newcomer.DeviceID)
			default:
				if test.missingHead {
					input = bytes.Replace(input, []byte(`"predecessor_head":"`), []byte(`"missing_predecessor_head":"`), 1)
				}
				err = coordinator.ImportOnboarding(context.Background(), input, fixture.genesis.Vault, fixture.genesis.Anchor, newcomer.DeviceID)
			}
			require.ErrorIs(t, err, test.want)
			selections, err := store.VaultSelections(context.Background())
			require.NoError(t, err)
			if test.name == "existing conflicting selection" {
				assert.Equal(t, []state.VaultSelection{{Vault: fixture.genesis.Vault, DeviceID: "another-device", RecordedAt: 9}}, selections)
			} else {
				assert.Empty(t, selections, "refusal leaves no selection write")
			}
			_, err = store.VaultCheckpoint(context.Background(), fixture.genesis.Vault)
			assert.ErrorIs(t, err, state.ErrVaultCheckpointNotFound, "refusal leaves no checkpoint write")
			_, err = store.AuthenticatedPositionEvidenceAtEpoch(context.Background(), fixture.genesis.Vault, 0)
			assert.ErrorIs(t, err, state.ErrAuthenticatedPositionEvidenceNotFound, "refusal leaves no predecessor evidence write")
		})
	}
}

func newAdminNewcomer(t *testing.T, deviceID string) (vault.DeviceMaterial, vault.PublicDeviceInput) {
	t.Helper()
	signing, recipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	keyID := bytes.Clone(signing.Public().(ed25519.PublicKey))
	device := vault.DeviceMaterial{DeviceID: deviceID, KeyID: keyID, Signing: signing, Recipient: recipient}
	public := vault.PublicDeviceInput{
		DeviceID: deviceID, KeyID: bytes.Clone(keyID), SigningPublicKey: bytes.Clone(signing.Public().(ed25519.PublicKey)),
		RecipientPublicKey: bytes.Clone(recipient.PublicKey().Bytes()),
	}
	return device, public
}

func enrollWithFixture(t *testing.T, fixture *pushFixture, newcomer vault.DeviceMaterial, public vault.PublicDeviceInput) AdministrativeResult {
	t.Helper()
	approval := vault.EnrollmentTranscriptFingerprint(fixture.genesis.Vault, public.DeviceID, public.KeyID, vault.RoleRestoreOnly, public.SigningPublicKey, public.RecipientPublicKey)
	result, err := fixture.coordinator.Enroll(context.Background(), EnrollRequest{
		Selection: VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}, Device: public,
		Role: vault.RoleRestoreOnly, ApprovalFingerprint: approval, Kit: fixture.kit,
	})
	require.NoError(t, err)
	assert.Equal(t, StatusCommitted, result.Status)
	assert.NotNil(t, newcomer.Recipient)
	return result
}

func newNewcomerCoordinator(t *testing.T, fixture *pushFixture, store *state.Store, paths platform.Paths, keyring *pushDeviceKeyring) *Coordinator {
	t.Helper()
	clock := fixture.clock
	coordinator, err := NewCoordinator(Dependencies{
		Config: &memoryConfig{value: config.Default()}, State: store, DeviceKeys: keyring,
		Trust:   StateTrustSource{State: store, Keyring: keyring},
		Session: pushTestSession{did: pushTestDID, methods: fixture.reader.VerificationMethods},
		Remote:  VaultReader{Reader: atproto.VaultReader{Transport: fixture.pds, ObservationStore: store, Clock: func() time.Time { return clock }}},
		Clock:   func() time.Time { return clock }, Paths: paths,
	})
	require.NoError(t, err)
	return coordinator
}

func certificateObjectsMust(t *testing.T, revision *atproto.Revision) [][]byte {
	t.Helper()
	certificates, err := certificateObjects(revision)
	require.NoError(t, err)
	return certificates
}

func mustVaultCheckpoint(t *testing.T, store *state.Store, vaultID [32]byte) state.VaultCheckpoint {
	t.Helper()
	checkpoint, err := store.VaultCheckpoint(context.Background(), vaultID)
	require.NoError(t, err)
	return checkpoint
}

func assertEmptyBases(t *testing.T, store *state.Store, message string) {
	t.Helper()
	bases, err := store.AppliedBase(context.Background(), "files")
	require.NoError(t, err)
	assert.Empty(t, bases, message)
}

type adminRaceTransport struct {
	base        *atprototest.MemoryPDS
	beforeApply func()
	fired       bool
}

func (transport *adminRaceTransport) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	if endpoint == "com.atproto.repo.applyWrites" && !transport.fired {
		transport.fired = true
		transport.beforeApply()
	}
	return transport.base.Do(ctx, method, endpoint, query, body, contentType)
}

func (transport *adminRaceTransport) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	return transport.base.OpenStream(ctx, endpoint, query)
}

type adminReadbackFailureTransport struct {
	base  *atprototest.MemoryPDS
	fired bool
}

func (transport *adminReadbackFailureTransport) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	status, response, err := transport.base.Do(ctx, method, endpoint, query, body, contentType)
	if endpoint == "com.atproto.repo.applyWrites" && status >= 200 && status < 300 && err == nil && !transport.fired {
		transport.fired = true
		transport.base.SetHooks(atprototest.MemoryPDSHooks{GetBlobStatus: 503})
	}
	return status, response, err
}

func (transport *adminReadbackFailureTransport) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	return transport.base.OpenStream(ctx, endpoint, query)
}
