package atproto

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ Transport = (*atprototest.MemoryPDS)(nil)

func TestMemoryPDSDrivesGenesisAndOrdinaryPublication(t *testing.T) {
	for _, responseHook := range []struct {
		name string
		set  func() atprototest.MemoryPDSHooks
	}{
		{name: "normal", set: func() atprototest.MemoryPDSHooks { return atprototest.MemoryPDSHooks{} }},
		{name: "lost response", set: func() atprototest.MemoryPDSHooks {
			return atprototest.MemoryPDSHooks{LoseNextApplyWritesResponse: true}
		}},
		{name: "duplicated response", set: func() atprototest.MemoryPDSHooks {
			return atprototest.MemoryPDSHooks{DuplicateNextApplyWritesResponse: true}
		}},
	} {
		t.Run(responseHook.name, func(t *testing.T) {
			fixture, pds := memoryPDSGenesisFixture(t)
			ctx := context.Background()
			genesis, err := CommitGenesis(ctx, fixture.io, fixture.kit, fixture.root, fixture.genesis)
			require.NoError(t, err)
			assert.Zero(t, genesis.ReadResult.PublicationCount)
			assert.True(t, genesis.Revision.HasRecord(RecordKey{Collection: VaultCheckpointNSID, RKey: "self"}))
			assert.True(t, pds.BlobIsLive(genesis.ReadResult.Snapshot.Blob.Ref.CID().String()))

			adapter := ATProtoTransitionIO{
				Reader: fixture.io.Reader, Transport: pds, BlobUploadLimit: fixture.io.BlobUploadLimit,
				DID: fixture.io.DID, TrustAnchor: fixture.genesis.Anchor, ObservationStore: fixture.store,
			}
			_, predecessor, err := adapter.ReadCurrent(ctx)
			require.NoError(t, err)
			plaintext := []byte("synthetic ordinary publication content")
			publication, err := vault.PreparePublication(predecessor, vault.PublicationIntent{
				Vault: mustTestVault(t, predecessor), Signer: fixture.root, ContentKey: publicationTestBytes(t, 32),
				Wraps: publicationTestWraps(t, predecessor.Certificates), Plaintext: plaintext,
				PublicationID: [16]byte(publicationTestBytes(t, 16)), Nonce: [24]byte(publicationTestBytes(t, 24)),
				EpochFirstSeen: fixture.store, Clock: func() time.Time { return time.Unix(500, 0) },
			})
			require.NoError(t, err)
			pds.SetHooks(responseHook.set())
			publicationIO := ATProtoPublicationIO{
				Reader: fixture.io.Reader, Transport: pds, BlobUploadLimit: fixture.io.BlobUploadLimit,
				DID: fixture.io.DID, TrustAnchor: fixture.genesis.Anchor, ObservationStore: fixture.store,
			}
			committed, err := CommitPublication(ctx, publicationIO, fixture.store, publication, fixture.root.Signing, time.Unix(500, 0))
			require.NoError(t, err, committed.Evidence)
			assert.Equal(t, TransitionOutcome(TransitionOutcomeCommitted), committed.Outcome)
			assert.NotNil(t, committed.Revision)
			assert.Equal(t, uint64(1), readHeadPublicationCount(t, committed.Revision))
			assert.Len(t, committed.Revision.Records(), 7)
			record, exists := committed.Revision.Records()[RecordKey{Collection: VaultSnapshotNSID, RKey: committed.Marker.RKey}]
			require.True(t, exists)
			decoded, err := DecodeRecord(record.Data)
			require.NoError(t, err)
			snapshot, ok := decoded.(SnapshotRecord)
			require.True(t, ok)
			assert.True(t, pds.BlobIsLive(snapshot.Blob.Ref.CID().String()))

			readBack, err := (VaultReader{Transport: pds, ObservationStore: fixture.store}).Read(ctx, ReadRequest{
				DID: fixture.io.DID, DIDDocumentID: fixture.io.Reader.DIDDocumentID,
				VerificationMethods: fixture.io.Reader.VerificationMethods, Vault: fixture.genesis.Vault,
				TrustAnchor: fixture.genesis.Anchor, DeviceKeyID: bytes.Clone(fixture.root.KeyID), DeviceKey: fixture.root.Recipient,
			})
			require.NoError(t, err)
			assert.Equal(t, uint64(1), readBack.PublicationCount)
			assert.Equal(t, plaintext, readBack.Plaintext)
			assert.Equal(t, 7, len(readBack.Revision.Records()))
		})
	}
}

func TestPublishAttestationResolvesLostResponseAndIsIdempotent(t *testing.T) {
	fixture, pds := memoryPDSGenesisFixture(t)
	ctx := context.Background()
	_, err := CommitGenesis(ctx, fixture.io, fixture.kit, fixture.root, fixture.genesis)
	require.NoError(t, err)
	encoded, err := vault.BuildAttestation(vault.AttestationBuildRequest{
		VaultID: fixture.genesis.Vault, TrustAnchor: fixture.genesis.Anchor,
		State: vault.ControlEvidence{
			Policy: fixture.genesis.Policy, Control: fixture.genesis.Control,
			Certificates: [][]byte{fixture.genesis.Certificate},
		},
		SignerCertificate: fixture.genesis.Certificate, SigningKey: fixture.root.Signing,
		RetentionFloor: 0, RetainedRecoveryPoints: 1,
		RecoveryPoints: []vault.RetentionRecoveryPoint{{Epoch: 0, SnapshotCID: bytes.Clone(fixture.genesis.SnapshotCID)}},
	})
	require.NoError(t, err)
	publicationIO := ATProtoPublicationIO{
		Reader: fixture.io.Reader, Transport: pds, DID: fixture.io.DID, TrustAnchor: fixture.genesis.Anchor,
		ObservationStore: fixture.store, Clock: fixture.io.Clock,
	}
	pds.SetHooks(atprototest.MemoryPDSHooks{LoseNextApplyWritesResponse: true})
	result, err := PublishAttestation(ctx, publicationIO, fixture.root.DeviceID, fixture.root.KeyID, encoded)
	require.NoError(t, err)
	expectedRKey, err := AttestationRecordRKey(encoded)
	require.NoError(t, err)
	assert.Equal(t, expectedRKey, result.RKey)
	assert.False(t, result.Idempotent)
	assert.NotEmpty(t, result.RecordCID)
	assert.NotEmpty(t, result.CommitCID)
	key := RecordKey{Collection: VaultAttestationNSID, RKey: result.RKey}
	assert.True(t, result.Revision.HasRecord(key))
	assert.Equal(t, result.RecordCID, result.Revision.Membership()[key])

	currentCommit := result.Revision.CommitCID()
	duplicate, err := PublishAttestation(ctx, publicationIO, fixture.root.DeviceID, fixture.root.KeyID, encoded)
	require.NoError(t, err)
	assert.True(t, duplicate.Idempotent)
	assert.Equal(t, result.RKey, duplicate.RKey)
	assert.Equal(t, result.RecordCID, duplicate.RecordCID)
	assert.Equal(t, currentCommit, duplicate.CommitCID)

	conflicting, err := vault.BuildAttestation(vault.AttestationBuildRequest{
		VaultID: fixture.genesis.Vault, TrustAnchor: fixture.genesis.Anchor,
		State: vault.ControlEvidence{
			Policy: fixture.genesis.Policy, Control: fixture.genesis.Control,
			Certificates: [][]byte{fixture.genesis.Certificate},
		},
		SignerCertificate: fixture.genesis.Certificate, SigningKey: fixture.root.Signing,
		RetentionFloor: 0, RetainedRecoveryPoints: 1,
		RecoveryPoints: []vault.RetentionRecoveryPoint{{Epoch: 0, SnapshotCID: []byte("different-snapshot")}},
	})
	require.NoError(t, err)
	_, err = PublishAttestation(ctx, publicationIO, fixture.root.DeviceID, fixture.root.KeyID, conflicting)
	assert.ErrorIs(t, err, ErrAttestationConflict)
	assert.Equal(t, currentCommit, pds.CurrentRevision().CommitCID.String())
}

func TestMemoryPDSServesCommittedEnrollmentTransition(t *testing.T) {
	fixture, pds := memoryPDSGenesisFixture(t)
	ctx := context.Background()
	_, err := CommitGenesis(ctx, fixture.io, fixture.kit, fixture.root, fixture.genesis)
	require.NoError(t, err)

	adapter := ATProtoTransitionIO{
		Reader: fixture.io.Reader, Transport: pds, BlobUploadLimit: fixture.io.BlobUploadLimit,
		DID: fixture.io.DID, TrustAnchor: fixture.genesis.Anchor, ObservationStore: fixture.store,
	}
	_, predecessor, err := adapter.ReadCurrent(ctx)
	require.NoError(t, err)
	adapter.PreviousPolicies = append(adapter.PreviousPolicies, policyRecordBytesForObject(t, predecessor.Policy))
	adapter.PreviousControls = append(adapter.PreviousControls, encodeReadControlRecord(t, predecessor.Control))

	newSigning, newRecipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	newDevice := vault.DeviceMaterial{DeviceID: "memory-pds-enrolled", KeyID: []byte("memory-pds-enrolled-key"), Signing: newSigning, Recipient: newRecipient}
	keyIDs := make([][]byte, 0, len(predecessor.Certificates)+1)
	for _, encoded := range predecessor.Certificates {
		certificate, decodeErr := vault.DecodeCertificate(encoded)
		require.NoError(t, decodeErr)
		keyIDs = append(keyIDs, bytes.Clone(certificate.KeyID))
	}
	keyIDs = append(keyIDs, bytes.Clone(newDevice.KeyID))
	transition, err := vault.PrepareTransition(predecessor, vault.TransitionIntent{
		Kind: vault.TransitionEnroll, Vault: mustTestVault(t, predecessor), Signer: fixture.root,
		NewDevice: &newDevice, RequestedRole: vault.RolePublisher, ContentKey: publicationTestBytes(t, 32),
		Recipients: cloneTransitionCertificates(predecessor.Certificates), Wraps: publicationTestWrapsForKeyIDs(t, keyIDs),
		Plaintext: []byte("synthetic enrollment snapshot"), PublicationID: [16]byte(publicationTestBytes(t, 16)),
		Nonce: [24]byte(publicationTestBytes(t, 24)),
	})
	require.NoError(t, err)
	adapter.PreviousPolicies = append(adapter.PreviousPolicies, policyRecordBytesForObject(t, transition.Policy))
	adapter.PreviousControls = append(adapter.PreviousControls, encodeReadControlRecord(t, transition.Control))
	result, err := CommitTransition(ctx, adapter, fixture.store, transition, fixture.root.Signing, time.Unix(501, 0))
	require.NoError(t, err, result.Evidence)
	assert.Equal(t, TransitionOutcome(TransitionOutcomeCommitted), result.Outcome)
	require.NotNil(t, result.Revision)
	assert.True(t, result.Revision.HasRecord(RecordKey{Collection: VaultSnapshotNSID, RKey: result.Marker.RKey}))
	assert.True(t, pds.BlobIsLive(result.BlobCID))
	_, current, err := adapter.ReadCurrent(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), current.EpochSeq)
	assert.True(t, currentContainsCertificate(t, result.Revision, newDevice.DeviceID))
}

func memoryPDSGenesisFixture(t *testing.T) (genesisFixture, *atprototest.MemoryPDS) {
	t.Helper()
	fixture := newGenesisFixture(t)
	pds, err := atprototest.NewMemoryPDS(genesisTestDID, fixture.transport.repositoryKey)
	require.NoError(t, err)
	method := pds.VerificationMethod()
	fixture.io.Transport = pds
	fixture.io.Reader.Transport = pds
	fixture.io.Reader.VerificationMethods = []VerificationMethod{{
		ID: method.ID, Type: method.Type, Controller: method.Controller, PublicKeyMultibase: method.PublicKeyMultibase,
	}}
	return fixture, pds
}

func readHeadPublicationCount(t *testing.T, revision *Revision) uint64 {
	t.Helper()
	record, exists := revision.Records()[RecordKey{Collection: VaultHeadNSID, RKey: "self"}]
	require.True(t, exists)
	decoded, err := DecodeRecord(record.Data)
	require.NoError(t, err)
	head, ok := decoded.(HeadRecord)
	require.True(t, ok)
	return head.PublicationCount
}

func currentContainsCertificate(t *testing.T, revision *Revision, deviceID string) bool {
	t.Helper()
	for key, record := range revision.Records() {
		if key.Collection != VaultCertificateNSID {
			continue
		}
		decoded, err := DecodeRecord(record.Data)
		if err != nil {
			assert.NoError(t, err)
			return false
		}
		certificate, ok := decoded.(CertificateRecord)
		if ok && certificate.DeviceID == deviceID {
			return true
		}
	}
	return false
}
