package integration

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationPrivacyEndToEnd(t *testing.T) {
	fixture := newPublicationFixture(t)
	uploaded := fixture.pds.StoredBlobCIDs()
	surface := collectPublicationAudit(context.Background(), fixture.transport, fixture.transport, fixture.did, uploaded)
	require.Empty(t, surface.incomplete)
	findings := publicationAuditFindings(surface, fixture.canaries)
	assert.Empty(t, findings, "%v", findings)
	assertPublicationCanariesAbsent(t, "getRepo", surface.repoBytes, fixture.canaries, publicationConfidential, publicationCredential)
	for cidText, block := range surface.blocks {
		assertPublicationCanariesAbsent(t, "CAR block "+cidText, block, fixture.canaries, publicationConfidential, publicationCredential)
	}
	for collection, body := range surface.records {
		assertPublicationCanariesAbsent(t, "listRecords "+collection, body, fixture.canaries, publicationConfidential, publicationCredential)
	}
	for blobCID, body := range surface.blobs {
		assert.Empty(t, scanCompressedPublicationCanaries(body, fixture.canaries), "getBlob %s", blobCID)
	}
	assertPublicationCanaryPresent(t, "getRepo", surface.repoBytes, fixture.canaries, "device-id")
	assert.Contains(t, string(surface.repoBytes), publicationAuditDeviceID)
	assert.True(t, bytes.Contains(surface.repoBytes, fixture.genesis.Vault[:]))
	publicDevice := fixture.canaries.forClass(publicationPublic)[0]
	assert.Contains(t, string(surface.repoBytes), string(publicDevice.raw))
	assertPublicationCanaryPresent(t, "authenticated published snapshot plaintext", fixture.publishedPlaintext, fixture.canaries, "file-content")
	assertPublicationCanaryPresent(t, "authenticated published snapshot plaintext", fixture.publishedPlaintext, fixture.canaries, "relative-path")
	assertPublicationCanaryPresent(t, "authenticated published snapshot plaintext", fixture.publishedPlaintext, fixture.canaries, "setting-value")
	local := readLocalPlaintextCanaries(t, fixture)
	assertPublicationCanaryPresent(t, "local plaintext", local, fixture.canaries, "file-content")
	assertPublicationCanaryPresent(t, "local plaintext", local, fixture.canaries, "setting-value")
	assert.True(t, bytes.Contains(local, []byte(publicationAuditFileTargetID)))
	assert.True(t, bytes.Contains(local, []byte(publicationAuditSettingsTargetID)))
	noOp, err := fixture.coordinator.Publish(context.Background(), fixture.selection)
	require.NoError(t, err)
	require.True(t, noOp.NoOp)
	report := fmt.Sprintf("%+v", noOp)
	assert.Empty(t, scanPublicationCanaries([]byte(report), fixture.canaries, publicationCredential))
	statusCode, statusOutput, statusError := fixture.runOfflineCLI("status")
	require.Equal(t, 0, statusCode)
	require.Empty(t, statusError)
	assert.Contains(t, statusOutput, publicationAuditFileTargetID)
	historyCode, historyOutput, historyError := fixture.runOfflineCLI("history")
	require.Equal(t, 0, historyCode)
	require.Empty(t, historyError)
	assert.Contains(t, historyOutput, publicationAuditFileTargetID)
	assert.Empty(t, scanPublicationCanaries([]byte(statusOutput+historyOutput), fixture.canaries, publicationCredential))
	for _, item := range fixture.canaries.forClass(publicationConfidential) {
		if item.name == "target-id" || item.name == "settings-target-id" {
			continue
		}
		assert.Empty(t, scanPublicationCanaries([]byte(statusOutput+historyOutput), publicationCanaries{items: []publicationCanary{item}}, publicationConfidential))
	}
}

func TestPublicationAuditTransportSplit(t *testing.T) {
	fixture := newPublicationFixture(t)
	public := &publicationAuditRecordingTransport{base: fixture.transport}
	authored := &publicationAuditRecordingTransport{base: fixture.transport}
	uploaded := fixture.pds.StoredBlobCIDs()
	surface := collectPublicationAudit(context.Background(), public, authored, fixture.did, uploaded)
	require.Empty(t, surface.incomplete)
	assert.NotSame(t, public, authored)

	publicEndpoints := publicationAuditRecordedEndpoints(public)
	assert.Contains(t, publicEndpoints, "com.atproto.sync.getRepo")
	assert.Contains(t, publicEndpoints, "com.atproto.repo.listRecords")
	assert.Contains(t, publicEndpoints, "com.atproto.sync.getBlob")
	assert.NotContains(t, publicEndpoints, "com.atproto.sync.listBlobs")
	assert.Equal(t, []string{"com.atproto.sync.listBlobs"}, publicationAuditRecordedEndpoints(authored))
	for _, blobCID := range uploaded {
		assert.Contains(t, public.blobCIDs, blobCID, "reachability probe for uploaded CID must use the public transport")
		assert.True(t, surface.reachables[blobCID])
	}
}

func TestPublicationMetadataDisclosure(t *testing.T) {
	fixture := newPublicationFixture(t)
	surface := collectPublicationAudit(context.Background(), fixture.transport, fixture.transport, fixture.did, fixture.pds.StoredBlobCIDs())
	require.Empty(t, surface.incomplete)
	require.NoError(t, auditRecordKeyInventory(surface))
	assert.Contains(t, string(surface.repoBytes), publicationAuditDeviceID)
	assert.True(t, bytes.Contains(surface.repoBytes, fixture.genesis.Vault[:]))
	var snapshot map[string]any
	var policyRecord map[string]any
	var controlRecord map[string]any
	for _, block := range surface.blocks {
		object, err := atdata.UnmarshalCBOR(block)
		if err != nil {
			continue
		}
		switch object["$type"] {
		case atproto.VaultSnapshotNSID:
			if bytes.Equal([]byte(object["vault"].(atdata.Bytes)), fixture.genesis.Vault[:]) {
				snapshot = object
			}
		case atproto.VaultPolicyNSID:
			policyRecord = object
		case atproto.VaultControlNSID:
			controlRecord = object
		}
	}
	require.NotNil(t, snapshot)
	require.NotNil(t, policyRecord)
	require.NotNil(t, controlRecord)
	keys, err := recordKeyInventory(snapshot)
	require.NoError(t, err)
	policyKeys, err := recordKeyInventory(policyRecord)
	require.NoError(t, err)
	controlKeys, err := recordKeyInventory(controlRecord)
	require.NoError(t, err)
	assert.Contains(t, keys, "$.publicationId")
	assert.Contains(t, keys, "$.policyDigest")
	assert.Contains(t, keys, "$.envelopeSignatureDigest")
	assert.Contains(t, keys, "$.blob.ref.$link")
	assert.Contains(t, policyKeys, "$.roles[].deviceId")
	assert.Contains(t, policyKeys, "$.roles[].role")
	assert.Contains(t, policyKeys, "$.recipients[].publicKey")
	assert.Contains(t, controlKeys, "$.revoked")
	roles, ok := policyRecord["roles"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, roles)
	firstRole, ok := roles[0].(map[string]any)
	require.True(t, ok)
	mutatedPolicy := make(map[string]any, len(policyRecord))
	for key, value := range policyRecord {
		mutatedPolicy[key] = value
	}
	mutatedRole := make(map[string]any, len(firstRole)+1)
	for key, value := range firstRole {
		mutatedRole[key] = value
	}
	mutatedRole["leakedField"] = "test"
	mutatedRoles := append([]any(nil), roles...)
	mutatedRoles[0] = mutatedRole
	mutatedPolicy["roles"] = mutatedRoles
	_, err = recordKeyInventory(mutatedPolicy)
	require.Error(t, err)
	assert.ErrorContains(t, err, "unexpected record key $.roles[].leakedField")
	unexpected := map[string]any{"$type": atproto.VaultHeadNSID, "schemaVersion": int64(1), "unexpectedDisclosure": "test"}
	_, err = recordKeyInventory(unexpected)
	require.Error(t, err)
	assert.ErrorContains(t, err, "unexpected record key $.unexpectedDisclosure")
}

func TestPublicationReferenceIntegrity(t *testing.T) {
	fixture := newPublicationFixture(t)
	surface := collectPublicationAudit(context.Background(), fixture.transport, fixture.transport, fixture.did, fixture.pds.StoredBlobCIDs())
	require.Empty(t, surface.incomplete)
	referenced, live, retrievable, findings := auditBlobReferences(surface, fixture.pds.StoredBlobCIDs(), fixture.pds.PubliclyRetrievable)
	require.NotEmpty(t, referenced)
	require.NotEmpty(t, live)
	assert.Empty(t, findings)
	for blobCID := range referenced {
		assert.True(t, live[blobCID])
		assert.True(t, retrievable[blobCID])
	}
	for blobCID := range live {
		assert.True(t, referenced[blobCID])
	}

	orphanPDS := newPublicationTestPDS(t)
	orphanBlob := publicationAuditUploadBlob(t, orphanPDS, []byte("retained orphan control"))
	orphanCID := orphanBlob.Ref.CID().String()
	orphanSurface := collectPublicationAudit(context.Background(), orphanPDS, orphanPDS, publicationAuditDID, []string{orphanCID})
	_, _, _, orphanFindings := auditBlobReferences(orphanSurface, orphanPDS.StoredBlobCIDs(), orphanPDS.PubliclyRetrievable)
	assert.Contains(t, strings.Join(orphanFindings, "\n"), "retained orphan "+orphanCID)
	assert.False(t, orphanPDS.PubliclyRetrievable(orphanCID))

	exposedPDS := newPublicationTestPDS(t)
	exposedBlob := publicationAuditUploadBlob(t, exposedPDS, []byte("post-processing disclosed candidate"))
	exposedCID := exposedBlob.Ref.CID().String()
	exposedValue, err := json.Marshal(map[string]any{"$type": publicationAuditCollection, "blob": exposedBlob})
	require.NoError(t, err)
	exposedPDS.SetHooks(atprototest.MemoryPDSHooks{
		RejectNextApplyWritesAfterBlobProcessing:       true,
		RejectNextApplyWritesAfterBlobProcessingStatus: 400,
		RejectNextApplyWritesAfterBlobProcessingCode:   "StorageQuotaExceeded",
	})
	status, body, err := publicationAuditApplyRecord(context.Background(), exposedPDS, exposedPDS.CurrentRevision().CommitCID.String(), "create", publicationAuditCollection, "exposed-control", exposedValue)
	require.NoError(t, err)
	assert.Equal(t, 400, status)
	assert.JSONEq(t, `{"error":"StorageQuotaExceeded"}`, string(body))
	assert.True(t, exposedPDS.PubliclyRetrievable(exposedCID))
	assert.False(t, exposedPDS.BlobIsLive(exposedCID))
	exposedSurface := collectPublicationAudit(context.Background(), exposedPDS, exposedPDS, publicationAuditDID, []string{exposedCID})
	_, _, _, exposedFindings := auditBlobReferences(exposedSurface, exposedPDS.StoredBlobCIDs(), exposedPDS.PubliclyRetrievable)
	assert.Contains(t, strings.Join(exposedFindings, "\n"), "publicly exposed orphan "+exposedCID)
	assert.Contains(t, strings.Join(exposedFindings, "\n"), "retrievable orphan "+exposedCID)
}

func TestPublicationTransportFailures(t *testing.T) {
	cases := []struct {
		name            string
		hooks           atprototest.MemoryPDSHooks
		wantCode        string
		wantStatus      int
		wantDisposition string
		wantUpload      int
		wantApply       int
		wantQueued      bool
	}{
		{name: "upload quota", hooks: atprototest.MemoryPDSHooks{RejectNextUploadBlobStatus: 400, RejectNextUploadBlobCode: "QuotaExceeded"}, wantCode: "QuotaExceeded", wantStatus: 400, wantDisposition: "quota", wantUpload: 1},
		{name: "post-blob apply storage quota", hooks: atprototest.MemoryPDSHooks{RejectNextApplyWritesAfterBlobProcessing: true, RejectNextApplyWritesAfterBlobProcessingStatus: 400, RejectNextApplyWritesAfterBlobProcessingCode: "StorageQuotaExceeded"}, wantCode: "StorageQuotaExceeded", wantStatus: 400, wantDisposition: "quota", wantUpload: 1, wantApply: 1},
		{name: "auth expiry", hooks: atprototest.MemoryPDSHooks{RejectNextUploadBlobStatus: 401, RejectNextUploadBlobCode: "AuthRequired"}, wantCode: "AuthRequired", wantStatus: 401, wantDisposition: "ambiguous", wantUpload: 1, wantQueued: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPublicationFixture(t)
			newContent := []byte("CONFIDENTIAL_NEW_PUBLICATION_CANARY_2de91f")
			require.NoError(t, os.WriteFile(fixture.filePath, newContent, 0o600))
			beforeState := fixture.logicalStateDigest()
			beforeApplication := fixture.applicationStateDigest()
			beforeKeys := fixture.keyringDigest()
			beforeHome := fixture.homeTreeDigest()
			beforeCommit := fixture.pds.CurrentRevision().CommitCID
			beforeHead, exists := fixture.pds.Record(atproto.VaultHeadNSID, "self")
			require.True(t, exists)
			beforeAttempts, err := fixture.store.TransitionAttempts(context.Background())
			require.NoError(t, err)
			beforeUpload := publicationCallCount(fixture.pds, "com.atproto.repo.uploadBlob")
			beforeApply := publicationCallCount(fixture.pds, "com.atproto.repo.applyWrites")
			beforeStored := fixture.pds.StoredBlobCIDs()
			fixture.pds.SetHooks(test.hooks)
			result, publishErr := fixture.coordinator.Publish(context.Background(), fixture.selection)
			require.Error(t, publishErr)
			assert.ErrorIs(t, publishErr, atproto.ErrCandidateMayBeDisclosed)
			if test.wantQueued {
				assert.ErrorIs(t, publishErr, atproto.ErrPublicationQueued)
			} else {
				assert.ErrorIs(t, publishErr, atproto.ErrPublicationQuota)
			}
			var statusErr *atproto.ProviderStatusError
			require.ErrorAs(t, publishErr, &statusErr)
			assert.Equal(t, test.wantStatus, statusErr.StatusCode)
			assert.Equal(t, test.wantCode, statusErr.Code)
			assert.Equal(t, service.StatusQueued, result.Status)
			assert.Equal(t, test.wantUpload, publicationCallCount(fixture.pds, "com.atproto.repo.uploadBlob")-beforeUpload)
			assert.Equal(t, test.wantApply, publicationCallCount(fixture.pds, "com.atproto.repo.applyWrites")-beforeApply)
			afterAttempts, err := fixture.store.TransitionAttempts(context.Background())
			require.NoError(t, err)
			assert.Len(t, afterAttempts, len(beforeAttempts)+1)
			beforeIDs := make(map[string]bool, len(beforeAttempts))
			for _, attempt := range beforeAttempts {
				beforeIDs[attempt.ID] = true
			}
			var newAttempt *state.TransitionAttempt
			for index := range afterAttempts {
				if !beforeIDs[afterAttempts[index].ID] {
					newAttempt = &afterAttempts[index]
					break
				}
			}
			require.NotNil(t, newAttempt)
			assert.Equal(t, state.TransitionAttemptNotLanded, newAttempt.Outcome)
			var evidence struct {
				RetryDisposition struct {
					Version int    `json:"version"`
					Value   string `json:"value"`
				} `json:"retryDisposition"`
			}
			require.NoError(t, json.Unmarshal([]byte(newAttempt.Evidence), &evidence))
			assert.Equal(t, 1, evidence.RetryDisposition.Version)
			assert.Equal(t, test.wantDisposition, evidence.RetryDisposition.Value)
			assert.Equal(t, beforeState, fixture.logicalStateDigest())
			assert.Equal(t, beforeApplication, fixture.applicationStateDigest())
			assert.Equal(t, beforeKeys, fixture.keyringDigest())
			assert.Equal(t, beforeHome, fixture.homeTreeDigest())
			assert.Equal(t, beforeCommit, fixture.pds.CurrentRevision().CommitCID)
			afterHead, exists := fixture.pds.Record(atproto.VaultHeadNSID, "self")
			require.True(t, exists)
			assert.Equal(t, beforeHead.Data, afterHead.Data)
			assert.NotContains(t, publishErr.Error(), "eyJ.synthetic.access-token-canary.credential")
			if test.name == "post-blob apply storage quota" {
				afterStored := fixture.pds.StoredBlobCIDs()
				var candidate string
				for _, item := range afterStored {
					if !containsString(beforeStored, item) {
						candidate = item
					}
				}
				require.NotEmpty(t, candidate)
				assert.True(t, fixture.pds.PubliclyRetrievable(candidate))
				assert.False(t, fixture.pds.BlobIsLive(candidate))
			}
		})
	}
	t.Run("record signature corruption rebuilds a valid repository commit", func(t *testing.T) {
		fixture := newPublicationFixture(t)
		healthy, err := fixture.coordinator.Pull(context.Background(), fixture.selection)
		require.NoError(t, err)
		assert.Equal(t, uint64(1), healthy.Read.PublicationCount)
		corrupt := publicationCorruptSnapshotRecordSignature(t, fixture)
		transport := publicationRevisionTransport{base: fixture.pds, revision: corrupt}
		fixture.transport = transport
		fixture.coordinator = fixture.newCoordinator(atproto.ATProtoPublicationIO{
			Reader: fixture.reader, Transport: transport, BlobUploadLimit: fixture.blobLimit,
			DID: fixture.did, TrustAnchor: fixture.genesis.Anchor, ObservationStore: fixture.store,
		}, time.Unix(1_800_000_000, 4))
		beforeBlob := publicationCallCount(fixture.pds, "com.atproto.sync.getBlob")
		publicationCompareTierOne(t, fixture, func() error {
			_, readErr := fixture.coordinator.Pull(context.Background(), fixture.selection)
			return readErr
		}, atproto.ErrReadRecordSignature, atproto.ReadStageRecordSignature)
		assert.Equal(t, beforeBlob+2, publicationCallCount(fixture.pds, "com.atproto.sync.getBlob"))
	})
	t.Run("head blob loss reaches the blob read stage", func(t *testing.T) {
		fixture := newPublicationFixture(t)
		_, err := fixture.coordinator.Pull(context.Background(), fixture.selection)
		require.NoError(t, err)
		blobCID, _ := publicationFindHeadBlob(t, fixture)
		beforeBlob := publicationCallCount(fixture.pds, "com.atproto.sync.getBlob")
		fixture.pds.RemoveBlob(blobCID)
		publicationCompareTierOne(t, fixture, func() error {
			_, readErr := fixture.coordinator.Pull(context.Background(), fixture.selection)
			return readErr
		}, atproto.ErrReadBlobMissing, atproto.ReadStageBlob)
		assert.Equal(t, beforeBlob+2, publicationCallCount(fixture.pds, "com.atproto.sync.getBlob"))
	})
	t.Run("mixed view exhausts revision retries", func(t *testing.T) {
		fixture := newPublicationFixture(t)
		_, err := fixture.coordinator.Pull(context.Background(), fixture.selection)
		require.NoError(t, err)
		first, second := publicationCreateSecondRevision(t, fixture)
		moving := &publicationMovingTransport{base: fixture.pds, first: first, second: second}
		fixture.transport = moving
		fixture.coordinator = fixture.newCoordinator(atproto.ATProtoPublicationIO{
			Reader: fixture.reader, Transport: moving, BlobUploadLimit: fixture.blobLimit,
			DID: fixture.did, TrustAnchor: fixture.genesis.Anchor, ObservationStore: fixture.store,
		}, time.Unix(1_800_000_000, 5))
		publicationCompareTierOne(t, fixture, func() error {
			_, readErr := fixture.coordinator.Pull(context.Background(), fixture.selection)
			return readErr
		}, atproto.ErrRevisionMoving, atproto.ReadStageRevision)
		assert.Equal(t, 12, moving.latest)
		assert.Equal(t, 6, moving.stream)
	})
	t.Run("tier 2 authenticated malformed snapshot records only position evidence", func(t *testing.T) {
		testPublicationTierTwoMalformedSnapshot(t)
	})
}

func testPublicationTierTwoMalformedSnapshot(t *testing.T) {
	fixture := newPublicationFixture(t)
	ctx := context.Background()
	baseline, err := fixture.coordinator.Pull(ctx, fixture.selection)
	require.NoError(t, err)
	publicationIO := atproto.ATProtoPublicationIO{
		Reader: fixture.reader, Transport: fixture.transport, BlobUploadLimit: fixture.blobLimit,
		DID: fixture.did, TrustAnchor: fixture.genesis.Anchor, ObservationStore: fixture.store,
	}
	_, predecessor, err := publicationIO.ReadCurrent(ctx)
	require.NoError(t, err)
	packed, err := vault.Pack(baseline.VerifiedSnapshot)
	require.NoError(t, err)
	malformedPlaintext := bytes.Clone(packed.Payload)
	var fileCanary []byte
	for _, item := range fixture.canaries.items {
		if item.name == "file-content" {
			fileCanary = bytes.Clone(item.raw)
			break
		}
	}
	require.NotEmpty(t, fileCanary)
	contentOffset := bytes.Index(malformedPlaintext, fileCanary)
	require.NotEqual(t, -1, contentOffset)
	malformedPlaintext[contentOffset] ^= 0x01
	policy, err := vault.DecodePolicy(predecessor.Policy)
	require.NoError(t, err)
	wraps := make([]vault.RecipientWrapInput, 0, len(policy.Recipients))
	for _, recipient := range policy.Recipients {
		ephemeral, keyErr := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, keyErr)
		var wrapNonce [24]byte
		_, keyErr = rand.Read(wrapNonce[:])
		require.NoError(t, keyErr)
		wraps = append(wraps, vault.RecipientWrapInput{KeyID: bytes.Clone(recipient.KeyID), EphemeralPrivate: [32]byte(ephemeral.Bytes()), WrapNonce: wrapNonce})
	}
	var contentKey [32]byte
	var nonce [24]byte
	var publicationID [16]byte
	_, err = rand.Read(contentKey[:])
	require.NoError(t, err)
	_, err = rand.Read(nonce[:])
	require.NoError(t, err)
	_, err = rand.Read(publicationID[:])
	require.NoError(t, err)
	publication, err := vault.PreparePublication(predecessor, vault.PublicationIntent{
		Vault: fixture.genesis.Vault, Signer: fixture.root, ContentKey: contentKey[:], Wraps: wraps,
		Plaintext: malformedPlaintext, PublicationID: publicationID, Nonce: nonce,
	})
	require.NoError(t, err)
	commit, err := atproto.CommitPublication(ctx, publicationIO, fixture.store, publication, fixture.root.Signing, time.Unix(1_800_000_000, 6))
	require.NoError(t, err)
	assert.Equal(t, atproto.TransitionOutcome(atproto.TransitionOutcomeCommitted), commit.Outcome)

	beforeApplication := fixture.applicationStateDigest()
	beforeHome := fixture.homeTreeDigest()
	beforeCheckpoint, err := fixture.store.VaultCheckpoint(ctx, fixture.genesis.Vault)
	require.NoError(t, err)
	beforePosition, err := fixture.store.AuthenticatedPositionEvidence(ctx, fixture.genesis.Vault, baseline.Read.EpochSeq, fixture.genesis.PolicyDigest)
	require.NoError(t, err)
	beforeHistory, err := fixture.store.AuthenticatedPositionHistory(ctx, fixture.genesis.Vault)
	require.NoError(t, err)
	beforeFileBases, err := fixture.store.AppliedBase(ctx, publicationAuditFileTargetID)
	require.NoError(t, err)
	beforeSettingsBases, err := fixture.store.AppliedBase(ctx, publicationAuditSettingsTargetID)
	require.NoError(t, err)
	beforeJournal, err := fixture.store.JournalEntriesAll(ctx)
	require.NoError(t, err)
	beforeAttempts, err := fixture.store.TransitionAttempts(ctx)
	require.NoError(t, err)

	_, pullErr := fixture.coordinator.Pull(ctx, fixture.selection)
	require.Error(t, pullErr)
	assert.ErrorContains(t, pullErr, "unpack authenticated remote snapshot")
	assert.ErrorContains(t, pullErr, "snapshot entry digest mismatch")
	assert.Equal(t, beforeApplication, fixture.applicationStateDigest())
	assert.Equal(t, beforeHome, fixture.homeTreeDigest())
	afterCheckpoint, err := fixture.store.VaultCheckpoint(ctx, fixture.genesis.Vault)
	require.NoError(t, err)
	assert.Equal(t, beforeCheckpoint, afterCheckpoint)
	afterFileBases, err := fixture.store.AppliedBase(ctx, publicationAuditFileTargetID)
	require.NoError(t, err)
	assert.Equal(t, beforeFileBases, afterFileBases)
	afterSettingsBases, err := fixture.store.AppliedBase(ctx, publicationAuditSettingsTargetID)
	require.NoError(t, err)
	assert.Equal(t, beforeSettingsBases, afterSettingsBases)
	afterJournal, err := fixture.store.JournalEntriesAll(ctx)
	require.NoError(t, err)
	assert.Equal(t, beforeJournal, afterJournal)
	afterAttempts, err := fixture.store.TransitionAttempts(ctx)
	require.NoError(t, err)
	assert.Equal(t, beforeAttempts, afterAttempts)

	afterPosition, err := fixture.store.AuthenticatedPositionEvidence(ctx, fixture.genesis.Vault, baseline.Read.EpochSeq, fixture.genesis.PolicyDigest)
	require.NoError(t, err)
	assert.Equal(t, beforePosition.Policy, afterPosition.Policy)
	assert.Equal(t, beforePosition.Control, afterPosition.Control)
	assert.Equal(t, beforePosition.PolicyDigest, afterPosition.PolicyDigest)
	beforeHead, err := vault.DecodeHead(beforePosition.Head)
	require.NoError(t, err)
	afterHead, err := vault.DecodeHead(afterPosition.Head)
	require.NoError(t, err)
	assert.NotEqual(t, beforeHead.SnapshotCID, afterHead.SnapshotCID)
	assert.Equal(t, uint64(2), afterHead.PublicationCount)
	remoteHeadRecord, exists := fixture.pds.Record(atproto.VaultHeadNSID, "self")
	require.True(t, exists)
	decodedRemoteHead, err := atproto.DecodeRecord(remoteHeadRecord.Data)
	require.NoError(t, err)
	remoteHead, ok := decodedRemoteHead.(atproto.HeadRecord)
	require.True(t, ok)
	assert.Equal(t, remoteHead.SnapshotCID, afterHead.SnapshotCID)
	afterHistory, err := fixture.store.AuthenticatedPositionHistory(ctx, fixture.genesis.Vault)
	require.NoError(t, err)
	assert.Len(t, afterHistory, len(beforeHistory)+1)
	for _, prior := range beforeHistory {
		assert.Contains(t, afterHistory, prior)
	}
	matchingRows := 0
	for _, evidence := range afterHistory {
		historyHead, decodeErr := vault.DecodeHead(evidence.Head)
		require.NoError(t, decodeErr)
		if bytes.Equal(historyHead.SnapshotCID, remoteHead.SnapshotCID) {
			matchingRows++
			assert.Equal(t, afterPosition.Policy, evidence.Policy)
			assert.Equal(t, afterPosition.Control, evidence.Control)
			assert.Equal(t, afterPosition.Head, evidence.Head)
		}
	}
	assert.Equal(t, 1, matchingRows)
}

func TestPublicationWrongRole(t *testing.T) {
	for _, roleCase := range []struct {
		name       string
		role       vault.Role
		mustRefuse bool
	}{
		{name: "publisher control", role: vault.RoleRoot},
		{name: "restore-only cannot publish", role: vault.RoleRestoreOnly, mustRefuse: true},
	} {
		t.Run(roleCase.name, func(t *testing.T) {
			fixture := newPublicationFixture(t)
			ctx := context.Background()
			if !roleCase.mustRefuse {
				require.Equal(t, vault.RoleRoot, roleCase.role)
				require.NoError(t, os.WriteFile(fixture.filePath, []byte("healthy publisher control"), 0o600))
				result, err := fixture.coordinator.Publish(ctx, fixture.selection)
				require.NoError(t, err)
				assert.Equal(t, service.StatusCommitted, result.Status)
				return
			}
			baseline, err := fixture.coordinator.Pull(ctx, fixture.selection)
			require.NoError(t, err)
			packed, err := vault.Pack(baseline.VerifiedSnapshot)
			require.NoError(t, err)
			newSigning, newRecipient, err := vault.GenerateDeviceKeys()
			require.NoError(t, err)
			restore := vault.DeviceMaterial{DeviceID: "publication-restore-only", KeyID: bytes.Clone(newSigning.Public().(ed25519.PublicKey)), Signing: newSigning, Recipient: newRecipient}
			transitionIO := atproto.ATProtoTransitionIO{
				Reader: fixture.reader, Transport: fixture.transport, BlobUploadLimit: fixture.blobLimit,
				DID: fixture.did, TrustAnchor: fixture.genesis.Anchor,
				PreviousPolicies: [][]byte{publicationHarnessPolicyRecord(t, fixture.genesis.Policy)}, PreviousControls: [][]byte{publicationHarnessControlRecord(t, fixture.genesis.Control)},
				ObservationStore: fixture.store,
			}
			_, predecessor, err := transitionIO.ReadCurrent(ctx)
			require.NoError(t, err)
			rootEphemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
			require.NoError(t, err)
			newEphemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
			require.NoError(t, err)
			var publicationID [16]byte
			var nonce [24]byte
			_, err = rand.Read(publicationID[:])
			require.NoError(t, err)
			_, err = rand.Read(nonce[:])
			require.NoError(t, err)
			contentKey := make([]byte, 32)
			_, err = rand.Read(contentKey)
			require.NoError(t, err)
			transition, err := vault.PrepareTransition(predecessor, vault.TransitionIntent{
				Kind: vault.TransitionEnroll, Vault: fixture.genesis.Vault, Signer: fixture.root, NewDevice: &restore,
				RequestedRole: roleCase.role, ContentKey: contentKey, Recipients: predecessor.Certificates,
				Wraps: []vault.RecipientWrapInput{
					{KeyID: bytes.Clone(fixture.root.KeyID), EphemeralPrivate: [32]byte(rootEphemeral.Bytes())},
					{KeyID: bytes.Clone(restore.KeyID), EphemeralPrivate: [32]byte(newEphemeral.Bytes())},
				},
				Plaintext: packed.Payload, PublicationID: publicationID, Nonce: nonce,
			})
			require.NoError(t, err)
			transitionResult, err := atproto.CommitTransition(ctx, transitionIO, fixture.store, transition, fixture.root.Signing, time.Unix(1_800_000_000, 1))
			require.NoError(t, err)
			assert.Equal(t, atproto.TransitionOutcome(atproto.TransitionOutcomeCommitted), transitionResult.Outcome)
			_, err = fixture.coordinator.Pull(ctx, fixture.selection)
			require.NoError(t, err)
			require.NoError(t, fixture.store.PutVaultSelection(ctx, state.VaultSelection{Vault: fixture.genesis.Vault, DeviceID: restore.DeviceID, RecordedAt: time.Unix(1_800_000_000, 2).Unix()}))
			fixture.keyring.devices[restore.DeviceID] = restore
			fixture.selection.DeviceID = restore.DeviceID
			require.NoError(t, os.WriteFile(fixture.filePath, []byte("role violation candidate"), 0o600))
			coordinator := fixture.newCoordinator(atproto.ATProtoPublicationIO{
				Reader: fixture.reader, Transport: fixture.transport, BlobUploadLimit: fixture.blobLimit,
				DID: fixture.did, TrustAnchor: fixture.genesis.Anchor, ObservationStore: fixture.store,
			}, time.Unix(1_800_000_000, 3))
			beforeUpload := publicationCallCount(fixture.pds, "com.atproto.repo.uploadBlob")
			beforeApply := publicationCallCount(fixture.pds, "com.atproto.repo.applyWrites")
			_, err = coordinator.Publish(ctx, fixture.selection)
			require.ErrorIs(t, err, vault.ErrPublicationAuthority)
			assert.Equal(t, beforeUpload, publicationCallCount(fixture.pds, "com.atproto.repo.uploadBlob"))
			assert.Equal(t, beforeApply, publicationCallCount(fixture.pds, "com.atproto.repo.applyWrites"))
		})
	}
}

func TestPublicationAuditDetectsSeededLeaks(t *testing.T) {
	canary := "POSITIVE_CONTROL_RECORD_PLAINTEXT_719ad"
	blobCanary := "POSITIVE_CONTROL_BLOB_PLAINTEXT_a105d"
	compressedCanary := "POSITIVE_CONTROL_COMPRESSED_CANARY_d13a2"
	orphanCanary := "POSITIVE_CONTROL_ORPHAN_CANARY_3e01a"
	reportCanary := "POSITIVE_CONTROL_REPORT_CANARY_918ca"
	registry := publicationCanaries{}
	registry.add("seeded-record", publicationConfidential, []byte(canary))
	registry.add("seeded-blob", publicationConfidential, []byte(blobCanary))
	registry.add("seeded-compressed", publicationConfidential, []byte(compressedCanary))
	registry.add("seeded-orphan", publicationConfidential, []byte(orphanCanary))
	testPDS := newPublicationTestPDS(t)
	seedPlaintextRecord(t, testPDS, publicationAuditCollection, "plaintext-control", canary)
	plainCID := seedBlobReferenceRecord(t, testPDS, "blob-control", []byte(blobCanary))
	compressed := compressedPublicationCanary(t, compressedCanary, true)
	assert.NotContains(t, string(compressed), compressedCanary)
	compressedCID := seedBlobReferenceRecord(t, testPDS, "compressed-control", compressed)
	zlibCompressed := compressedPublicationCanary(t, compressedCanary, false)
	assert.NotContains(t, string(zlibCompressed), compressedCanary)
	zlibCID := seedBlobReferenceRecord(t, testPDS, "zlib-compressed-control", zlibCompressed)
	orphan := publicationAuditUploadBlob(t, testPDS, []byte(orphanCanary))
	orphanCID := orphan.Ref.CID().String()
	exposed := publicationAuditUploadBlob(t, testPDS, []byte("exposed orphan bytes"))
	exposedCID := exposed.Ref.CID().String()
	exposedValue, err := json.Marshal(map[string]any{"$type": publicationAuditCollection, "blob": exposed})
	require.NoError(t, err)
	testPDS.SetHooks(atprototest.MemoryPDSHooks{RejectNextApplyWritesAfterBlobProcessing: true})
	status, _, err := publicationAuditApplyRecord(context.Background(), testPDS, testPDS.CurrentRevision().CommitCID.String(), "create", publicationAuditCollection, "exposed-orphan-control", exposedValue)
	require.NoError(t, err)
	assert.Equal(t, 400, status)
	assert.True(t, testPDS.PubliclyRetrievable(exposedCID))
	encodedOnly := "ENCODED_ONLY_CANARY_2f8d3"
	registry.add("encoded-only", publicationConfidential, []byte(encodedOnly))
	encodedForm := base64.StdEncoding.EncodeToString([]byte(encodedOnly))
	encodedRecord, err := json.Marshal(map[string]any{"$type": publicationAuditCollection, "value": encodedForm})
	require.NoError(t, err)
	_, _, err = publicationAuditApplyRecord(context.Background(), testPDS, testPDS.CurrentRevision().CommitCID.String(), "create", publicationAuditCollection, "encoded-record-control", encodedRecord)
	require.NoError(t, err)
	encodedCID := seedBlobReferenceRecord(t, testPDS, "encoded-blob-control", []byte(encodedForm))
	surface := collectPublicationAudit(context.Background(), testPDS, testPDS, publicationAuditDID, []string{orphanCID, exposedCID})
	require.Empty(t, surface.incomplete)
	findings := publicationAuditFindings(surface, registry)
	assert.Contains(t, findings, "seeded-record")
	recordBlock := ""
	for blockCID, block := range surface.blocks {
		if bytes.Contains(block, []byte(canary)) {
			recordBlock = blockCID
		}
	}
	require.NotEmpty(t, recordBlock)
	assert.Contains(t, findings, "CAR block "+recordBlock+" seeded-record")
	assert.Contains(t, findings, "listRecords "+publicationAuditCollection+" seeded-record")
	assert.Contains(t, findings, "getBlob "+plainCID+" seeded-blob")
	assert.Contains(t, findings, "getBlob "+compressedCID+" seeded-compressed")
	assert.Contains(t, findings, "getBlob "+zlibCID+" seeded-compressed")
	assert.Contains(t, findings, "listRecords "+publicationAuditCollection+" encoded-only")
	assert.Contains(t, findings, "getBlob "+encodedCID+" encoded-only")
	assert.NotContains(t, string(surface.repoBytes), encodedOnly)
	assert.NotContains(t, string(surface.blobs[encodedCID]), encodedOnly)
	_, _, _, integrityFindings := auditBlobReferences(surface, testPDS.StoredBlobCIDs(), testPDS.PubliclyRetrievable)
	assert.Contains(t, strings.Join(integrityFindings, "\n"), "retained orphan "+orphanCID)
	assert.Contains(t, strings.Join(integrityFindings, "\n"), "publicly exposed orphan "+exposedCID)
	syntheticReport := []byte("service report: " + reportCanary)
	registry.add("seeded-service-report", publicationConfidential, []byte(reportCanary))
	assert.Contains(t, scanPublicationCanaries(syntheticReport, registry, publicationConfidential), "seeded-service-report")
	gap := publicationAuditSurface{incomplete: []string{"getRepo CAR parse failed"}}
	assert.Contains(t, publicationAuditFindings(gap, registry), "getRepo CAR parse failed")
	unexpected := map[string]any{"$type": atproto.VaultHeadNSID, "schemaVersion": int64(1), "addedField": "leak"}
	_, err = recordKeyInventory(unexpected)
	require.Error(t, err)
	assert.ErrorContains(t, err, "unexpected record key $.addedField")
}

func TestCleanupPublicationLiveRecordsAcceptsRecordNotFound(t *testing.T) {
	t.Run("record was never created", func(t *testing.T) {
		transport := &publicationCleanupTransport{
			getStatuses: []int{http.StatusBadRequest},
			getBodies:   [][]byte{[]byte(`{"error":"RecordNotFound"}`)},
		}
		cleanupPublicationLiveRecords(t, transport, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", []string{"systems.lamb.dottie.vaultHead/self"})
		assert.Equal(t, []string{"GET com.atproto.repo.getRecord"}, transport.calls)
	})

	t.Run("deletion is verified with RecordNotFound", func(t *testing.T) {
		transport := &publicationCleanupTransport{
			getStatuses: []int{http.StatusOK, http.StatusBadRequest},
			getBodies:   [][]byte{[]byte(`{"value":{}}`), []byte(`{"error":"RecordNotFound"}`)},
		}
		cleanupPublicationLiveRecords(t, transport, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", []string{"systems.lamb.dottie.vaultHead/self"})
		assert.Equal(t, []string{
			"GET com.atproto.repo.getRecord",
			"POST com.atproto.repo.deleteRecord",
			"GET com.atproto.repo.getRecord",
		}, transport.calls)
	})
}

type publicationCleanupTransport struct {
	getStatuses []int
	getBodies   [][]byte
	getCalls    int
	calls       []string
}

func (transport *publicationCleanupTransport) Do(_ context.Context, method, endpoint string, _ url.Values, _ []byte, _ string) (int, []byte, error) {
	transport.calls = append(transport.calls, method+" "+endpoint)
	if endpoint == "com.atproto.repo.getRecord" {
		index := transport.getCalls
		transport.getCalls++
		return transport.getStatuses[index], bytes.Clone(transport.getBodies[index]), nil
	}
	if endpoint == "com.atproto.repo.deleteRecord" {
		return http.StatusOK, nil, nil
	}
	return 0, nil, fmt.Errorf("unexpected endpoint")
}

func (transport *publicationCleanupTransport) OpenStream(context.Context, string, url.Values) (int, io.ReadCloser, error) {
	return 0, nil, fmt.Errorf("synthetic stream unavailable")
}

func TestLivePublicationRepositoryPrecondition(t *testing.T) {
	did := "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
	transport := &liveRepositoryDescriptionTransport{
		status: http.StatusOK,
		body:   []byte(`{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","collections":["app.bsky.graph.follow","app.bsky.actor.profile"]}`),
	}
	skipReason, err := livePublicationRepositoryPrecondition(context.Background(), transport, did)
	require.NoError(t, err)
	assert.Equal(t, "repository is not empty; collections: app.bsky.actor.profile, app.bsky.graph.follow; genesis requires an empty repository; a skipped gate is not provider evidence", skipReason)
	assert.Equal(t, http.MethodGet, transport.method)
	assert.Equal(t, "com.atproto.repo.describeRepo", transport.endpoint)
	assert.Equal(t, did, transport.query.Get("repo"))

	transport = &liveRepositoryDescriptionTransport{
		status: http.StatusOK,
		body:   []byte(`{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","collections":[]}`),
	}
	skipReason, err = livePublicationRepositoryPrecondition(context.Background(), transport, did)
	require.NoError(t, err)
	assert.Empty(t, skipReason)
}

type liveRepositoryDescriptionTransport struct {
	status   int
	body     []byte
	method   string
	endpoint string
	query    url.Values
}

func (transport *liveRepositoryDescriptionTransport) Do(_ context.Context, method, endpoint string, query url.Values, _ []byte, _ string) (int, []byte, error) {
	transport.method = method
	transport.endpoint = endpoint
	transport.query = query
	return transport.status, bytes.Clone(transport.body), nil
}

func (transport *liveRepositoryDescriptionTransport) OpenStream(context.Context, string, url.Values) (int, io.ReadCloser, error) {
	return 0, nil, fmt.Errorf("synthetic stream unavailable")
}

type livePublicationRunManifest struct {
	RunID            string   `json:"run_id"`
	Provider         string   `json:"provider"`
	Handle           string   `json:"handle"`
	Collections      []string `json:"collections"`
	RecordTargets    []string `json:"record_targets,omitempty"`
	UploadedBlobCIDs []string `json:"uploaded_blob_cids"`
}

type livePublicationArtifact struct {
	RunID                  string   `json:"run_id"`
	Provider               string   `json:"provider"`
	Criterion              string   `json:"criterion"`
	Outcome                string   `json:"outcome"`
	RecordCount            int      `json:"record_count"`
	EnumeratedLiveCIDCount int      `json:"enumerated_live_cid_count"`
	UploadedCIDCount       int      `json:"uploaded_cid_count"`
	RetainedSetEvidence    string   `json:"retained_set_evidence"`
	StandingLimits         []string `json:"standing_limits"`
	BlobRetentionNote      string   `json:"blob_retention_note"`
}

func newLivePublicationArtifact(runID, provider string) livePublicationArtifact {
	return livePublicationArtifact{
		RunID: runID, Provider: provider, Criterion: "live publication privacy audited",
		RetainedSetEvidence: "retained_set=unobservable",
		StandingLimits: []string{
			"record reads are public", "blob fetches are public", "blob enumeration is authenticated",
			"hosted logs and server storage are unobservable", "provider blobs cannot be deleted",
		},
		BlobRetentionNote: "A successful live privacy run leaves its uploaded ciphertext blobs on the provider permanently because the provider exposes no blob delete; this is expected and recorded rather than cleaned.",
	}
}

func writeLivePublicationArtifact(directory string, artifact livePublicationArtifact) (string, error) {
	encoded, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(directory, "publication-privacy.json")
	if err := writeAtomicLiveFile(path, encoded); err != nil {
		return "", err
	}
	return path, nil
}

func writeLivePublicationManifest(path string, manifest livePublicationRunManifest) error {
	if manifest.UploadedBlobCIDs == nil {
		manifest.UploadedBlobCIDs = []string{}
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return writeAtomicLiveFile(path, encoded)
}

func persistLivePublicationUpload(path string, manifest *livePublicationRunManifest, cid string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("uploaded blob CID cannot be recorded because the run manifest does not exist: %w", err)
	}
	if !containsString(manifest.UploadedBlobCIDs, cid) {
		manifest.UploadedBlobCIDs = append(manifest.UploadedBlobCIDs, cid)
	}
	return writeLivePublicationManifest(path, *manifest)
}

func writeAtomicLiveFile(path string, contents []byte) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".dottie-live-write-")
	if err != nil {
		return err
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

func TestLivePublicationPrivacy(t *testing.T) {
	if os.Getenv("DOTTIE_LIVE_PUBLICATION_PRIVACY") != "1" {
		t.Skip("set DOTTIE_LIVE_PUBLICATION_PRIVACY=1 with explicit disposable-account authorization to run the live publication privacy audit")
	}
	handle := os.Getenv("DOTTIE_HANDLE")
	if !allowedPDSHandle(handle) {
		require.True(t, allowedPDSHandle(handle), "DOTTIE_HANDLE is not in the live disposable-identity allowlist")
	}
	provider := pdsProviderName(handle)
	runID := hex.EncodeToString(publicationAuditRandom(t, 16))
	manifestDir := liveArtifactDir(t)
	manifest := livePublicationRunManifest{
		RunID: runID, Provider: provider, Handle: handle,
		Collections: append([]string(nil), publicationAuditCollections...), RecordTargets: []string{}, UploadedBlobCIDs: []string{},
	}
	manifestPath := filepath.Join(manifestDir, "run-manifest.json")
	artifact := newLivePublicationArtifact(runID, provider)
	var tracked *publicationCIDTracker
	var recordCount, enumeratedLiveCIDCount, uploadedCIDCount int
	auditCompleted := false
	defer func() {
		artifact.RecordCount = recordCount
		artifact.EnumeratedLiveCIDCount = enumeratedLiveCIDCount
		if tracked != nil {
			uploadedCIDCount = len(tracked.uploaded)
		}
		artifact.UploadedCIDCount = uploadedCIDCount
		if t.Failed() {
			artifact.Outcome = "failed"
		} else if t.Skipped() {
			artifact.Outcome = "skipped"
		} else if auditCompleted {
			artifact.Outcome = "passed"
		} else {
			artifact.Outcome = "failed"
		}
		path, writeErr := writeLivePublicationArtifact(manifestDir, artifact)
		assert.NoError(t, writeErr)
		if writeErr == nil {
			t.Logf("live publication artifact written (%s)", filepath.Base(path))
		}
	}()
	keyring, err := platform.NewKeyring()
	require.NoError(t, err)
	defer keyring.Close()
	client, err := atproto.NewClient("https://dottie.lamb.systems/client-metadata.json", keyring)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	identity, err := client.Discover(ctx, handle)
	require.NoError(t, err)
	session, err := client.LoadSession(ctx, identity.DID)
	require.NoError(t, err)
	for _, collection := range publicationAuditCollections {
		assert.True(t, hasPDScope(session.Scopes, "repo:"+collection))
	}
	assert.True(t, hasPDScope(session.Scopes, "blob:application/octet-stream"))
	auth, err := atproto.NewAuthMethod(client, identity, handle, session)
	require.NoError(t, err)
	authenticatedAPI, err := newPDSAPIClient(identity.PDS, auth, nil)
	require.NoError(t, err)
	anonymousAPI, err := newPDSAPIClient(identity.PDS, nil, nil)
	require.NoError(t, err)
	authenticated := atproto.NewATClientTransport(authenticatedAPI)
	tracked = &publicationCIDTracker{base: authenticated, manifestPath: manifestPath}
	tracked.onUpload = func(cid string) error {
		return persistLivePublicationUpload(manifestPath, &manifest, cid)
	}
	anonymous := atproto.NewATClientTransport(anonymousAPI)
	skipReason, err := livePublicationRepositoryPrecondition(ctx, anonymous, identity.DID)
	require.NoError(t, err)
	if skipReason != "" {
		t.Skip(skipReason)
	}
	require.NoError(t, writeLivePublicationManifest(manifestPath, manifest))
	reader := atproto.RevisionReader{Transport: tracked, Budgets: atproto.DefaultBudgets(), DIDDocumentID: identity.DIDDocumentID, VerificationMethods: identity.VerificationMethods}
	baseline := collectPublicationAudit(ctx, anonymous, authenticated, identity.DID, nil)
	require.Empty(t, baseline.incomplete)
	for collection, pages := range baseline.recordPages {
		for _, body := range pages {
			var result struct {
				Records []json.RawMessage `json:"records"`
			}
			require.NoError(t, json.Unmarshal(body, &result))
			require.Empty(t, result.Records, "refusing to alter account with existing records in %s", collection)
		}
	}
	defer func() { cleanupPublicationLiveRecords(t, authenticated, identity.DID, manifest.RecordTargets) }()
	limit, known, described := describePDS(t, ctx, provider, identity.PDS, anonymousAPI)
	require.True(t, described && known)
	beforeGenesisWrite := func(genesis vault.Genesis, device vault.DeviceMaterial) {
		envelope, decodeErr := vault.DecodeEnvelope(genesis.Snapshot)
		assert.NoError(t, decodeErr)
		if decodeErr != nil {
			return
		}
		snapshotRKey := "genesis-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(envelope.PublicationID[:]))
		certificateHash := sha256.Sum256(append([]byte(device.DeviceID+"\x00"), device.KeyID...))
		manifest.RecordTargets = []string{
			atproto.VaultSnapshotNSID + "/" + snapshotRKey,
			atproto.VaultHeadNSID + "/self", atproto.VaultControlNSID + "/self",
			atproto.VaultPolicyNSID + "/self", atproto.VaultCheckpointNSID + "/self",
			atproto.VaultCertificateNSID + "/" + hex.EncodeToString(certificateHash[:]),
		}
		assert.NoError(t, writeLivePublicationManifest(manifestPath, manifest))
	}
	tracked.beforeWrite = func(body []byte) error {
		var input struct {
			Writes []struct {
				Collection string `json:"collection"`
				RKey       string `json:"rkey"`
			} `json:"writes"`
		}
		if err := json.Unmarshal(body, &input); err != nil {
			return err
		}
		for _, write := range input.Writes {
			target := write.Collection + "/" + write.RKey
			if !containsString(manifest.RecordTargets, target) {
				manifest.RecordTargets = append(manifest.RecordTargets, target)
			}
		}
		return writeLivePublicationManifest(manifestPath, manifest)
	}
	fixture := newPublicationFixtureWithTransport(t, tracked, reader, identity.DID, limit, nil, nil, beforeGenesisWrite)
	surface := collectPublicationAudit(ctx, anonymous, authenticated, identity.DID, tracked.uploaded)
	recordCount = len(surface.records)
	enumeratedLiveCIDCount = len(surface.listBlobs)
	uploadedCIDCount = len(tracked.uploaded)
	require.Empty(t, surface.incomplete)
	assert.Empty(t, publicationAuditFindings(surface, fixture.canaries))
	referenceIntegrityCIDs := append([]string(nil), surface.listBlobs...)
	for _, blobCID := range tracked.uploaded {
		if !containsString(referenceIntegrityCIDs, blobCID) {
			referenceIntegrityCIDs = append(referenceIntegrityCIDs, blobCID)
		}
	}
	_, _, _, refsFindings := auditBlobReferences(surface, referenceIntegrityCIDs, nil)
	assert.Empty(t, refsFindings)
	assert.Contains(t, string(surface.repoBytes), fixture.root.DeviceID)
	assert.True(t, bytes.Contains(surface.repoBytes, fixture.genesis.Vault[:]))
	assert.FileExists(t, manifestPath)
	artifact.Criterion = "live publication privacy audited"
	artifact.RetainedSetEvidence = "retained_set=unobservable"
	auditCompleted = true
}

func cleanupPublicationLiveRecords(t *testing.T, transport atproto.Transport, did string, targets []string) {
	t.Helper()
	for _, target := range targets {
		parts := strings.SplitN(target, "/", 2)
		if len(parts) != 2 {
			assert.Fail(t, "live run manifest contains an invalid record target")
			continue
		}
		collection, rkey := parts[0], parts[1]
		query := url.Values{"repo": {did}, "collection": {collection}, "rkey": {rkey}}
		status, responseBody, err := transport.Do(context.Background(), "GET", "com.atproto.repo.getRecord", query, nil, "")
		if err != nil {
			assert.Fail(t, "live record cleanup lookup failed")
			continue
		}
		if isPDSRecordAbsent(status, responseBody) {
			continue
		}
		if status != 200 {
			assert.Fail(t, "live record cleanup lookup returned an unexpected status")
			continue
		}
		body, err := json.Marshal(map[string]string{"repo": did, "collection": collection, "rkey": rkey})
		if err != nil {
			assert.Fail(t, "live record cleanup request could not be encoded")
			continue
		}
		status, _, err = transport.Do(context.Background(), "POST", "com.atproto.repo.deleteRecord", nil, body, "application/json")
		assert.True(t, err == nil && status >= 200 && status < 300, "live record cleanup request did not commit")
		status, responseBody, err = transport.Do(context.Background(), "GET", "com.atproto.repo.getRecord", query, nil, "")
		assert.True(t, err == nil && isPDSRecordAbsent(status, responseBody), "live record cleanup was not verified")
	}
}

func livePublicationRepositoryPrecondition(ctx context.Context, transport atproto.Transport, did string) (string, error) {
	status, body, err := transport.Do(ctx, "GET", "com.atproto.repo.describeRepo", url.Values{"repo": {did}}, nil, "")
	if err != nil {
		return "", fmt.Errorf("live repository description failed")
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("live repository description returned status %d", status)
	}
	var description struct {
		Collections *[]string `json:"collections"`
	}
	if err := json.Unmarshal(body, &description); err != nil {
		return "", fmt.Errorf("live repository description was invalid")
	}
	if description.Collections == nil {
		return "", fmt.Errorf("live repository description omitted collections")
	}
	if len(*description.Collections) == 0 {
		return "", nil
	}
	collections := append([]string(nil), (*description.Collections)...)
	sort.Strings(collections)
	return "repository is not empty; collections: " + strings.Join(collections, ", ") + "; genesis requires an empty repository; a skipped gate is not provider evidence", nil
}

type publicationAuditRecordingTransport struct {
	base     atproto.Transport
	calls    []string
	blobCIDs []string
}

func (transport *publicationAuditRecordingTransport) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	transport.calls = append(transport.calls, endpoint)
	return transport.base.Do(ctx, method, endpoint, query, body, contentType)
}

func (transport *publicationAuditRecordingTransport) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	transport.calls = append(transport.calls, endpoint)
	if endpoint == "com.atproto.sync.getBlob" {
		transport.blobCIDs = append(transport.blobCIDs, query.Get("cid"))
	}
	return transport.base.OpenStream(ctx, endpoint, query)
}

func publicationAuditRecordedEndpoints(transport *publicationAuditRecordingTransport) []string {
	return append([]string(nil), transport.calls...)
}

type publicationCIDTracker struct {
	base         atproto.Transport
	uploaded     []string
	beforeWrite  func([]byte) error
	manifestPath string
	onUpload     func(string) error
}

func (tracker *publicationCIDTracker) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	if endpoint == "com.atproto.repo.applyWrites" && tracker.beforeWrite != nil {
		if err := tracker.beforeWrite(body); err != nil {
			return 0, nil, err
		}
	}
	if endpoint == "com.atproto.repo.uploadBlob" && tracker.manifestPath != "" {
		if tracker.onUpload == nil {
			return 0, nil, fmt.Errorf("publication blob upload has no run-manifest persistence callback")
		}
		if _, err := os.Stat(tracker.manifestPath); err != nil {
			return 0, nil, fmt.Errorf("publication blob upload attempted before run manifest exists: %w", err)
		}
	}
	status, response, err := tracker.base.Do(ctx, method, endpoint, query, body, contentType)
	if endpoint == "com.atproto.repo.uploadBlob" && err == nil && status >= 200 && status < 300 {
		blobCID := uploadedCID(response)
		if blobCID == "" {
			return status, response, fmt.Errorf("successful publication blob upload omitted its CID")
		}
		if !containsString(tracker.uploaded, blobCID) {
			tracker.uploaded = append(tracker.uploaded, blobCID)
			if tracker.onUpload != nil {
				if err := tracker.onUpload(blobCID); err != nil {
					return status, response, fmt.Errorf("persist uploaded publication blob CID: %w", err)
				}
			}
		}
	}
	return status, response, err
}

func (tracker *publicationCIDTracker) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	return tracker.base.OpenStream(ctx, endpoint, query)
}

type publicationUploadTestTransport struct {
	response []byte
	calls    int
}

func (transport *publicationUploadTestTransport) Do(context.Context, string, string, url.Values, []byte, string) (int, []byte, error) {
	transport.calls++
	return http.StatusOK, bytes.Clone(transport.response), nil
}

func (*publicationUploadTestTransport) OpenStream(context.Context, string, url.Values) (int, io.ReadCloser, error) {
	return 0, nil, fmt.Errorf("synthetic stream unavailable")
}

func TestLivePublicationEvidencePersistsUploadedCIDsAndSuccessArtifact(t *testing.T) {
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "run-manifest.json")
	manifest := livePublicationRunManifest{
		RunID: "offline-run-id", Provider: "Bluesky-hosted", Collections: []string{},
		RecordTargets: []string{}, UploadedBlobCIDs: []string{},
	}
	require.NoError(t, writeLivePublicationManifest(manifestPath, manifest))
	transport := &publicationUploadTestTransport{response: []byte(`{"blob":{"ref":{"$link":"bafycid-one"}}}`)}
	tracker := &publicationCIDTracker{base: transport, manifestPath: manifestPath}
	tracker.onUpload = func(cid string) error {
		return persistLivePublicationUpload(manifestPath, &manifest, cid)
	}
	for _, cid := range []string{"bafycid-one", "bafycid-two", "bafycid-one"} {
		transport.response = []byte(fmt.Sprintf(`{"blob":{"ref":{"$link":%q}}}`, cid))
		status, _, err := tracker.Do(context.Background(), "POST", "com.atproto.repo.uploadBlob", nil, nil, "application/octet-stream")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	var persisted livePublicationRunManifest
	require.NoError(t, json.Unmarshal(manifestBytes, &persisted))
	require.Equal(t, []string{"bafycid-one", "bafycid-two"}, persisted.UploadedBlobCIDs)
	manifestInfo, err := os.Stat(manifestPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), manifestInfo.Mode().Perm())

	artifact := newLivePublicationArtifact("offline-run-id", "Bluesky-hosted")
	artifact.Outcome = "passed"
	artifact.RecordCount = 7
	artifact.EnumeratedLiveCIDCount = 2
	artifact.UploadedCIDCount = len(tracker.uploaded)
	artifactPath, err := writeLivePublicationArtifact(directory, artifact)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(directory, "publication-privacy.json"), artifactPath)
	require.FileExists(t, artifactPath)
	artifactBytes, err := os.ReadFile(artifactPath)
	require.NoError(t, err)
	var persistedArtifact livePublicationArtifact
	require.NoError(t, json.Unmarshal(artifactBytes, &persistedArtifact))
	require.Equal(t, "offline-run-id", persistedArtifact.RunID)
	require.Equal(t, "Bluesky-hosted", persistedArtifact.Provider)
	require.Equal(t, "live publication privacy audited", persistedArtifact.Criterion)
	require.Equal(t, "passed", persistedArtifact.Outcome)
	require.Equal(t, 7, persistedArtifact.RecordCount)
	require.Equal(t, 2, persistedArtifact.EnumeratedLiveCIDCount)
	require.Equal(t, 2, persistedArtifact.UploadedCIDCount)
	require.Equal(t, "retained_set=unobservable", persistedArtifact.RetainedSetEvidence)
	limits := strings.Join(persistedArtifact.StandingLimits, "; ")
	for _, limit := range []string{"record reads are public", "blob fetches are public", "blob enumeration is authenticated", "hosted logs and server storage are unobservable", "provider blobs cannot be deleted"} {
		require.Contains(t, limits, limit)
	}
	require.Contains(t, persistedArtifact.BlobRetentionNote, "permanently")
	require.Contains(t, persistedArtifact.BlobRetentionNote, "expected and recorded rather than cleaned")
	require.NotContains(t, string(artifactBytes), "bafycid-one")
	require.NotContains(t, string(artifactBytes), directory)
	artifactInfo, err := os.Stat(artifactPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), artifactInfo.Mode().Perm())

	missingTransport := &publicationUploadTestTransport{response: transport.response}
	missingTracker := &publicationCIDTracker{
		base: missingTransport, manifestPath: filepath.Join(directory, "missing-manifest.json"),
		onUpload: func(cid string) error { return nil },
	}
	_, _, err = missingTracker.Do(context.Background(), "POST", "com.atproto.repo.uploadBlob", nil, nil, "application/octet-stream")
	require.ErrorContains(t, err, "attempted before run manifest exists")
	require.Zero(t, missingTransport.calls)
}

type publicationRevisionTransport struct {
	base     atproto.Transport
	revision atprototest.SignedRevision
}

func (transport publicationRevisionTransport) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	if endpoint == "com.atproto.sync.getLatestCommit" {
		return 200, []byte(fmt.Sprintf(`{"cid":%q,"rev":%q}`, transport.revision.CommitCID.String(), atprototest.RepositoryRevision)), nil
	}
	return transport.base.Do(ctx, method, endpoint, query, body, contentType)
}

func (transport publicationRevisionTransport) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	if endpoint == "com.atproto.sync.getRepo" {
		return 200, io.NopCloser(bytes.NewReader(bytes.Clone(transport.revision.CAR))), nil
	}
	return transport.base.OpenStream(ctx, endpoint, query)
}

type publicationMovingTransport struct {
	base   atproto.Transport
	first  atprototest.SignedRevision
	second atprototest.SignedRevision
	latest int
	stream int
}

func (transport *publicationMovingTransport) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	if endpoint == "com.atproto.sync.getLatestCommit" {
		transport.latest++
		revision := transport.first
		if transport.latest%2 == 0 {
			revision = transport.second
		}
		encoded, err := json.Marshal(map[string]string{"cid": revision.CommitCID.String(), "rev": atprototest.RepositoryRevision})
		return 200, encoded, err
	}
	return transport.base.Do(ctx, method, endpoint, query, body, contentType)
}

func (transport *publicationMovingTransport) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	if endpoint == "com.atproto.sync.getRepo" {
		transport.stream++
		revision := transport.first
		if transport.stream%2 == 0 {
			revision = transport.second
		}
		return 200, io.NopCloser(bytes.NewReader(bytes.Clone(revision.CAR))), nil
	}
	return transport.base.OpenStream(ctx, endpoint, query)
}

func publicationAuditRandom(t *testing.T, size int) []byte {
	t.Helper()
	result := make([]byte, size)
	_, err := rand.Read(result)
	require.NoError(t, err)
	return result
}

func newPublicationTestPDS(t *testing.T) *atprototest.MemoryPDS {
	t.Helper()
	key, err := atprototest.NewSigningKey()
	require.NoError(t, err)
	pds, err := atprototest.NewMemoryPDS(publicationAuditDID, key)
	require.NoError(t, err)
	return pds
}

func publicationCallCount(pds *atprototest.MemoryPDS, endpoint string) int {
	count := 0
	for _, call := range pds.Calls() {
		if call == endpoint {
			count++
		}
	}
	return count
}

func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func publicationCorruptSnapshotRecordSignature(t *testing.T, fixture *publicationFixture) atprototest.SignedRevision {
	t.Helper()
	current := fixture.pds.CurrentRevision()
	records := current.Records
	headRecord, exists := fixture.pds.Record(atproto.VaultHeadNSID, "self")
	require.True(t, exists)
	headValue, err := atproto.DecodeRecord(headRecord.Data)
	require.NoError(t, err)
	head, ok := headValue.(atproto.HeadRecord)
	require.True(t, ok)
	found := false
	for index := range records {
		if records[index].Collection != atproto.VaultSnapshotNSID {
			continue
		}
		decoded, err := atproto.DecodeRecord(records[index].Data)
		require.NoError(t, err)
		snapshot, ok := decoded.(atproto.SnapshotRecord)
		require.True(t, ok)
		if !bytes.Equal(cid.Cid(snapshot.Blob.Ref).Bytes(), head.SnapshotCID) {
			continue
		}
		snapshot.Signature[0] ^= 0x80
		records[index].Data, err = atproto.EncodeRecord(snapshot)
		require.NoError(t, err)
		found = true
		break
	}
	require.True(t, found)
	revision, err := atprototest.BuildSignedRevision(fixture.did, fixture.repoKey, records)
	require.NoError(t, err)
	return revision
}

func publicationCreateSecondRevision(t *testing.T, fixture *publicationFixture) (atprototest.SignedRevision, atprototest.SignedRevision) {
	t.Helper()
	first := fixture.pds.CurrentRevision()
	_, _, err := publicationAuditApplyRecord(context.Background(), fixture.pds, first.CommitCID.String(), "create", "systems.example.moving", "next", []byte(`{"$type":"systems.example.moving","value":"second"}`))
	require.NoError(t, err)
	second := fixture.pds.CurrentRevision()
	return first, second
}

func publicationFindHeadBlob(t *testing.T, fixture *publicationFixture) (string, []byte) {
	t.Helper()
	record, exists := fixture.pds.Record(atproto.VaultHeadNSID, "self")
	require.True(t, exists)
	decoded, err := atproto.DecodeRecord(record.Data)
	require.NoError(t, err)
	head, ok := decoded.(atproto.HeadRecord)
	require.True(t, ok)
	blobCID, err := cid.Cast(head.BlobCID)
	require.NoError(t, err)
	return blobCID.String(), bytes.Clone(head.BlobCID)
}

func publicationCompareTierOne(t *testing.T, fixture *publicationFixture, operation func() error, want error, stage atproto.ReadStage) {
	t.Helper()
	beforeState := fixture.logicalStateDigest()
	beforeApplication := fixture.applicationStateDigest()
	beforeKeys := fixture.keyringDigest()
	beforeHome := fixture.homeTreeDigest()
	err := operation()
	require.ErrorIs(t, err, want)
	var readError *atproto.ReadError
	require.ErrorAs(t, err, &readError)
	assert.Equal(t, stage, readError.Stage)
	assert.Equal(t, beforeState, fixture.logicalStateDigest())
	assert.Equal(t, beforeApplication, fixture.applicationStateDigest())
	assert.Equal(t, beforeKeys, fixture.keyringDigest())
	assert.Equal(t, beforeHome, fixture.homeTreeDigest())
}
