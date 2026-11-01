package integration

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type publicationRaceIO struct {
	base    atproto.PublicationIO
	ready   chan<- string
	release <-chan struct{}
}

func (io publicationRaceIO) ReadCurrent(ctx context.Context) (*atproto.Revision, vault.Predecessor, error) {
	return io.base.ReadCurrent(ctx)
}

func (io publicationRaceIO) StageCandidate(ctx context.Context, data []byte) (json.RawMessage, string, error) {
	return io.base.StageCandidate(ctx, data)
}

func (io publicationRaceIO) ApplyPublication(ctx context.Context, revision *atproto.Revision, publication atproto.FencedSnapshotPublication) error {
	io.ready <- "publish"
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-io.release:
	}
	return io.base.ApplyPublication(ctx, revision, publication)
}

type revocationRaceIO struct {
	base    atproto.TransitionIO
	ready   chan<- string
	release <-chan struct{}
}

func (io revocationRaceIO) ReadCurrent(ctx context.Context) (*atproto.Revision, vault.Predecessor, error) {
	return io.base.ReadCurrent(ctx)
}

func (io revocationRaceIO) StageCandidate(ctx context.Context, data []byte) (json.RawMessage, string, error) {
	return io.base.StageCandidate(ctx, data)
}

func (io revocationRaceIO) ApplyTransition(ctx context.Context, revision *atproto.Revision, publication atproto.FencedPublication) error {
	io.ready <- "revoke"
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-io.release:
	}
	return io.base.ApplyTransition(ctx, revision, publication)
}

type publicationRaceResult struct {
	writer      string
	publication atproto.PublicationCommitResult
	transition  atproto.TransitionCommitResult
	err         error
}

func TestLivePublicationVersusRootRevocationSharedDeviceKeys(t *testing.T) {
	if os.Getenv("DOTTIE_LIVE_PUBLICATION") != "1" {
		t.Skip("set DOTTIE_LIVE_PUBLICATION=1 with explicit disposable-account authorization to run the publication-versus-revocation race")
	}
	handle := os.Getenv("DOTTIE_HANDLE")
	if !allowedPDSHandle(handle) {
		require.True(t, allowedPDSHandle(handle), "DOTTIE_HANDLE is not in the live disposable-identity allowlist")
	}
	provider := pdsProviderName(handle)
	runID := hex.EncodeToString(publicationHarnessRandom(t, 16))
	keyring, err := platform.NewKeyring()
	if err != nil {
		require.NoError(t, err, "open Secret Service keyring: %v", err)
	}
	defer keyring.Close()
	clientA, err := atproto.NewClient("https://dottie.lamb.systems/client-metadata.json", keyring)
	require.NoError(t, err)
	clientB, err := atproto.NewClient("https://dottie.lamb.systems/client-metadata.json", keyring)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	identityA, err := clientA.Discover(ctx, handle)
	require.NoError(t, err, "discover disposable PDS identity: %v", err)
	identityB, err := clientB.Discover(ctx, handle)
	require.NoError(t, err, "discover second PDS client identity: %v", err)
	require.Equal(t, identityA.DID, identityB.DID)
	require.Equal(t, identityA.PDS, identityB.PDS)
	sessionA, err := clientA.LoadSession(ctx, identityA.DID)
	require.NoError(t, err)
	sessionB, err := clientB.LoadSession(ctx, identityB.DID)
	require.NoError(t, err)
	for _, session := range []*atproto.Session{sessionA, sessionB} {
		for _, collection := range []string{atproto.VaultSnapshotNSID, atproto.VaultHeadNSID, atproto.VaultControlNSID, atproto.VaultPolicyNSID, atproto.VaultCertificateNSID} {
			require.True(t, hasPDScope(session.Scopes, "repo:"+collection), "session missing repository scope for %s", collection)
		}
		require.True(t, hasPDScope(session.Scopes, "blob:application/octet-stream"), "session missing snapshot blob scope")
	}
	authA, err := atproto.NewAuthMethod(clientA, identityA, handle, sessionA)
	require.NoError(t, err)
	authB, err := atproto.NewAuthMethod(clientB, identityB, handle, sessionB)
	require.NoError(t, err)
	apiA, err := newPDSAPIClient(identityA.PDS, authA, nil)
	require.NoError(t, err)
	apiB, err := newPDSAPIClient(identityB.PDS, authB, nil)
	require.NoError(t, err)
	transportA := atproto.NewATClientTransport(apiA)
	transportB := atproto.NewATClientTransport(apiB)
	readerA := atproto.RevisionReader{Transport: transportA, Budgets: atproto.DefaultBudgets(), DIDDocumentID: identityA.DIDDocumentID, VerificationMethods: identityA.VerificationMethods}
	readerB := atproto.RevisionReader{Transport: transportB, Budgets: atproto.DefaultBudgets(), DIDDocumentID: identityB.DIDDocumentID, VerificationMethods: identityB.VerificationMethods}
	initial, err := readerA.Read(ctx, identityA.DID)
	require.NoError(t, err, "read initial verified repository revision: %v", err)
	for key := range initial.Records() {
		require.False(t, strings.HasPrefix(key.Collection, "systems.lamb.dottie."), "refusing to alter an account with existing vault records")
	}

	kit := publicationHarnessRandom(t, 32)
	vaultName := "publication-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(publicationHarnessRandom(t, 16)))
	rootSigning, rootRecipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	root := vault.DeviceMaterial{DeviceID: "publication-root", KeyID: publicationHarnessRandom(t, 16), Signing: rootSigning, Recipient: rootRecipient}
	bootstrap, err := vault.Bootstrap(kit, vaultName, root)
	require.NoError(t, err)
	bootstrapWrites, err := ledgerBootstrapWrites(bootstrap)
	require.NoError(t, err)
	tracked := []fenceCreatedRecord{
		{collection: atproto.VaultPolicyNSID, rkey: "self"},
		{collection: atproto.VaultControlNSID, rkey: "self"},
		{collection: atproto.VaultCertificateNSID, rkey: ledgerCertificateRKey(root.DeviceID, root.KeyID)},
	}
	trackedSet := make(map[fenceCreatedRecord]bool, len(tracked))
	for _, record := range tracked {
		trackedSet[record] = true
	}
	defer func() {
		cleanupFenceRecords(t, provider, identityA, transportA, readerA, tracked)
	}()
	bootstrapBody, err := ledgerApplyBody(identityA.DID, initial.CommitCID(), bootstrapWrites)
	require.NoError(t, err)
	status, response, err := transportA.Do(ctx, http.MethodPost, "com.atproto.repo.applyWrites", nil, bootstrapBody, "application/json")
	if err != nil || status < 200 || status >= 300 {
		require.NoError(t, err, "create temporary bootstrap records: status=%d", status)
		require.GreaterOrEqual(t, status, 200)
		require.Less(t, status, 300, "bootstrap response: %s", redactBodyPrefix(response))
	}

	stateRoot := t.TempDir()
	store, err := state.Open(platform.Paths{Home: filepath.Join(stateRoot, "home"), StateHome: filepath.Join(stateRoot, "state"), CacheHome: filepath.Join(stateRoot, "cache")})
	require.NoError(t, err)
	defer store.Close()
	transitionIO := atproto.ATProtoTransitionIO{Reader: readerA, Transport: transportA, DID: identityA.DID, TrustAnchor: bootstrap.Anchor}
	publisher, enrollment, err := ledgerPrepareEnrollment(bootstrap, root, 1)
	require.NoError(t, err)
	for _, key := range ledgerTransitionTargets(enrollment, publisher) {
		trackPublicationHarnessRecord(trackedSet, &tracked, key)
	}
	enrollmentResult, err := atproto.CommitTransition(ctx, transitionIO, store, enrollment, root.Signing, time.Now())
	require.NoError(t, err)
	assert.Equal(t, atproto.TransitionOutcome(atproto.TransitionOutcomeCommitted), enrollmentResult.Outcome)

	publicationIOA := atproto.ATProtoPublicationIO{Reader: readerA, Transport: transportA, DID: identityA.DID, TrustAnchor: bootstrap.Anchor}
	_, predecessor, err := publicationIOA.ReadCurrent(ctx)
	require.NoError(t, err)
	publisherCertificate := findPublicationHarnessCertificate(t, predecessor.Certificates, publisher.DeviceID)
	publicationID := [16]byte(publicationHarnessRandom(t, 16))
	publicationIntent := vault.PublicationIntent{
		Vault: bootstrap.Vault, Signer: root, ContentKey: publicationHarnessRandom(t, 32),
		Wraps: publicationHarnessWraps(t, predecessor.Certificates), Plaintext: []byte("synthetic disposable snapshot payload"),
		PublicationID: publicationID, Nonce: [24]byte(publicationHarnessRandom(t, 24)),
	}
	publication, err := vault.PreparePublication(predecessor, publicationIntent)
	require.NoError(t, err)
	revocationID := [16]byte(publicationHarnessRandom(t, 16))
	revocation := vault.Transition{}
	{
		activeRecipients := make([][]byte, 0, len(predecessor.Certificates)-1)
		for _, encoded := range predecessor.Certificates {
			certificate, decodeErr := vault.DecodeCertificate(encoded)
			require.NoError(t, decodeErr)
			if certificate.DeviceID != publisher.DeviceID {
				activeRecipients = append(activeRecipients, bytes.Clone(encoded))
			}
		}
		contentKey := publicationHarnessRandom(t, 32)
		wraps := publicationHarnessWraps(t, activeRecipients)
		revocation, err = vault.PrepareTransition(predecessor, vault.TransitionIntent{
			Kind: vault.TransitionRevoke, Vault: bootstrap.Vault, Signer: root, RevokeDeviceID: publisher.DeviceID,
			ContentKey: contentKey, Recipients: activeRecipients, Wraps: wraps,
			Plaintext: []byte("synthetic disposable snapshot payload"), PublicationID: revocationID,
			Nonce: [24]byte(publicationHarnessRandom(t, 24)),
		})
		require.NoError(t, err)
	}

	publicationEnvelope, err := vault.DecodeEnvelope(publication.Snapshot)
	require.NoError(t, err)
	revocationEnvelope, err := vault.DecodeEnvelope(revocation.Snapshot)
	require.NoError(t, err)
	trackPublicationHarnessRecord(trackedSet, &tracked, fenceCreatedRecord{collection: atproto.VaultSnapshotNSID, rkey: publicationHarnessMarker("publish-", publicationEnvelope.PublicationID)})
	trackPublicationHarnessRecord(trackedSet, &tracked, fenceCreatedRecord{collection: atproto.VaultSnapshotNSID, rkey: publicationHarnessMarker("revoke-", revocationEnvelope.PublicationID)})
	for _, key := range []fenceCreatedRecord{
		{collection: atproto.VaultHeadNSID, rkey: "self"},
		{collection: atproto.VaultControlNSID, rkey: "self"},
		{collection: atproto.VaultPolicyNSID, rkey: "self"},
	} {
		trackPublicationHarnessRecord(trackedSet, &tracked, key)
	}

	ready := make(chan string, 2)
	release := make(chan struct{})
	results := make(chan publicationRaceResult, 2)
	publicationIO := publicationRaceIO{base: publicationIOA, ready: ready, release: release}
	transitionIOB := atproto.ATProtoTransitionIO{Reader: readerB, Transport: transportB, DID: identityB.DID, TrustAnchor: bootstrap.Anchor}
	revocationIO := revocationRaceIO{base: transitionIOB, ready: ready, release: release}
	go func() {
		result, commitErr := atproto.CommitPublication(ctx, publicationIO, store, publication, root.Signing, time.Now())
		results <- publicationRaceResult{writer: "ordinary-publication", publication: result, err: commitErr}
	}()
	go func() {
		result, commitErr := atproto.CommitTransition(ctx, revocationIO, store, revocation, root.Signing, time.Now())
		results <- publicationRaceResult{writer: "root-revocation", transition: result, err: commitErr}
	}()
	writers := make(map[string]bool)
	for range 2 {
		select {
		case writer := <-ready:
			writers[writer] = true
		case <-ctx.Done():
			require.NoError(t, ctx.Err(), "both independent clients must reach the fenced race")
		}
	}
	require.True(t, writers["publish"])
	require.True(t, writers["revoke"])
	close(release)
	outcomes := []publicationRaceResult{<-results, <-results}
	winner := -1
	loser := -1
	for index, outcome := range outcomes {
		committed := outcome.err == nil && (outcome.writer == "ordinary-publication" && outcome.publication.Outcome == atproto.TransitionOutcome(atproto.TransitionOutcomeCommitted) || outcome.writer == "root-revocation" && outcome.transition.Outcome == atproto.TransitionOutcome(atproto.TransitionOutcomeCommitted))
		lostFence := errors.Is(outcome.err, atproto.ErrFenceLost) && !errors.Is(outcome.err, atproto.ErrCandidateMayBeDisclosed)
		if committed {
			if winner != -1 {
				assert.Fail(t, "both publication and revocation committed")
			}
			winner = index
		} else if lostFence {
			loser = index
		} else {
			assert.Fail(t, "race result was neither a verified commit nor a clean lost fence")
		}
	}
	require.NotEqual(t, -1, winner)
	require.NotEqual(t, -1, loser)
	latest, finalPredecessor, err := transitionIO.ReadCurrent(ctx)
	require.NoError(t, err)
	winnerResult := outcomes[winner]
	loserResult := outcomes[loser]
	winnerMarker, winnerRecordCID, winnerBlobCID := publicationRaceIdentifiers(winnerResult)
	loserMarker, loserRecordCID, loserBlobCID := publicationRaceIdentifiers(loserResult)
	membership := latest.Membership()
	assert.Equal(t, winnerRecordCID, membership[winnerMarker])
	assert.NotEqual(t, loserRecordCID, membership[loserMarker])
	loserReferenced, err := revisionReferencesBlob(latest, loserBlobCID)
	require.NoError(t, err)
	assert.False(t, loserReferenced)
	finalPolicy, err := vault.DecodePolicy(finalPredecessor.Policy)
	require.NoError(t, err)
	finalControl, err := vault.DecodeControl(finalPredecessor.Control)
	require.NoError(t, err)
	finalHead, err := vault.DecodeHead(finalPredecessor.Head)
	require.NoError(t, err)
	if winnerResult.writer == "ordinary-publication" {
		assert.Equal(t, predecessor.EpochSeq, finalPolicy.EpochSeq)
		assert.Equal(t, predecessor.PolicyDigest, finalPredecessor.PolicyDigest)
		assert.Equal(t, uint64(1), finalHead.PublicationCount)
		assert.Equal(t, predecessor.ControlCID, finalPredecessor.ControlCID)
	} else {
		assert.Equal(t, predecessor.EpochSeq+1, finalPolicy.EpochSeq)
		assert.Equal(t, uint64(0), finalHead.PublicationCount)
		assert.Contains(t, finalControl.Revoked, vault.RevokedDevice{DeviceID: publisherCertificate.DeviceID, CertEpoch: publisherCertificate.CertEpoch})
		assert.NotContains(t, policyRecipientDeviceIDs(finalPolicy), publisherCertificate.DeviceID)
		assert.Equal(t, finalHead.SnapshotCID, finalControl.HeadSnapshotCID)
	}
	controlHeadCID, err := cid.Cast(finalControl.HeadSnapshotCID)
	require.NoError(t, err)
	liveHeadCID, err := cid.Cast(finalHead.SnapshotCID)
	require.NoError(t, err)
	fmt.Printf("PUBLICATION_RACE provider=%q run_id=%q vault_id=%q winner=%q loser=%q winner_marker=%q winner_record_cid=%q winner_blob_cid=%q loser_marker=%q loser_record_cid=%q loser_blob_cid=%q loser_blob_referenced=%t control_head_snapshot_cid=%q live_head_snapshot_cid=%q\n",
		provider, runID, hex.EncodeToString(bootstrap.Vault[:]), winnerResult.writer, loserResult.writer,
		winnerMarker.RKey, winnerRecordCID, winnerBlobCID, loserMarker.RKey, loserRecordCID, loserBlobCID, loserReferenced,
		controlHeadCID.String(), liveHeadCID.String())
	for _, outcome := range outcomes {
		if outcome.writer == "ordinary-publication" && errors.Is(outcome.err, atproto.ErrFenceLost) {
			assert.NotErrorIs(t, outcome.err, atproto.ErrCandidateMayBeDisclosed)
		}
		if outcome.writer == "root-revocation" && errors.Is(outcome.err, atproto.ErrFenceLost) {
			assert.NotErrorIs(t, outcome.err, atproto.ErrCandidateMayBeDisclosed)
		}
	}
}

func publicationRaceIdentifiers(result publicationRaceResult) (atproto.RecordKey, string, string) {
	if result.writer == "ordinary-publication" {
		return result.publication.Marker, result.publication.RecordCID, result.publication.BlobCID
	}
	return result.transition.Marker, result.transition.RecordCID, result.transition.BlobCID
}

func publicationHarnessRandom(t *testing.T, size int) []byte {
	t.Helper()
	result := make([]byte, size)
	_, err := rand.Read(result)
	require.NoError(t, err)
	return result
}

func publicationHarnessWraps(t *testing.T, certificates [][]byte) []vault.RecipientWrapInput {
	t.Helper()
	wraps := make([]vault.RecipientWrapInput, 0, len(certificates))
	for _, encoded := range certificates {
		certificate, err := vault.DecodeCertificate(encoded)
		require.NoError(t, err)
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)
		var privateBytes [32]byte
		copy(privateBytes[:], private.Bytes())
		var nonce [24]byte
		_, err = rand.Read(nonce[:])
		require.NoError(t, err)
		wraps = append(wraps, vault.RecipientWrapInput{KeyID: bytes.Clone(certificate.KeyID), EphemeralPrivate: privateBytes, WrapNonce: nonce})
	}
	return wraps
}

func findPublicationHarnessCertificate(t *testing.T, certificates [][]byte, deviceID string) vault.Certificate {
	t.Helper()
	for _, encoded := range certificates {
		certificate, err := vault.DecodeCertificate(encoded)
		require.NoError(t, err)
		if certificate.DeviceID == deviceID {
			return certificate
		}
	}
	require.Fail(t, "active certificate not found")
	return vault.Certificate{}
}

func trackPublicationHarnessRecord(seen map[fenceCreatedRecord]bool, tracked *[]fenceCreatedRecord, record fenceCreatedRecord) {
	if seen[record] {
		return
	}
	seen[record] = true
	*tracked = append(*tracked, record)
}

func publicationHarnessMarker(prefix string, publicationID [16]byte) string {
	return prefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(publicationID[:]))
}

func policyRecipientDeviceIDs(policy vault.Policy) []string {
	devices := make([]string, len(policy.Recipients))
	for index, recipient := range policy.Recipients {
		devices[index] = recipient.DeviceID
	}
	return devices
}
