package integration

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
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
	"github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ledgerApplyInput struct {
	Repo       string            `json:"repo"`
	SwapCommit string            `json:"swapCommit"`
	Writes     []json.RawMessage `json:"writes"`
}

type ledgerApplyWrite struct {
	Type       string          `json:"$type"`
	Collection string          `json:"collection"`
	RKey       string          `json:"rkey"`
	Value      json.RawMessage `json:"value"`
}

type ledgerRaceIO struct {
	base    atproto.TransitionIO
	ready   chan<- struct{}
	release <-chan struct{}
}

func (io ledgerRaceIO) ReadCurrent(ctx context.Context) (*atproto.Revision, vault.Predecessor, error) {
	return io.base.ReadCurrent(ctx)
}

func (io ledgerRaceIO) StageCandidate(ctx context.Context, data []byte, expectedPolicy vault.Policy, certificates [][]byte) (json.RawMessage, string, error) {
	return io.base.StageCandidate(ctx, data, expectedPolicy, certificates)
}

func (io ledgerRaceIO) ApplyTransition(ctx context.Context, revision *atproto.Revision, publication atproto.FencedPublication) error {
	io.ready <- struct{}{}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-io.release:
	}
	return io.base.ApplyTransition(ctx, revision, publication)
}

func TestLiveLedgerSharedRootRace(t *testing.T) {
	if os.Getenv("DOTTIE_LIVE_LEDGER") != "1" {
		t.Skip("set DOTTIE_LIVE_LEDGER=1 with explicit disposable-account authorization to run the shared-root enrollment fence experiment")
	}
	handle := os.Getenv("DOTTIE_HANDLE")
	if !allowedPDSHandle(handle) {
		require.True(t, allowedPDSHandle(handle), "DOTTIE_HANDLE is not in the live disposable-identity allowlist")
	}
	provider := pdsProviderName(handle)
	keyring, err := platform.NewKeyring()
	if err != nil {
		require.NoError(t, err, "open Secret Service keyring: %v", err)
	}
	defer keyring.Close()
	clientA, err := atproto.NewClient("https://dottie.lamb.systems/client-metadata.json", keyring)
	if err != nil {
		require.NoError(t, err)
	}
	clientB, err := atproto.NewClient("https://dottie.lamb.systems/client-metadata.json", keyring)
	if err != nil {
		require.NoError(t, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	identityA, err := clientA.Discover(ctx, handle)
	if err != nil {
		require.NoError(t, err, "discover disposable PDS identity: %v", err)
	}
	identityB, err := clientB.Discover(ctx, handle)
	if err != nil {
		require.NoError(t, err, "discover second PDS client identity: %v", err)
	}
	if identityA.DID != identityB.DID || identityA.PDS != identityB.PDS {
		require.Equal(t, identityA.DID, identityB.DID, "separate ledger clients must bind to the same disposable DID")
		require.Equal(t, identityA.PDS, identityB.PDS, "separate ledger clients must bind to the same PDS")
	}
	sessionA, err := clientA.LoadSession(ctx, identityA.DID)
	if err != nil {
		require.NoError(t, err, "load first scoped OAuth session")
	}
	sessionB, err := clientB.LoadSession(ctx, identityB.DID)
	if err != nil {
		require.NoError(t, err, "load second scoped OAuth session")
	}
	for _, collection := range []string{atproto.VaultSnapshotNSID, atproto.VaultHeadNSID, atproto.VaultControlNSID, atproto.VaultPolicyNSID, atproto.VaultCertificateNSID} {
		if !hasPDScope(sessionA.Scopes, "repo:"+collection) {
			require.True(t, hasPDScope(sessionA.Scopes, "repo:"+collection), "first session is missing required repository scope")
		}
		if !hasPDScope(sessionB.Scopes, "repo:"+collection) {
			require.True(t, hasPDScope(sessionB.Scopes, "repo:"+collection), "second session is missing required repository scope")
		}
	}
	for _, session := range []*atproto.Session{sessionA, sessionB} {
		if !hasPDScope(session.Scopes, "blob:application/octet-stream") {
			require.True(t, hasPDScope(session.Scopes, "blob:application/octet-stream"), "session is missing required blob scope")
		}
	}
	authA, err := atproto.NewAuthMethod(clientA, identityA, handle, sessionA)
	if err != nil {
		require.NoError(t, err)
	}
	authB, err := atproto.NewAuthMethod(clientB, identityB, handle, sessionB)
	if err != nil {
		require.NoError(t, err)
	}
	apiA, err := newPDSAPIClient(identityA.PDS, authA, nil)
	if err != nil {
		require.NoError(t, err)
	}
	apiB, err := newPDSAPIClient(identityB.PDS, authB, nil)
	if err != nil {
		require.NoError(t, err)
	}
	anonymousAPI, err := newPDSAPIClient(identityA.PDS, nil, nil)
	if err != nil {
		require.NoError(t, err)
	}
	blobUploadLimit, limitKnown, describeOK := describePDS(t, ctx, provider, identityA.PDS, anonymousAPI)
	require.True(t, describeOK && limitKnown, "live ledger requires a discovered PDS blobUploadLimit")
	transportA := atproto.NewATClientTransport(apiA)
	transportB := atproto.NewATClientTransport(apiB)
	readerA := atproto.RevisionReader{Transport: transportA, Budgets: atproto.DefaultBudgets(), DIDDocumentID: identityA.DIDDocumentID, VerificationMethods: identityA.VerificationMethods}
	readerB := atproto.RevisionReader{Transport: transportB, Budgets: atproto.DefaultBudgets(), DIDDocumentID: identityB.DIDDocumentID, VerificationMethods: identityB.VerificationMethods}
	initial, err := readerA.Read(ctx, identityA.DID)
	if err != nil {
		require.NoError(t, err, "read initial verified ledger revision: %v", err)
	}
	for key := range initial.Records() {
		if strings.HasPrefix(key.Collection, "systems.lamb.dottie.") {
			require.False(t, strings.HasPrefix(key.Collection, "systems.lamb.dottie."), "refusing to alter an account with existing vault records")
		}
	}

	kit := make([]byte, 32)
	_, err = rand.Read(kit)
	require.NoError(t, err)
	var vaultNameBytes [16]byte
	_, err = rand.Read(vaultNameBytes[:])
	require.NoError(t, err)
	vaultName := "ledger-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(vaultNameBytes[:]))
	rootSigning, rootRecipient, err := vault.GenerateDeviceKeys()
	require.NoError(t, err)
	root := vault.DeviceMaterial{DeviceID: "ledger-root", KeyID: bytes.Clone(vaultNameBytes[:]), Signing: rootSigning, Recipient: rootRecipient}
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
	body, err := ledgerApplyBody(identityA.DID, initial.CommitCID(), bootstrapWrites)
	require.NoError(t, err)
	status, response, err := transportA.Do(ctx, http.MethodPost, "com.atproto.repo.applyWrites", nil, body, "application/json")
	if err != nil || status < 200 || status >= 300 {
		require.NoError(t, err, "bootstrap temporary ledger records: status=%d", status)
		require.GreaterOrEqual(t, status, 200, "bootstrap temporary ledger records failed")
		require.Less(t, status, 300, "bootstrap temporary ledger records failed: %s", redactBodyPrefix(response))
	}

	attempts := make([]vault.Transition, 2)
	newDeviceIDs := make([]string, 2)
	for index := range attempts {
		device, transition, err := ledgerPrepareEnrollment(bootstrap, root, byte(index+1))
		if err != nil {
			require.NoError(t, err, "prepare local enrollment bundle")
		}
		attempts[index] = transition
		newDeviceIDs[index] = device.DeviceID
		for _, key := range ledgerTransitionTargets(transition, device) {
			if !trackedSet[key] {
				trackedSet[key] = true
				tracked = append(tracked, key)
			}
		}
	}
	ioA := atproto.ATProtoTransitionIO{Reader: readerA, Transport: transportA, BlobUploadLimit: blobUploadLimit, DID: identityA.DID, TrustAnchor: bootstrap.Anchor}
	ioB := atproto.ATProtoTransitionIO{Reader: readerB, Transport: transportB, BlobUploadLimit: blobUploadLimit, DID: identityB.DID, TrustAnchor: bootstrap.Anchor}
	stateRoot := t.TempDir()
	stateStore, err := state.Open(platform.Paths{Home: filepath.Join(stateRoot, "home"), StateHome: filepath.Join(stateRoot, "state"), CacheHome: filepath.Join(stateRoot, "cache")})
	if err != nil {
		require.NoError(t, err)
	}
	defer stateStore.Close()
	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	results := make(chan ledgerAttemptResult, 2)
	clients := []struct {
		io     atproto.TransitionIO
		bundle vault.Transition
		key    []byte
	}{
		{io: ledgerRaceIO{base: ioA, ready: ready, release: release}, bundle: attempts[0], key: root.Signing},
		{io: ledgerRaceIO{base: ioB, ready: ready, release: release}, bundle: attempts[1], key: root.Signing},
	}
	for _, client := range clients {
		go func(current struct {
			io     atproto.TransitionIO
			bundle vault.Transition
			key    []byte
		}) {
			result, commitErr := atproto.CommitTransition(ctx, current.io, stateStore, current.bundle, current.key, time.Now())
			results <- ledgerAttemptResult{result: result, err: commitErr}
		}(client)
	}
	for range 2 {
		select {
		case <-ready:
		case <-ctx.Done():
			require.NoError(t, ctx.Err(), "both independent clients must reach the fenced commit")
		}
	}
	close(release)
	outcomes := []ledgerAttemptResult{<-results, <-results}
	winner := -1
	loser := -1
	for index, outcome := range outcomes {
		if outcome.result.Outcome == atproto.TransitionOutcome(atproto.TransitionOutcomeCommitted) && outcome.err == nil {
			if winner != -1 {
				assert.Fail(t, "both concurrent enrollments committed")
			}
			winner = index
			continue
		}
		if errors.Is(outcome.err, atproto.ErrFenceLost) && !errors.Is(outcome.err, atproto.ErrCandidateMayBeDisclosed) {
			loser = index
			continue
		}
		assert.Fail(t, "race result was neither a verified commit nor a clean lost fence")
	}
	require.NotEqual(t, -1, winner, "one shared-root enrollment must commit")
	require.NotEqual(t, -1, loser, "the losing enrollment must report InvalidSwap")
	latest, err := readerA.Read(ctx, identityA.DID)
	if err != nil {
		require.NoError(t, err, "read final verified revision: %v", err)
	}
	membership := latest.Membership()
	assert.Equal(t, outcomes[winner].result.RecordCID, membership[outcomes[winner].result.Marker], "winner marker must be present at its expected CID")
	assert.NotEqual(t, outcomes[loser].result.RecordCID, membership[outcomes[loser].result.Marker], "loser marker must not be referenced")
	referenced, err := revisionReferencesBlob(latest, outcomes[loser].result.BlobCID)
	if err != nil {
		require.NoError(t, err, "inspect loser blob references: %v", err)
	}
	assert.False(t, referenced, "losing candidate blob must not be referenced")
	policyRecord, ok := latest.Records()[atproto.RecordKey{Collection: atproto.VaultPolicyNSID, RKey: "self"}]
	require.True(t, ok, "successor policy must be present")
	decoded, err := atproto.DecodeRecord(policyRecord.Data)
	require.NoError(t, err)
	policy, ok := decoded.(atproto.PolicyRecord)
	require.True(t, ok, "successor policy record type")
	assert.Len(t, policy.Roles, 2, "successor policy must add exactly one device")
	assert.Equal(t, newDeviceIDs[winner], ledgerAddedDeviceID(policy, newDeviceIDs), "the successor policy must list the winning new device")
	for index, outcome := range outcomes {
		fmt.Printf("LEDGER_RACE provider=%q experiment=%q outcome=%q marker=%q marker_record_cid=%q candidate_blob_cid=%q\n", provider, "experiment-ledger-shared-root-race", outcome.result.Outcome, outcome.result.Marker.RKey, outcome.result.RecordCID, outcome.result.BlobCID)
		if index == loser {
			assert.ErrorIs(t, outcome.err, atproto.ErrFenceLost, "loser must report the structured fence outcome")
		}
	}
}

type ledgerAttemptResult struct {
	result atproto.TransitionCommitResult
	err    error
}

func ledgerBootstrapWrites(bootstrap vault.BootstrapResult) ([]atproto.RecordWrite, error) {
	policy, err := vault.DecodePolicy(bootstrap.Policy)
	if err != nil {
		return nil, err
	}
	control, err := vault.DecodeControl(bootstrap.Control)
	if err != nil {
		return nil, err
	}
	certificate, err := vault.DecodeCertificate(bootstrap.Certificate)
	if err != nil {
		return nil, err
	}
	policyRecord := atproto.PolicyRecord{
		SchemaVersion: 1, Vault: append([]byte(nil), policy.Vault[:]...), EpochSeq: policy.EpochSeq,
		PolicyRetentionFloor: policy.PolicyRetentionFloor, RetainedRecoveryPoints: policy.RetainedRecoveryPoints,
		MaxPublications: policy.MaxPublications, MaxEpochAge: policy.MaxEpochAge,
		RecoveryAnchor: append([]byte(nil), policy.RecoveryAnchor[:]...), PrevPolicyDigest: append([]byte(nil), policy.PrevPolicyDigest[:]...),
		SignerDeviceID: policy.Signer.DeviceID, SignerKeyID: append([]byte(nil), policy.Signer.KeyID...), Signature: append([]byte(nil), policy.Signature[:]...),
	}
	for _, role := range policy.Roles {
		policyRecord.Roles = append(policyRecord.Roles, atproto.PolicyRoleRecord{DeviceID: role.DeviceID, Role: uint8(role.Role)})
	}
	for _, recipient := range policy.Recipients {
		policyRecord.Recipients = append(policyRecord.Recipients, atproto.PolicyRecipientRecord{DeviceID: recipient.DeviceID, KeyID: append([]byte(nil), recipient.KeyID...), PublicKey: append([]byte(nil), recipient.PublicKey[:]...)})
	}
	revoked := make([]atproto.RevokedDeviceRecord, len(control.Revoked))
	for index, value := range control.Revoked {
		revoked[index] = atproto.RevokedDeviceRecord{DeviceID: value.DeviceID, CertEpoch: value.CertEpoch}
	}
	controlRecord := atproto.ControlRecord{
		SchemaVersion: 1, Vault: append([]byte(nil), control.Vault[:]...), EpochSeq: control.EpochSeq,
		PolicyDigest: append([]byte(nil), control.PolicyDigest[:]...), HeadSnapshotCID: append([]byte(nil), control.HeadSnapshotCID...),
		Revoked: revoked, PrevControlCID: append([]byte(nil), control.PrevControlCID...),
		SignerDeviceID: control.Signer.DeviceID, SignerKeyID: append([]byte(nil), control.Signer.KeyID...), Signature: append([]byte(nil), control.Signature[:]...),
	}
	certificateRecord := atproto.CertificateRecord{
		SchemaVersion: 1, Vault: append([]byte(nil), certificate.Vault[:]...), DeviceID: certificate.DeviceID,
		KeyID: append([]byte(nil), certificate.KeyID...), SigningPublicKey: append([]byte(nil), certificate.SigningPublicKey[:]...),
		EncryptionPublicKey: append([]byte(nil), certificate.EncryptionPublicKey[:]...), Role: uint8(certificate.Role), CertEpoch: certificate.CertEpoch,
		Issuer: certificate.Issuer, RevocationRef: append([]byte(nil), certificate.RevocationRef...),
		SignerDeviceID: certificate.Signer.DeviceID, SignerKeyID: append([]byte(nil), certificate.Signer.KeyID...), Signature: append([]byte(nil), certificate.Signature[:]...),
	}
	policyJSON, err := ledgerRecordJSON(atproto.VaultPolicyNSID, policyRecord)
	if err != nil {
		return nil, err
	}
	controlJSON, err := ledgerRecordJSON(atproto.VaultControlNSID, controlRecord)
	if err != nil {
		return nil, err
	}
	certificateJSON, err := ledgerRecordJSON(atproto.VaultCertificateNSID, certificateRecord)
	if err != nil {
		return nil, err
	}
	return []atproto.RecordWrite{
		{Action: atproto.RecordCreate, Collection: atproto.VaultPolicyNSID, RKey: "self", Record: policyJSON},
		{Action: atproto.RecordCreate, Collection: atproto.VaultControlNSID, RKey: "self", Record: controlJSON},
		{Action: atproto.RecordCreate, Collection: atproto.VaultCertificateNSID, RKey: ledgerCertificateRKey(certificate.DeviceID, certificate.KeyID), Record: certificateJSON},
	}, nil
}

func ledgerRecordJSON(typeID string, record any) (json.RawMessage, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return nil, err
	}
	typeBytes, err := json.Marshal(typeID)
	if err != nil {
		return nil, err
	}
	fields["$type"] = typeBytes
	return json.Marshal(fields)
}

func ledgerApplyBody(did, commit string, writes []atproto.RecordWrite) ([]byte, error) {
	input := ledgerApplyInput{Repo: did, SwapCommit: commit, Writes: make([]json.RawMessage, 0, len(writes))}
	for _, write := range writes {
		typeName := "com.atproto.repo.applyWrites#create"
		if write.Action == atproto.RecordUpdate {
			typeName = "com.atproto.repo.applyWrites#update"
		}
		encoded, err := json.Marshal(ledgerApplyWrite{Type: typeName, Collection: write.Collection, RKey: write.RKey, Value: write.Record})
		if err != nil {
			return nil, err
		}
		input.Writes = append(input.Writes, encoded)
	}
	return json.Marshal(input)
}

func ledgerPrepareEnrollment(bootstrap vault.BootstrapResult, root vault.DeviceMaterial, id byte) (vault.DeviceMaterial, vault.Transition, error) {
	newSigning, newRecipient, err := vault.GenerateDeviceKeys()
	if err != nil {
		return vault.DeviceMaterial{}, vault.Transition{}, err
	}
	newDevice := vault.DeviceMaterial{DeviceID: fmt.Sprintf("ledger-publisher-%d", id), KeyID: []byte(fmt.Sprintf("ledger-key-%d", id)), Signing: newSigning, Recipient: newRecipient}
	policyDigest, err := vault.ComputePolicyDigest(bootstrap.Policy)
	if err != nil {
		return vault.DeviceMaterial{}, vault.Transition{}, err
	}
	controlCID := cid.NewCidV1(cid.Raw, mustLedgerMultihash(bootstrap.Control)).Bytes()
	predecessor := vault.Predecessor{ControlCID: controlCID, PolicyDigest: policyDigest, EpochSeq: 0, Control: bootstrap.Control, Policy: bootstrap.Policy, Certificates: [][]byte{bootstrap.Certificate}, TrustAnchor: bootstrap.Anchor}
	rootWrap, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return vault.DeviceMaterial{}, vault.Transition{}, err
	}
	newWrap, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return vault.DeviceMaterial{}, vault.Transition{}, err
	}
	contentKey := make([]byte, 32)
	if _, err := rand.Read(contentKey); err != nil {
		return vault.DeviceMaterial{}, vault.Transition{}, err
	}
	var publicationID [16]byte
	if _, err := rand.Read(publicationID[:]); err != nil {
		return vault.DeviceMaterial{}, vault.Transition{}, err
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return vault.DeviceMaterial{}, vault.Transition{}, err
	}
	wraps := []vault.RecipientWrapInput{
		{KeyID: append([]byte(nil), root.KeyID...), EphemeralPrivate: [32]byte(rootWrap.Bytes())},
		{KeyID: append([]byte(nil), newDevice.KeyID...), EphemeralPrivate: [32]byte(newWrap.Bytes())},
	}
	transition, err := vault.PrepareTransition(predecessor, vault.TransitionIntent{
		Kind: vault.TransitionEnroll, Vault: bootstrap.Vault, Signer: root, NewDevice: &newDevice,
		RequestedRole: vault.RolePublisher, ContentKey: contentKey, Recipients: [][]byte{bootstrap.Certificate}, Wraps: wraps,
		Plaintext: []byte("synthetic disposable ledger payload"), PublicationID: publicationID, Nonce: nonce,
	})
	return newDevice, transition, err
}

func ledgerTransitionTargets(transition vault.Transition, device vault.DeviceMaterial) []fenceCreatedRecord {
	envelope, _ := vault.DecodeEnvelope(transition.Snapshot)
	return []fenceCreatedRecord{
		{collection: atproto.VaultSnapshotNSID, rkey: "enroll-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(envelope.PublicationID[:]))},
		{collection: atproto.VaultHeadNSID, rkey: "self"},
		{collection: atproto.VaultControlNSID, rkey: "self"},
		{collection: atproto.VaultPolicyNSID, rkey: "self"},
		{collection: atproto.VaultCertificateNSID, rkey: ledgerCertificateRKey(device.DeviceID, device.KeyID)},
	}
}

func ledgerCertificateRKey(deviceID string, keyID []byte) string {
	digest := sha256.Sum256(append([]byte(deviceID+"\x00"), keyID...))
	return hex.EncodeToString(digest[:])
}

func mustLedgerMultihash(data []byte) []byte {
	hash, _ := multihash.Sum(data, multihash.SHA2_256, -1)
	return hash
}

func ledgerAddedDeviceID(policy atproto.PolicyRecord, candidates []string) string {
	for _, candidate := range candidates {
		for _, role := range policy.Roles {
			if role.DeviceID == candidate {
				return candidate
			}
		}
	}
	return ""
}
