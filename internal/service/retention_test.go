package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoordinatorRetentionRefusesCheckpointControlCIDMismatch(t *testing.T) {
	fixture := retentionPruneFixture(t, nil)
	ctx := context.Background()
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	read, err := fixture.coordinator.Pull(ctx, selection)
	require.NoError(t, err)
	trust, err := fixture.coordinator.deps.Trust.Resolve(ctx, selection)
	require.NoError(t, err)
	before, err := fixture.store.RetentionDeclaration(ctx, selection.Vault, selection.DeviceID)
	require.NoError(t, err)

	checkpoint := trust.Checkpoint
	trust.Checkpoint.ControlCID = []byte("different-control-cid")
	assert.Equal(t, checkpoint.Epoch, trust.Checkpoint.Epoch)
	assert.Equal(t, checkpoint.SnapshotCID, trust.Checkpoint.SnapshotCID)
	assert.Equal(t, checkpoint.PolicyDigest, trust.Checkpoint.PolicyDigest)
	assert.Equal(t, checkpoint.ControlBytes, trust.Checkpoint.ControlBytes)
	assert.NotEqual(t, checkpoint.ControlCID, trust.Checkpoint.ControlCID)
	retention := fixture.coordinator.refreshRetention(ctx, selection, trust, read.Read, read.Currency)
	assert.Equal(t, RetentionAdmissionRefused, retention.Admission)
	assert.Equal(t, RetentionReasonCheckpointPosition, retention.Reason)

	after, err := fixture.store.RetentionDeclaration(ctx, selection.Vault, selection.DeviceID)
	require.NoError(t, err)
	assert.Equal(t, before.RecoveryPoints, after.RecoveryPoints)
	assert.Equal(t, before.DeclarationDigest, after.DeclarationDigest)
}

func TestRetentionPointBodyEvidenceRefusesWrongParentCIDMissingAndDuplicateBodies(t *testing.T) {
	fixture := newPushFixture(t)
	ctx := context.Background()
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	_, err := fixture.coordinator.Pull(ctx, selection)
	require.NoError(t, err)
	newcomer, public := newAdminNewcomer(t, "retention-body-evidence")
	enrollment := enrollWithFixture(t, fixture, newcomer, public)
	require.Equal(t, StatusCommitted, enrollment.Status)
	require.NoError(t, os.WriteFile(fixture.file, []byte("theme = 'body-evidence-publication'\n"), 0o600))
	_, err = fixture.coordinator.Push(ctx, selection)
	require.NoError(t, err)
	read, err := fixture.coordinator.Pull(ctx, selection)
	require.NoError(t, err)

	positions, err := retentionPositions(ctx, fixture.store, fixture.genesis.Vault)
	require.NoError(t, err)
	checkpoint := mustVaultCheckpoint(t, fixture.store, fixture.genesis.Vault)
	held, found := findCheckpointRetentionPosition(positions, checkpoint)
	require.True(t, found)
	start, found := findEpochStartRetentionPosition(positions, held)
	require.True(t, found)
	startBody, err := fixture.coordinator.retentionBody(ctx, read.Read, start, start.head.SnapshotCID)
	require.NoError(t, err)
	var publication retentionPosition
	for _, position := range positions {
		if position.head.EpochSeq == checkpoint.Epoch && position.head.PublicationCount == 1 {
			publication = position
		}
	}
	require.NotEmpty(t, publication.evidence.Head)
	publicationBody, err := fixture.coordinator.retentionBody(ctx, read.Read, publication, publication.head.SnapshotCID)
	require.NoError(t, err)
	boundary := state.RetentionRecoveryPoint{
		Epoch: held.head.EpochSeq, SnapshotCID: bytes.Clone(held.head.SnapshotCID),
		PolicyDigest: held.head.PolicyDigest, ControlCID: bytes.Clone(held.controlCID),
	}
	ordinary := state.RetentionRecoveryPoint{
		Epoch: publication.head.EpochSeq, SnapshotCID: bytes.Clone(publication.head.SnapshotCID),
		PolicyDigest: publication.head.PolicyDigest, ControlCID: bytes.Clone(publication.controlCID),
	}
	boundaryEvidence := vault.RetentionRecoveryPointEvidence{
		Point:    vault.RetentionRecoveryPoint{Epoch: boundary.Epoch, SnapshotCID: bytes.Clone(boundary.SnapshotCID), PolicyDigest: boundary.PolicyDigest, ControlCID: bytes.Clone(boundary.ControlCID)},
		Position: retentionControlEvidence(held.evidence), EpochStartHead: bytes.Clone(start.evidence.Head), EpochStartSnapshot: bytes.Clone(startBody),
	}
	ordinaryEvidence := vault.RetentionRecoveryPointEvidence{
		Point:    vault.RetentionRecoveryPoint{Epoch: ordinary.Epoch, SnapshotCID: bytes.Clone(ordinary.SnapshotCID), PolicyDigest: ordinary.PolicyDigest, ControlCID: bytes.Clone(ordinary.ControlCID)},
		Position: retentionControlEvidence(publication.evidence), EpochStartHead: bytes.Clone(start.evidence.Head), EpochStartSnapshot: bytes.Clone(startBody),
		Head: bytes.Clone(publication.evidence.Head), Ciphertext: bytes.Clone(publicationBody),
	}
	request := vault.RetentionDeclarationRequest{
		VaultID: fixture.genesis.Vault, TrustAnchor: fixture.genesis.Anchor, State: retentionControlEvidence(held.evidence),
		DeviceID: fixture.device.DeviceID, RecoveryPoints: []vault.RetentionRecoveryPoint{boundaryEvidence.Point, ordinaryEvidence.Point},
		PointEvidence: []vault.RetentionRecoveryPointEvidence{boundaryEvidence, ordinaryEvidence},
	}
	_, err = vault.EvaluateRetentionDeclaration(cloneRetentionDeclarationRequest(request))
	require.NoError(t, err)

	wrongParent := cloneRetentionPointEvidence(ordinaryEvidence)
	wrongHead, err := vault.DecodeHead(wrongParent.Head)
	require.NoError(t, err)
	wrongHead.PrevHeadCID = bytes.Clone(publication.head.SnapshotCID)
	envelope, err := vault.DecodeEnvelope(publicationBody)
	require.NoError(t, err)
	require.NotEqual(t, envelope.Parent, wrongHead.PrevHeadCID)
	wrongParent.Head, err = signRetentionHeadForTest(t, wrongHead, fixture.device.Signing)
	require.NoError(t, err)
	_, err = vault.EvaluateRetentionDeclaration(cloneRetentionDeclarationRequestWithEvidence(request, []vault.RetentionRecoveryPointEvidence{boundaryEvidence, wrongParent}))
	require.Error(t, err, "a validly signed head whose predecessor differs from the envelope parent is refused")

	wrongCID := cloneRetentionPointEvidence(ordinaryEvidence)
	wrongCID.Ciphertext = bytes.Clone(startBody)
	require.NotEqual(t, ordinaryEvidence.Ciphertext, wrongCID.Ciphertext)
	_, err = vault.EvaluateRetentionDeclaration(cloneRetentionDeclarationRequestWithEvidence(request, []vault.RetentionRecoveryPointEvidence{boundaryEvidence, wrongCID}))
	require.Error(t, err, "a body whose CID differs from the signed snapshot point is refused")

	missing := cloneRetentionPointEvidence(ordinaryEvidence)
	missing.Ciphertext = nil
	_, err = vault.EvaluateRetentionDeclaration(cloneRetentionDeclarationRequestWithEvidence(request, []vault.RetentionRecoveryPointEvidence{boundaryEvidence, missing}))
	require.Error(t, err, "an ordinary point with no exact body is refused")

	duplicate := cloneRetentionPointEvidence(boundaryEvidence)
	duplicate.Head = bytes.Clone(start.evidence.Head)
	duplicate.Ciphertext = bytes.Clone(startBody)
	duplicateRequest := cloneRetentionDeclarationRequest(request)
	duplicateRequest.RecoveryPoints = cloneRetentionRecoveryPoints([]vault.RetentionRecoveryPoint{boundaryEvidence.Point})
	duplicateRequest.PointEvidence = []vault.RetentionRecoveryPointEvidence{duplicate}
	_, err = vault.EvaluateRetentionDeclaration(duplicateRequest)
	require.Error(t, err, "the epoch-start point cannot carry a second body")
}

func TestRetentionRefreshRefusesMissingAndWrongCIDHistoricalBodies(t *testing.T) {
	for _, mode := range []string{"missing", "wrong-cid"} {
		t.Run(mode, func(t *testing.T) {
			fixture := retentionPruneFixture(t, nil)
			ctx := context.Background()
			selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
			before := mustRetentionDeclaration(t, fixture.store, fixture.genesis.Vault, fixture.device.DeviceID)
			current, err := fixture.coordinator.Pull(ctx, selection)
			require.NoError(t, err)
			checkpoint := mustVaultCheckpoint(t, fixture.store, fixture.genesis.Vault)
			wrongBody := bytes.Clone(current.Read.Ciphertext)
			fault := retentionBlobFaultTransport{base: fixture.pds, targetCID: cid.MustParse(stringCID(t, checkpoint.SnapshotCID))}
			if mode == "missing" {
				fault.status = 404
			} else {
				fault.body = wrongBody
			}
			fixture.coordinator.deps.Remote = VaultReader{Reader: atproto.VaultReader{
				Transport: fault, ObservationStore: fixture.store, Clock: func() time.Time { return fixture.clock },
			}}
			read, err := fixture.coordinator.Pull(ctx, selection)
			require.NoError(t, err, "a verified live read remains usable when historical retention body retrieval is refused")
			assert.Equal(t, RetentionAdmissionRefused, read.Retention.Admission)
			assert.Equal(t, RetentionReasonHistoricalBody, read.Retention.Reason)
			after := mustRetentionDeclaration(t, fixture.store, fixture.genesis.Vault, fixture.device.DeviceID)
			assert.Equal(t, before.RecoveryPoints, after.RecoveryPoints)
			assert.Equal(t, before.DeclarationDigest, after.DeclarationDigest)
		})
	}
}

func TestRetentionRefreshRefusesDuplicateHistoricalSnapshotBodies(t *testing.T) {
	fixture := retentionPruneFixture(t, nil)
	ctx := context.Background()
	selection := VaultSelection{Vault: fixture.genesis.Vault, DeviceID: fixture.device.DeviceID}
	before := mustRetentionDeclaration(t, fixture.store, fixture.genesis.Vault, fixture.device.DeviceID)
	checkpoint := mustVaultCheckpoint(t, fixture.store, fixture.genesis.Vault)
	recordBytes := duplicateRetentionSnapshotRecord(t, fixture, checkpoint.SnapshotCID)
	write := map[string]any{
		"$type": "com.atproto.repo.applyWrites#create", "collection": atproto.VaultSnapshotNSID,
		"rkey": "duplicate-retention-body", "value": json.RawMessage(recordBytes),
	}
	requestBytes, err := json.Marshal(map[string]any{
		"repo": pushTestDID, "swapCommit": fixture.pds.CurrentRevision().CommitCID.String(), "writes": []any{write},
	})
	require.NoError(t, err)
	status, _, err := fixture.pds.Do(ctx, "POST", "com.atproto.repo.applyWrites", nil, requestBytes, "application/json")
	require.NoError(t, err)
	require.Equal(t, 200, status)
	matchingRecords := 0
	for _, record := range fixture.pds.CurrentRevision().Records {
		if record.Collection != atproto.VaultSnapshotNSID {
			continue
		}
		decoded, err := atproto.DecodeRecord(record.Data)
		require.NoError(t, err)
		snapshot, ok := decoded.(atproto.SnapshotRecord)
		if ok && bytes.Equal(snapshot.Blob.Ref.CID().Bytes(), checkpoint.SnapshotCID) {
			matchingRecords++
		}
	}
	require.Equal(t, 2, matchingRecords, "PDS retains both valid records referencing the same snapshot body")

	read, err := fixture.coordinator.Pull(ctx, selection)
	require.NoError(t, err)
	assert.Equal(t, RetentionAdmissionRefused, read.Retention.Admission)
	assert.Equal(t, RetentionReasonHistoricalBody, read.Retention.Reason)
	after := mustRetentionDeclaration(t, fixture.store, fixture.genesis.Vault, fixture.device.DeviceID)
	assert.Equal(t, before.RecoveryPoints, after.RecoveryPoints)
	assert.Equal(t, before.DeclarationDigest, after.DeclarationDigest)
}

func duplicateRetentionSnapshotRecord(t *testing.T, fixture *pushFixture, snapshotCID []byte) []byte {
	t.Helper()
	for _, record := range fixture.pds.CurrentRevision().Records {
		if record.Collection != atproto.VaultSnapshotNSID {
			continue
		}
		decoded, err := atproto.DecodeRecord(record.Data)
		require.NoError(t, err)
		snapshot, ok := decoded.(atproto.SnapshotRecord)
		if ok && bytes.Equal(snapshot.Blob.Ref.CID().Bytes(), snapshotCID) {
			encoded, err := json.Marshal(map[string]any{
				"$type": atproto.VaultSnapshotNSID, "schemaVersion": snapshot.SchemaVersion,
				"vault": atdata.Bytes(snapshot.Vault), "publicationId": atdata.Bytes(snapshot.PublicationID),
				"epochSeq": int64(snapshot.EpochSeq), "policyDigest": atdata.Bytes(snapshot.PolicyDigest),
				"parent": atdata.Bytes(snapshot.Parent), "blob": snapshot.Blob,
				"signerDeviceId": snapshot.SignerDeviceID, "signerKeyId": atdata.Bytes(snapshot.SignerKeyID),
				"envelopeSignatureDigest": atdata.Bytes(snapshot.EnvelopeSignatureDigest),
				"signature":               atdata.Bytes(snapshot.Signature),
			})
			require.NoError(t, err)
			require.True(t, json.Valid(encoded))
			return encoded
		}
	}
	t.Fatal("snapshot record for requested retention point is missing")
	return nil
}

type retentionBlobFaultTransport struct {
	base      atproto.Transport
	targetCID cid.Cid
	status    int
	body      []byte
}

func (transport retentionBlobFaultTransport) Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error) {
	return transport.base.Do(ctx, method, endpoint, query, body, contentType)
}

func (transport retentionBlobFaultTransport) OpenStream(ctx context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	if endpoint == "com.atproto.sync.getBlob" && query.Get("cid") == transport.targetCID.String() {
		if transport.status != 0 {
			return transport.status, io.NopCloser(bytes.NewReader(nil)), nil
		}
		return 200, io.NopCloser(bytes.NewReader(bytes.Clone(transport.body))), nil
	}
	return transport.base.OpenStream(ctx, endpoint, query)
}

func stringCID(t *testing.T, encoded []byte) string {
	t.Helper()
	value, err := cid.Cast(encoded)
	require.NoError(t, err)
	return value.String()
}

func cloneRetentionPointEvidence(evidence vault.RetentionRecoveryPointEvidence) vault.RetentionRecoveryPointEvidence {
	cloned := evidence
	cloned.Point.SnapshotCID = bytes.Clone(evidence.Point.SnapshotCID)
	cloned.Point.ControlCID = bytes.Clone(evidence.Point.ControlCID)
	cloned.Position = cloneRetentionControlEvidence(evidence.Position)
	cloned.Intermediates = make([]vault.ControlEvidence, len(evidence.Intermediates))
	for index, intermediate := range evidence.Intermediates {
		cloned.Intermediates[index] = cloneRetentionControlEvidence(intermediate)
	}
	cloned.EpochStartHead = bytes.Clone(evidence.EpochStartHead)
	cloned.EpochStartSnapshot = bytes.Clone(evidence.EpochStartSnapshot)
	cloned.Head = bytes.Clone(evidence.Head)
	cloned.Ciphertext = bytes.Clone(evidence.Ciphertext)
	return cloned
}

func cloneRetentionControlEvidence(evidence vault.ControlEvidence) vault.ControlEvidence {
	return vault.ControlEvidence{
		Policy: bytes.Clone(evidence.Policy), Control: bytes.Clone(evidence.Control),
		Certificates: cloneServiceByteSlices(evidence.Certificates),
	}
}

func cloneRetentionRecoveryPoints(points []vault.RetentionRecoveryPoint) []vault.RetentionRecoveryPoint {
	cloned := make([]vault.RetentionRecoveryPoint, len(points))
	for index, point := range points {
		cloned[index] = point
		cloned[index].SnapshotCID = bytes.Clone(point.SnapshotCID)
		cloned[index].ControlCID = bytes.Clone(point.ControlCID)
	}
	return cloned
}

func cloneRetentionDeclarationRequest(request vault.RetentionDeclarationRequest) vault.RetentionDeclarationRequest {
	request.State = cloneRetentionControlEvidence(request.State)
	request.RecoveryPoints = cloneRetentionRecoveryPoints(request.RecoveryPoints)
	request.PointEvidence = cloneRetentionPointEvidenceList(request.PointEvidence)
	return request
}

func cloneRetentionDeclarationRequestWithEvidence(request vault.RetentionDeclarationRequest, evidence []vault.RetentionRecoveryPointEvidence) vault.RetentionDeclarationRequest {
	cloned := cloneRetentionDeclarationRequest(request)
	cloned.PointEvidence = cloneRetentionPointEvidenceList(evidence)
	return cloned
}

func cloneRetentionPointEvidenceList(evidence []vault.RetentionRecoveryPointEvidence) []vault.RetentionRecoveryPointEvidence {
	cloned := make([]vault.RetentionRecoveryPointEvidence, len(evidence))
	for index, pointEvidence := range evidence {
		cloned[index] = cloneRetentionPointEvidence(pointEvidence)
	}
	return cloned
}

func signRetentionHeadForTest(t *testing.T, head vault.Head, signing ed25519.PrivateKey) ([]byte, error) {
	t.Helper()
	head.Signature = [64]byte{}
	unsigned, err := vault.EncodeHead(head)
	if err != nil {
		return nil, err
	}
	preimage := append([]byte("dottie/v1/sig"), unsigned[:len(unsigned)-ed25519.SignatureSize]...)
	signature, err := vault.Sign("dottie/v1/sig-head", preimage, signing)
	if err != nil {
		return nil, err
	}
	copy(head.Signature[:], signature)
	return vault.EncodeHead(head)
}
