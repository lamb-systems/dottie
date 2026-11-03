package vault

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExportCheckpointMustMatchArchiveVaultAndSignedControlPosition(t *testing.T) {
	archive, fixture := exportArchiveForValidationTest(t)
	require.NoError(t, validateExportSignatures(archive, fixture.kit))

	t.Run("archive vault", func(t *testing.T) {
		checkpoint := decodeExportTestCheckpoint(t, archive.Checkpoint)
		checkpoint.Vault[0] ^= 1
		altered := archive
		altered.Checkpoint = signExportTestCheckpoint(t, fixture, checkpoint)
		err := validateExportSignatures(altered, fixture.kit)
		require.ErrorIs(t, err, ErrAuthorization)
		assert.ErrorContains(t, err, "checkpoint vault or anchor")
	})

	for _, check := range []struct {
		name   string
		mutate func(*Checkpoint)
	}{
		{
			name: "epoch",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.EpochSeq++
			},
		},
		{
			name: "policy digest",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.PolicyDigest[0] ^= 1
			},
		},
	} {
		t.Run("signed control position "+check.name, func(t *testing.T) {
			checkpoint := decodeExportTestCheckpoint(t, archive.Checkpoint)
			check.mutate(&checkpoint)
			altered := archive
			altered.Checkpoint = signExportTestCheckpoint(t, fixture, checkpoint)
			err := validateExportSignatures(altered, fixture.kit)
			require.ErrorIs(t, err, ErrAuthorization)
			assert.ErrorContains(t, err, "checkpoint position is absent or does not match signed control evidence")
		})
	}
}

func TestExportCurrentPolicyMustMatchManifestEpochAndDigest(t *testing.T) {
	archive, fixture := exportArchiveForValidationTest(t)
	require.NoError(t, validateExportSignatures(archive, fixture.kit))

	for _, check := range []struct {
		name   string
		mutate func(*ExportArchive)
	}{
		{
			name: "epoch",
			mutate: func(archive *ExportArchive) {
				archive.Epoch++
			},
		},
		{
			name: "policy digest",
			mutate: func(archive *ExportArchive) {
				archive.PolicyDigest[0] ^= 1
			},
		},
	} {
		t.Run(check.name, func(t *testing.T) {
			altered := archive
			check.mutate(&altered)
			err := validateExportSignatures(altered, fixture.kit)
			require.ErrorIs(t, err, ErrExportPolicy)
			assert.ErrorContains(t, err, "manifest epoch or policy digest does not match current position")
		})
	}
}

func exportArchiveForValidationTest(t *testing.T) (ExportArchive, devicesFixture) {
	t.Helper()
	input, fixture := exportTestInput(t)
	archive, err := archiveFromInput(input)
	require.NoError(t, err)
	return archive, fixture
}

func decodeExportTestCheckpoint(t *testing.T, encoded []byte) Checkpoint {
	t.Helper()
	checkpoint, err := DecodeCheckpoint(encoded)
	require.NoError(t, err)
	return checkpoint
}

func signExportTestCheckpoint(t *testing.T, fixture devicesFixture, checkpoint Checkpoint) []byte {
	t.Helper()
	key, err := deriveKitSigningKey(fixture.kit, fixture.bootstrap.Vault)
	require.NoError(t, err)
	return signCheckpointValue(t, checkpoint, key)
}

func TestExportCheckpointSnapshotMustMatchSignedPosition(t *testing.T) {
	input, fixture := exportTestInput(t)
	position := exportPositionFromTransition(t, fixture.transition)
	predecessor := predecessorAfterTransition(t, fixture.predecessor, fixture.transition)
	publication, err := PreparePublication(predecessor, publicationTestIntent(fixture, predecessor))
	require.NoError(t, err)
	input.Current.Head = bytes.Clone(publication.Head)
	input.Checkpoint = exportCheckpointForPosition(t, fixture, position)
	input.Blobs = append(input.Blobs, ExportBlob{CID: bytes.Clone(publication.BlobCID), Data: bytes.Clone(publication.Snapshot)})
	archive, err := archiveFromInput(input)
	require.NoError(t, err)
	require.NoError(t, validateExportSignatures(archive, fixture.kit), "the kit-signed checkpoint matching the signed control is accepted")

	control, err := DecodeControl(position.Control)
	require.NoError(t, err)
	checkpoint := decodeExportTestCheckpoint(t, archive.Checkpoint)
	assert.Equal(t, control.HeadSnapshotCID, checkpoint.SnapshotCID, "the positive checkpoint matches the signed epoch-start snapshot")
	checkpoint.SnapshotCID = bytes.Clone(publication.SnapshotCID)
	assert.NotEqual(t, control.HeadSnapshotCID, checkpoint.SnapshotCID, "the hostile checkpoint names the later same-control publication head")
	archive.Checkpoint = signExportTestCheckpoint(t, fixture, checkpoint)

	err = validateExportSignatures(archive, fixture.kit)
	require.ErrorIs(t, err, ErrAuthorization)
	assert.ErrorContains(t, err, "checkpoint position is absent or does not match signed control evidence")
}
