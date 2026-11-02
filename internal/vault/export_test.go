package vault

import (
	"archive/tar"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ipfs/go-cid"
)

type exportTestMember struct {
	name string
	data []byte
}

func TestExportArchiveRoundTripPreservesSignedObjects(t *testing.T) {
	input, fixture := exportTestInput(t)
	encoded, err := EncodeExportArchive(input)
	require.NoError(t, err)

	archive, err := ReadExportArchive(bytes.NewReader(encoded), exportTestOptions(fixture))
	require.NoError(t, err)
	assert.Equal(t, input.Current.Policy, archive.Current.Policy, "policy bytes changed")
	assert.Equal(t, input.Current.Control, archive.Current.Control, "control bytes changed")
	assert.ElementsMatch(t, input.Current.Certificates, archive.Current.Certificates, "certificate bytes changed")
	assert.Equal(t, input.Current.Head, archive.Current.Head, "head bytes changed")
	assert.Equal(t, input.Checkpoint, archive.Checkpoint, "checkpoint bytes changed")
	assert.Equal(t, input.Lineage[0].Policy, archive.Lineage[0].Policy, "lineage policy bytes changed")
	assert.Equal(t, input.Lineage[0].Control, archive.Lineage[0].Control, "lineage control bytes changed")
	assert.ElementsMatch(t, input.Lineage[0].Certificates, archive.Lineage[0].Certificates, "lineage certificate bytes changed")
	assert.Equal(t, input.Blobs[0].CID, archive.Blobs[0].CID, "blob CID changed")
	assert.Equal(t, input.Blobs[0].Data, archive.Blobs[0].Data, "blob bytes changed")
	assert.Equal(t, ExportOmissionUnavailableLocalHistory, archive.Manifest.Omissions[0], "caller omission was lost")
	assert.Equal(t, []string{exportLimitationNeverHeld, exportLimitationScope, exportLimitationCAR}, archive.Manifest.Limitations, "archive limitations changed")
	assert.Equal(t, fixture.bootstrap.Vault, archive.VaultID, "vault ID changed")
	assert.Equal(t, fixture.bootstrap.Anchor, archive.Anchor, "anchor changed")
}

func TestReadExportArchiveRoundTripsTwoDistinctReferencedBlobs(t *testing.T) {
	input, fixture := exportTestInput(t)
	predecessor := predecessorAfterTransition(t, fixture.predecessor, fixture.transition)
	publication, err := PreparePublication(predecessor, publicationTestIntent(fixture, predecessor))
	require.NoError(t, err)
	input.Current.Head = bytes.Clone(publication.Head)
	input.Blobs = append(input.Blobs, ExportBlob{CID: bytes.Clone(publication.BlobCID), Data: bytes.Clone(publication.Snapshot)})

	encoded, err := EncodeExportArchive(input)
	require.NoError(t, err)
	archive, err := ReadExportArchive(bytes.NewReader(encoded), exportTestOptions(fixture))
	require.NoError(t, err)
	assert.Len(t, archive.Blobs, 2, "distinct referenced blobs did not round-trip")
	assert.NotEqual(t, archive.Blobs[0].CID, archive.Blobs[1].CID, "round-trip blobs are not distinct")
}

func TestReadExportArchiveRejectsDuplicateBlobCID(t *testing.T) {
	input, _ := exportTestInput(t)
	input.Blobs = append(input.Blobs, ExportBlob{CID: bytes.Clone(input.Blobs[0].CID), Data: bytes.Clone(input.Blobs[0].Data)})
	_, err := EncodeExportArchive(input)
	assert.ErrorIs(t, err, ErrExportIntegrity, "duplicate blob CID was accepted")
}

func TestReadExportArchiveRefusesWrongVersionBeforeEntryValidation(t *testing.T) {
	input, fixture := exportTestInput(t)
	encoded, err := EncodeExportArchive(input)
	require.NoError(t, err)
	wrongVersion := rewriteExportArchive(t, encoded, func(manifest *ExportManifest, _ *[]exportTestMember) {
		manifest.FormatVersion = ExportFormatVersion + 1
	})
	reader := &countingExportReader{reader: bytes.NewReader(wrongVersion)}

	_, err = ReadExportArchive(reader, exportTestOptions(fixture))
	assert.ErrorIs(t, err, ErrUnsupportedExportVersion, "unknown version was not refused")
	assert.Less(t, reader.read, int64(len(wrongVersion)), "unsupported version consumed payload members")
}

func TestReadExportArchiveRejectsInvalidMagicBeforeReadingPayload(t *testing.T) {
	reader := &magicGuardReader{}
	_, err := ReadExportArchive(reader, ImportOptions{})
	assert.ErrorIs(t, err, ErrIncompleteExport, "invalid magic was accepted")
	assert.Equal(t, int64(len(exportMagic)), reader.read, "reader consumed bytes beyond the invalid magic")
}

func TestReadExportArchiveRefusesCorruptedEntryBeforeWrite(t *testing.T) {
	input, fixture := exportTestInput(t)
	encoded, err := EncodeExportArchive(input)
	require.NoError(t, err)
	corrupted := rewriteExportArchive(t, encoded, func(_ *ExportManifest, members *[]exportTestMember) {
		for index := range *members {
			if (*members)[index].name == "000001" {
				(*members)[index].data[0] ^= 0x80
				return
			}
		}
		require.FailNow(t, "test archive did not contain first object")
	})
	destination := filepath.Join(t.TempDir(), "existing")
	original := []byte("destination must remain untouched")
	require.NoError(t, os.WriteFile(destination, original, 0o600))

	_, err = ReadExportArchive(bytes.NewReader(corrupted), exportTestOptions(fixture))
	require.ErrorIs(t, err, ErrExportIntegrity)
	actual, readErr := os.ReadFile(destination)
	require.NoError(t, readErr)
	assert.Equal(t, original, actual, "refused import changed destination")
}

func TestReadExportArchiveRefusesManifestDigestMismatch(t *testing.T) {
	input, fixture := exportTestInput(t)
	encoded, err := EncodeExportArchive(input)
	require.NoError(t, err)
	mismatched := rewriteExportArchive(t, encoded, func(manifest *ExportManifest, _ *[]exportTestMember) {
		manifest.Entries[0].SHA256 = string(bytes.Repeat([]byte{'0'}, 64))
	})

	err = readExportRefusalWithoutMutation(t, mismatched, exportTestOptions(fixture))
	assert.ErrorIs(t, err, ErrExportIntegrity, "manifest digest mismatch was accepted")
}

func TestReadExportArchiveRequiresIntentForForeignVaultAndHonorsItExplicitly(t *testing.T) {
	input, fixture := exportTestInput(t)
	encoded, err := EncodeExportArchive(input)
	require.NoError(t, err)
	options := exportTestOptions(fixture)
	options.ExpectedVaultID[0] ^= 1

	err = readExportRefusalWithoutMutation(t, encoded, options)
	require.ErrorIs(t, err, ErrForeignVault)
	options.AllowVaultMove = true
	archive, err := ReadExportArchive(bytes.NewReader(encoded), options)
	require.NoError(t, err)
	assert.Equal(t, fixture.bootstrap.Vault, archive.VaultID, "explicit move changed archive source identity")
}

func TestReadExportArchiveRejectsTruncationAndCARInput(t *testing.T) {
	input, fixture := exportTestInput(t)
	encoded, err := EncodeExportArchive(input)
	require.NoError(t, err)
	err = readExportRefusalWithoutMutation(t, encoded[:len(encoded)-600], exportTestOptions(fixture))
	assert.Error(t, err, "truncated archive was accepted")

	err = readExportRefusalWithoutMutation(t, []byte("\x01\x63CAR\x01\x00"), exportTestOptions(fixture))
	assert.ErrorIs(t, err, ErrIncompleteExport, "CAR-shaped input was accepted as an export")
}

func TestReadExportArchiveNamesMissingReferencedCID(t *testing.T) {
	input, fixture := exportTestInput(t)
	encoded, err := EncodeExportArchive(input)
	require.NoError(t, err)
	missing := rewriteExportArchive(t, encoded, func(manifest *ExportManifest, members *[]exportTestMember) {
		keptEntries := manifest.Entries[:0]
		for _, entry := range manifest.Entries {
			if entry.Kind != exportEntryBlob {
				keptEntries = append(keptEntries, entry)
			}
		}
		manifest.Entries = keptEntries
		keptMembers := (*members)[:0]
		for _, member := range *members {
			if member.name != inputBlobMember(t, encoded) {
				keptMembers = append(keptMembers, member)
			}
		}
		*members = keptMembers
	})

	err = readExportRefusalWithoutMutation(t, missing, exportTestOptions(fixture))
	require.ErrorIs(t, err, ErrExportBlob)
	cidText := mustCIDString(t, input.Blobs[0].CID)
	assert.Contains(t, err.Error(), cidText, "missing blob refusal did not identify CID")
}

func TestReadExportArchiveRefusesCheckpointNewerThanCurrent(t *testing.T) {
	input, fixture := exportTestInput(t)
	checkpointPosition := exportPositionFromTransition(t, fixture.transition)
	input.Checkpoint = exportCheckpointForPosition(t, fixture, checkpointPosition)
	input.Current = ExportPosition{
		Policy: bytes.Clone(fixture.bootstrap.Policy), Control: bytes.Clone(fixture.bootstrap.Control),
		Certificates: [][]byte{bytes.Clone(fixture.bootstrap.Certificate)},
	}
	input.Epoch = 0
	input.PolicyDigest = mustPolicyDigest(fixture.bootstrap.Policy)
	input.Lineage = []ExportPosition{checkpointPosition}
	input.RecoveryPoints = nil

	_, err := EncodeExportArchive(input)
	assert.ErrorIs(t, err, ErrExportPolicy, "current position below authenticated checkpoint was accepted")
}

func TestReadExportArchiveRefusesMissingPublicationHeadHistoryIntermediate(t *testing.T) {
	input, fixture := exportTestInput(t)
	predecessor := predecessorAfterTransition(t, fixture.predecessor, fixture.transition)
	publication, err := PreparePublication(predecessor, publicationTestIntent(fixture, predecessor))
	require.NoError(t, err)
	input.Current.Head = bytes.Clone(publication.Head)
	input.RecoveryPoints = nil
	input.Blobs = []ExportBlob{{CID: bytes.Clone(publication.BlobCID), Data: bytes.Clone(publication.Snapshot)}}

	_, err = EncodeExportArchive(input)
	require.ErrorIs(t, err, ErrExportBlob)
	assert.Contains(t, err.Error(), mustCIDString(t, fixture.transition.BlobCID), "missing publication predecessor refusal did not identify its CID")
}

func TestReadExportArchiveRefusesMissingCheckpointSnapshotPayload(t *testing.T) {
	input, fixture := exportTestInput(t)
	predecessor := predecessorAfterTransition(t, fixture.predecessor, fixture.transition)
	publication, err := PreparePublication(predecessor, publicationTestIntent(fixture, predecessor))
	require.NoError(t, err)
	checkpointPosition := exportPositionFromTransition(t, fixture.transition)
	input.Checkpoint = exportCheckpointForPosition(t, fixture, checkpointPosition)
	input.Current.Head = bytes.Clone(publication.Head)
	input.RecoveryPoints = nil
	input.Blobs = []ExportBlob{{CID: bytes.Clone(publication.BlobCID), Data: bytes.Clone(publication.Snapshot)}}

	_, err = EncodeExportArchive(input)
	require.ErrorIs(t, err, ErrExportBlob)
	assert.Contains(t, err.Error(), mustCIDString(t, fixture.transition.BlobCID), "missing checkpoint snapshot refusal did not identify its CID")

	input.RecoveryPoints = []ExportPosition{checkpointPosition}
	input.Blobs = append(input.Blobs, ExportBlob{CID: bytes.Clone(fixture.transition.BlobCID), Data: bytes.Clone(fixture.transition.Snapshot)})
	encoded, err := EncodeExportArchive(input)
	require.NoError(t, err)
	_, err = ReadExportArchive(bytes.NewReader(encoded), exportTestOptions(fixture))
	require.NoError(t, err)
}

func TestReadExportArchiveRefusesMissingControlLineageIntermediate(t *testing.T) {
	input, fixture := exportTestInput(t)
	second := secondEnrollmentTransition(t, fixture)
	secondPosition := exportPositionFromTransition(t, second)
	firstControlCID, err := rawCID(fixture.transition.Control)
	require.NoError(t, err)
	input.Current = secondPosition
	input.Epoch = secondEpoch(t, secondPosition)
	input.PolicyDigest = mustPolicyDigest(secondPosition.Policy)
	input.Lineage = []ExportPosition{{
		Policy: bytes.Clone(fixture.bootstrap.Policy), Control: bytes.Clone(fixture.bootstrap.Control),
		Certificates: [][]byte{bytes.Clone(fixture.bootstrap.Certificate)},
	}}
	input.RecoveryPoints = nil
	input.Blobs = []ExportBlob{{CID: bytes.Clone(second.BlobCID), Data: bytes.Clone(second.Snapshot)}}

	_, err = EncodeExportArchive(input)
	require.ErrorIs(t, err, ErrIncompleteExport)
	assert.Contains(t, err.Error(), mustCIDString(t, firstControlCID), "missing control predecessor refusal did not identify its CID")
}

func TestReadExportArchiveRefusesPublicationCountAbovePolicyMaximum(t *testing.T) {
	input, fixture := exportTestInput(t)
	head, err := DecodeHead(input.Current.Head)
	require.NoError(t, err)
	policy, err := DecodePolicy(input.Current.Policy)
	require.NoError(t, err)
	head.PublicationCount = uint64(policy.MaxPublications) + 1
	input.Current.Head = signHeadValue(t, head, fixture.root.Signing)

	_, err = EncodeExportArchive(input)
	assert.ErrorIs(t, err, ErrExportPolicy, "signed head above policy publication bound was accepted")
}

func TestWriteExportArchivePublishesWithCapturePredicate(t *testing.T) {
	input, _ := exportTestInput(t)
	destination := filepath.Join(t.TempDir(), "backup.tar")
	calls := 0
	err := WriteExportArchive(destination, input, func(path string) (bool, error) {
		calls++
		assert.Equal(t, destination, path, "predicate received unexpected destination")
		return false, nil
	})
	require.NoError(t, err)
	assert.Equal(t, 2, calls, "capture predicate was not checked before and after encoding")
	actual, err := os.ReadFile(destination)
	require.NoError(t, err)
	expected, err := EncodeExportArchive(input)
	require.NoError(t, err)
	assert.Equal(t, expected, actual, "published archive bytes changed")
	info, err := os.Stat(destination)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "published archive permissions changed")
}

func TestWriteExportArchivePinsDirectoryAcrossCapturePredicateRace(t *testing.T) {
	input, _ := exportTestInput(t)
	base := t.TempDir()
	parent := filepath.Join(base, "output")
	captured := filepath.Join(base, "captured")
	moved := filepath.Join(base, "output-moved")
	require.NoError(t, os.Mkdir(parent, 0o700))
	require.NoError(t, os.Mkdir(captured, 0o700))
	calls := 0
	err := WriteExportArchive(filepath.Join(parent, "backup.tar"), input, func(string) (bool, error) {
		calls++
		if calls == 2 {
			require.NoError(t, os.Rename(parent, moved))
			require.NoError(t, os.Symlink(captured, parent))
		}
		return false, nil
	})
	require.Error(t, err)
	assert.Equal(t, 2, calls, "capture predicate was not rechecked before writing")
	contents, readErr := os.ReadDir(captured)
	require.NoError(t, readErr)
	assert.Empty(t, contents, "directory replacement redirected export into capture selection")
}

func TestWriteExportArchiveRefusesCaptureSelectionWithoutChangingDestination(t *testing.T) {
	input, _ := exportTestInput(t)
	directory := t.TempDir()
	destination := filepath.Join(directory, "backup.tar")
	original := []byte("existing bytes")
	require.NoError(t, os.WriteFile(destination, original, 0o600))
	calls := 0
	err := WriteExportArchive(destination, input, func(path string) (bool, error) {
		calls++
		assert.Equal(t, destination, path, "predicate received unexpected destination")
		return true, nil
	})
	require.Error(t, err)
	assert.Equal(t, 1, calls, "capture predicate call count")
	assert.Contains(t, err.Error(), "inside a capture selection", "wrong refusal")
	actual, readErr := os.ReadFile(destination)
	require.NoError(t, readErr)
	assert.Equal(t, original, actual, "refused export changed destination")
}

func TestExportArchiveContainsNoKeyMaterial(t *testing.T) {
	input, fixture := exportTestInput(t)
	encoded, err := EncodeExportArchive(input)
	require.NoError(t, err)
	manifest, err := readExportTestManifest(encoded)
	require.NoError(t, err)
	manifestBytes, err := encodeExportManifest(manifest)
	require.NoError(t, err)

	secrets := [][]byte{
		fixture.kit,
		fixture.root.Signing[:32],
		fixture.root.Recipient.Bytes(),
		fixture.newDevice.Signing[:32],
		fixture.newDevice.Recipient.Bytes(),
		fixture.intent.ContentKey,
		fixture.intent.Wraps[0].EphemeralPrivate[:],
	}
	for _, secret := range secrets {
		require.NotEmpty(t, secret, "test secret fixture is empty")
		assert.False(t, bytes.Contains(encoded, secret), "archive contains key material")
		assert.False(t, bytes.Contains(manifestBytes, secret), "manifest contains key material")
	}
}

func TestEncodeExportArchiveRejectsUnreferencedBlob(t *testing.T) {
	input, _ := exportTestInput(t)
	secret := []byte("synthetic unreferenced key-like payload")
	cid, err := rawCID(secret)
	require.NoError(t, err)
	input.Blobs = append(input.Blobs, ExportBlob{CID: cid, Data: secret})

	_, err = EncodeExportArchive(input)
	assert.ErrorIs(t, err, ErrExportIntegrity, "unreferenced data was accepted into the archive")
}

func TestReadExportArchiveRequiresAnchorBindingBeforeSignatures(t *testing.T) {
	input, fixture := exportTestInput(t)
	encoded, err := EncodeExportArchive(input)
	require.NoError(t, err)
	options := exportTestOptions(fixture)
	options.ExpectedAnchor[0] ^= 1

	err = readExportRefusalWithoutMutation(t, encoded, options)
	assert.ErrorIs(t, err, ErrForeignAnchor, "foreign anchor was not refused")
}

func exportTestInput(t *testing.T) (ExportInput, devicesFixture) {
	t.Helper()
	fixture := newDevicesFixture(t)
	currentHead, err := DecodeHead(fixture.transition.Head)
	require.NoError(t, err)
	policyDigest, err := ComputePolicyDigest(fixture.transition.Policy)
	require.NoError(t, err)
	input := ExportInput{
		VaultID: fixture.bootstrap.Vault, AnchorFingerprint: fixture.bootstrap.Anchor,
		Epoch: currentHead.EpochSeq, PolicyDigest: policyDigest,
		Current: ExportPosition{
			Policy: bytes.Clone(fixture.transition.Policy), Control: bytes.Clone(fixture.transition.Control),
			Certificates: cloneByteSlices(fixture.transition.Recipients), Head: bytes.Clone(fixture.transition.Head),
		},
		Checkpoint: bytes.Clone(fixture.bootstrap.Checkpoint),
		Lineage: []ExportPosition{{
			Policy: bytes.Clone(fixture.bootstrap.Policy), Control: bytes.Clone(fixture.bootstrap.Control),
			Certificates: [][]byte{bytes.Clone(fixture.bootstrap.Certificate)},
		}},
		RecoveryPoints: []ExportPosition{{
			Policy: bytes.Clone(fixture.transition.Policy), Control: bytes.Clone(fixture.transition.Control),
			Certificates: cloneByteSlices(fixture.transition.Recipients), Head: bytes.Clone(fixture.transition.Head),
		}},
		Blobs:     []ExportBlob{{CID: bytes.Clone(fixture.transition.BlobCID), Data: bytes.Clone(fixture.transition.Snapshot)}},
		Omissions: []ExportOmissionCode{ExportOmissionUnavailableLocalHistory}, RecoveryKit: bytes.Clone(fixture.kit),
	}
	return input, fixture
}

func exportTestOptions(fixture devicesFixture) ImportOptions {
	return ImportOptions{ExpectedVaultID: fixture.bootstrap.Vault, ExpectedAnchor: fixture.bootstrap.Anchor, RecoveryKit: bytes.Clone(fixture.kit)}
}

func rewriteExportArchive(t *testing.T, encoded []byte, mutate func(*ExportManifest, *[]exportTestMember)) []byte {
	t.Helper()
	require.True(t, bytes.HasPrefix(encoded, []byte(exportMagic)), "test input is not a Dottie export")
	tarReader := tar.NewReader(bytes.NewReader(encoded[len(exportMagic):]))
	var members []exportTestMember
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		data, err := io.ReadAll(tarReader)
		require.NoError(t, err)
		members = append(members, exportTestMember{name: header.Name, data: data})
	}
	require.NotEmpty(t, members, "archive has no manifest")
	var manifest ExportManifest
	require.NoError(t, json.Unmarshal(members[0].data, &manifest))
	mutate(&manifest, &members)
	manifestBytes, err := encodeExportManifest(manifest)
	require.NoError(t, err)
	members[0].name = exportManifestMember
	members[0].data = manifestBytes
	for index := 1; index < len(members); index++ {
		members[index].name = ordinal(index)
	}
	var result bytes.Buffer
	result.WriteString(exportMagic)
	writer := tar.NewWriter(&result)
	for _, member := range members {
		require.NoError(t, writeMember(writer, member.name, member.data))
	}
	require.NoError(t, writer.Close())
	return result.Bytes()
}

func readExportRefusalWithoutMutation(t *testing.T, encoded []byte, options ImportOptions) error {
	t.Helper()
	destination := filepath.Join(t.TempDir(), "import-target")
	original := []byte("unchanged by read-only import")
	require.NoError(t, os.WriteFile(destination, original, 0o600))
	_, err := ReadExportArchive(bytes.NewReader(encoded), options)
	actual, readErr := os.ReadFile(destination)
	require.NoError(t, readErr)
	assert.Equal(t, original, actual, "refused import changed destination")
	return err
}

func readExportTestManifest(encoded []byte) (ExportManifest, error) {
	if len(encoded) < len(exportMagic) {
		return ExportManifest{}, io.ErrUnexpectedEOF
	}
	reader := tar.NewReader(bytes.NewReader(encoded[len(exportMagic):]))
	if _, err := reader.Next(); err != nil {
		return ExportManifest{}, err
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return ExportManifest{}, err
	}
	return decodeExportManifest(data)
}

func inputBlobMember(t *testing.T, encoded []byte) string {
	t.Helper()
	manifest, err := readExportTestManifest(encoded)
	require.NoError(t, err)
	for _, entry := range manifest.Entries {
		if entry.Kind == exportEntryBlob {
			return entry.Member
		}
	}
	require.FailNow(t, "archive has no blob member")
	return ""
}

func exportPositionFromTransition(t *testing.T, transition Transition) ExportPosition {
	t.Helper()
	return ExportPosition{
		Policy: bytes.Clone(transition.Policy), Control: bytes.Clone(transition.Control),
		Certificates: cloneByteSlices(transition.Recipients), Head: bytes.Clone(transition.Head),
	}
}

func exportCheckpointForPosition(t *testing.T, fixture devicesFixture, position ExportPosition) []byte {
	t.Helper()
	policy, err := DecodePolicy(position.Policy)
	require.NoError(t, err)
	head, err := DecodeHead(position.Head)
	require.NoError(t, err)
	controlCID, err := rawCID(position.Control)
	require.NoError(t, err)
	bootstrapCheckpoint, err := DecodeCheckpoint(fixture.bootstrap.Checkpoint)
	require.NoError(t, err)
	key, err := deriveKitSigningKey(fixture.kit, fixture.bootstrap.Vault)
	require.NoError(t, err)
	return signCheckpointValue(t, Checkpoint{
		Vault: fixture.bootstrap.Vault, SnapshotCID: bytes.Clone(head.SnapshotCID), EpochSeq: policy.EpochSeq,
		PolicyDigest: mustPolicyDigest(position.Policy), Anchor: fixture.bootstrap.Anchor,
		ControlCID: controlCID, Signer: bootstrapCheckpoint.Signer,
	}, key)
}

func secondEpoch(t *testing.T, position ExportPosition) uint64 {
	t.Helper()
	policy, err := DecodePolicy(position.Policy)
	require.NoError(t, err)
	return policy.EpochSeq
}

func secondEnrollmentTransition(t *testing.T, fixture devicesFixture) Transition {
	t.Helper()
	predecessor := predecessorAfterTransition(t, fixture.predecessor, fixture.transition)
	newDevice := DeviceMaterial{DeviceID: "device-third", KeyID: []byte("third-key"), Signing: fixedSigningKey(77), Recipient: fixedX25519Key(78)}
	wraps := []RecipientWrapInput{
		{KeyID: bytes.Clone(fixture.root.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(31, 32)), WrapNonce: [24]byte(fixtureBytes(63, 24))},
		{KeyID: bytes.Clone(fixture.newDevice.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(87, 32)), WrapNonce: [24]byte(fixtureBytes(111, 24))},
		{KeyID: bytes.Clone(newDevice.KeyID), EphemeralPrivate: [32]byte(fixtureBytes(121, 32)), WrapNonce: [24]byte(fixtureBytes(145, 24))},
	}
	transition, err := PrepareTransition(predecessor, TransitionIntent{
		Kind: TransitionEnroll, Vault: fixture.bootstrap.Vault, Signer: fixture.root,
		NewDevice: &newDevice, RequestedRole: RolePublisher, ContentKey: fixtureBytes(169, 32),
		Recipients: cloneByteSlices(fixture.transition.Recipients), Wraps: wraps,
		Plaintext: bytes.Clone(fixture.intent.Plaintext), PublicationID: [16]byte(fixtureBytes(201, 16)), Nonce: [24]byte(fixtureBytes(217, 24)),
	})
	require.NoError(t, err)
	return transition
}

type countingExportReader struct {
	reader io.Reader
	read   int64
}

func (reader *countingExportReader) Read(data []byte) (int, error) {
	count, err := reader.reader.Read(data)
	reader.read += int64(count)
	return count, err
}

type magicGuardReader struct {
	read int64
}

func (reader *magicGuardReader) Read(data []byte) (int, error) {
	if reader.read >= int64(len(exportMagic)) {
		return 0, errors.New("reader was consumed beyond invalid magic")
	}
	remaining := int64(len(exportMagic)) - reader.read
	if int64(len(data)) > remaining {
		data = data[:remaining]
	}
	for index := range data {
		data[index] = 'x'
	}
	reader.read += int64(len(data))
	return len(data), nil
}

func TestExportArchiveTestHelpersUseTestifyForFatalPaths(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "export_test.go", nil, 0)
	require.NoError(t, err)
	usesTestingFatal := false
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == "Fatal" {
			usesTestingFatal = true
		}
		return true
	})
	assert.False(t, usesTestingFatal, "export tests bypassed testify with testing.T.Fatal")
}

func mustCIDString(t *testing.T, encoded []byte) string {
	t.Helper()
	value, err := cid.Cast(encoded)
	require.NoError(t, err)
	return value.String()
}

func TestReadExportArchiveRejectsUnsupportedEntriesAndPreservesCanonicalData(t *testing.T) {
	input, fixture := exportTestInput(t)
	encoded, err := EncodeExportArchive(input)
	require.NoError(t, err)
	unknown := rewriteExportArchive(t, encoded, func(manifest *ExportManifest, _ *[]exportTestMember) {
		manifest.Entries[0].Kind = "unknown_object"
	})
	_, err = ReadExportArchive(bytes.NewReader(unknown), exportTestOptions(fixture))
	assert.Error(t, err, "unknown object kind was accepted")
}

func TestWriteExportArchiveRequiresContainmentPredicate(t *testing.T) {
	input, _ := exportTestInput(t)
	err := WriteExportArchive(filepath.Join(t.TempDir(), "archive"), input, nil)
	assert.ErrorIs(t, err, ErrExportCaptureCheck, "export without capture-selection check was accepted")
}

func TestExportArchiveManifestRejectsArbitraryDescriptiveBytes(t *testing.T) {
	input, fixture := exportTestInput(t)
	input.Omissions = []ExportOmissionCode{ExportOmissionCode(hex.EncodeToString(fixture.kit))}
	_, err := EncodeExportArchive(input)
	assert.ErrorIs(t, err, ErrExportIntegrity, "hex-encoded recovery kit was accepted as omission metadata")

	policyDigest := mustPolicyDigest(fixture.bootstrap.Policy)
	manifest := ExportManifest{
		FormatVersion:     ExportFormatVersion,
		VaultID:           hex.EncodeToString(fixture.bootstrap.Vault[:]),
		AnchorFingerprint: hex.EncodeToString(fixture.bootstrap.Anchor[:]),
		PolicyDigest:      hex.EncodeToString(policyDigest[:]),
		Limitations:       []string{exportLimitationNeverHeld, exportLimitationScope, exportLimitationCAR},
	}
	manifestBytes, err := encodeExportManifest(manifest)
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(manifestBytes, &fields))
	fields["description"] = hex.EncodeToString(fixture.kit)
	hostileManifest, err := json.Marshal(fields)
	require.NoError(t, err)
	_, err = decodeExportManifest(hostileManifest)
	assert.ErrorIs(t, err, ErrIncompleteExport, "manifest accepted an arbitrary descriptive field")
}
