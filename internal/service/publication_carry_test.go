package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/vault"
)

func carryTestBinding() publicationstate.Binding {
	binding := publicationstate.Binding{
		AccountDID: "did:plc:abcdefghijklmnopqrstuvwx",
		Backend:    publicationstate.BackendPublicRepo,
		Vault:      [32]byte{0x62},
	}
	binding.Repository = "at://" + binding.AccountDID
	return binding
}

func carryTestPacked(t *testing.T, target model.Target) (publicationdefinition, publication.SnapshotSegment) {
	t.Helper()
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{target},
		Entries: []model.Entry{{
			TargetID: target.ID,
			File: &model.FileEntry{
				Path: "init.lua", Kind: model.FileRegular, State: model.FilePresent, Mode: 0o644,
				Content: []byte("synthetic carried packed content"),
			},
		}},
	}
	packed, err := vault.PackTarget(snapshot, target.ID)
	require.NoError(t, err)
	cid, err := publication.RawPayloadCID(packed.Payload)
	require.NoError(t, err)
	return publicationdefinition{payload: packed.Payload}, publication.SnapshotSegment{
		Target: target, Form: publication.SegmentFormPacked,
		Blob: publication.BlobReference{
			CID: cid, Size: uint64(len(packed.Payload)), MIMEType: publication.SnapshotBlobMIMEType,
		},
	}
}

type publicationdefinition struct {
	payload []byte
}

func carryTestEntries(
	t *testing.T,
	target model.Target,
) ([]publication.PayloadEntry, publication.SnapshotSegment, []publicationstate.AcceptedMaterialEntry) {
	t.Helper()
	contents := [][]byte{[]byte("synthetic carried entry one"), []byte("synthetic carried entry two")}
	paths := []string{"one.lua", "two.lua"}
	payload := make([]publication.PayloadEntry, 0, len(contents))
	segment := publication.SnapshotSegment{Target: target, Form: publication.SegmentFormEntries}
	material := make([]publicationstate.AcceptedMaterialEntry, 0, len(contents))
	for index, content := range contents {
		cid, err := publication.RawPayloadCID(content)
		require.NoError(t, err)
		segment.Entries = append(segment.Entries, publication.SnapshotEntry{
			Path: paths[index], Mode: 0o644, Size: uint64(len(content)),
			Kind: publication.SnapshotEntryKindFile,
			Blob: publication.BlobReference{
				CID: cid, Size: uint64(len(content)), MIMEType: publication.BlobMIMEType,
			},
		})
		payload = append(payload, publication.PayloadEntry{
			Path: paths[index], Mode: 0o644, Size: uint64(len(content)), Content: content,
		})
		material = append(material, publicationstate.AcceptedMaterialEntry{
			Path: paths[index], Mode: 0o644, Content: content,
		})
	}
	return payload, segment, material
}

func carryTestSummary(segment publication.SnapshotSegment) publicationstate.SegmentSummary {
	summary := publicationstate.SegmentSummary{
		TargetID: segment.Target.ID, Form: publicationFormOfSegment(segment),
	}
	switch segment.Form {
	case publication.SegmentFormPacked:
		summary.BlobCID = segment.Blob.CID
		summary.BlobSize = segment.Blob.Size
	case publication.SegmentFormEntries:
		for _, entry := range segment.Entries {
			summary.Entries = append(summary.Entries, publicationstate.PayloadEntryReference{
				Path: entry.Path, CID: entry.Blob.CID, Size: entry.Size,
			})
		}
	case publication.SegmentFormSettings:
		summary.Settings = publication.SettingsDigest(segment.Settings)
	}
	return summary
}

func carryTestTarget(id, path string) model.Target {
	return model.Target{
		ID: id, Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		Root: &model.FileRoot{Base: model.RootHome, Path: path, Kind: model.SelectionDirectory},
	}
}

func carryTestConfiguration(id, path string) config.Config {
	return config.Config{Version: config.Version, Targets: []config.Target{{
		ID: id, Source: model.SourceFiles, Mode: config.BackupOnly,
		Root: &config.Root{Base: model.RootHome, Path: path, Kind: model.SelectionDirectory},
	}}}
}

func TestPublicationCarryKeepsAnAcceptedSegmentTheConfigurationDoesNotCarry(t *testing.T) {
	configured := carryTestTarget("current", "navi")
	carried := carryTestTarget("retired", "carried")
	definition, packedSegment := carryTestPacked(t, carried)
	_, entriesSegment, entriesMaterial := carryTestEntries(t, carried)
	_ = entriesSegment

	accepted := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: [32]byte{0x62},
		PublicationID: [16]byte{0x51}, Segments: []publication.SnapshotSegment{packedSegment},
	}
	material := publicationstate.AcceptedMaterial{
		SnapshotRecord: []byte{0x01},
		Segments: []publicationstate.AcceptedMaterialSegment{{
			Summary: carryTestSummary(packedSegment), Blob: definition.payload,
			Entries: entriesMaterial,
		}},
	}
	carry, err := publicationCarryOf(accepted, material, carryTestConfiguration(configured.ID, "navi"), nil)
	require.NoError(t, err)
	require.Len(t, carry.Segments, 1)
	assert.Equal(t, []string{"retired"}, carry.TargetIDs())

	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{configured},
		Entries: []model.Entry{{
			TargetID: configured.ID,
			File: &model.FileEntry{
				Path: "current.lua", Kind: model.FileRegular, State: model.FilePresent, Mode: 0o644,
				Content: []byte("synthetic current content"),
			},
		}},
	}
	binding := carryTestBinding()
	candidate, err := encodePublicationCandidateWithCarry(
		binding, snapshot, publicationstate.Floor{}, false, nil, carry, [16]byte{0x53},
	)
	require.NoError(t, err)
	record, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	require.NoError(t, err)
	require.Len(t, record.Segments, 2)
	assert.Equal(t, "current", record.Segments[0].Target.ID)
	assert.Equal(t, "retired", record.Segments[1].Target.ID)
	assert.Equal(t, packedSegment, record.Segments[1], "the carried segment is not byte-identical")
	require.Len(t, candidate.Payloads, 2)
	assert.Equal(t, definition.payload, candidate.Payloads[1])
	require.Len(t, candidate.Segments, 2)
	assert.Equal(t, publicationstate.PayloadFormPacked, candidate.Segments[1].Form)
}

func TestPublicationCarryKeepsAnAcceptedEntriesSegment(t *testing.T) {
	target := carryTestTarget("retired", "carried")
	payload, segment, material := carryTestEntries(t, target)
	accepted := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: [32]byte{0x62},
		PublicationID: [16]byte{0x51}, Segments: []publication.SnapshotSegment{segment},
	}
	acceptedMaterial := publicationstate.AcceptedMaterial{
		SnapshotRecord: []byte{0x01},
		Segments: []publicationstate.AcceptedMaterialSegment{{
			Summary: carryTestSummary(segment), Entries: material,
		}},
	}
	carry, err := publicationCarryOf(
		accepted, acceptedMaterial, carryTestConfiguration("current", "navi"), nil,
	)
	require.NoError(t, err)
	require.Len(t, carry.Segments, 1)
	assert.Equal(t, payload, carry.Entries["retired"])

	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{carryTestTarget("current", "navi")},
	}
	candidate, err := encodePublicationCandidateWithCarry(
		carryTestBinding(), snapshot, publicationstate.Floor{}, false, nil, carry, [16]byte{0x53},
	)
	require.NoError(t, err)
	record, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	require.NoError(t, err)
	require.Len(t, record.Segments, 2)
	assert.Equal(t, segment, record.Segments[1])
	require.Len(t, candidate.Entries, len(payload))
	assert.Equal(t, payload[0].Content, candidate.Entries[0].Content)
}

func TestPublicationCarryRefusesAPayloadThatDoesNotMatchTheAcceptedSummary(t *testing.T) {
	target := carryTestTarget("retired", "carried")
	definition, segment := carryTestPacked(t, target)
	tampered := append([]byte(nil), definition.payload...)
	tampered[len(tampered)-1] ^= 0xff

	accepted := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: [32]byte{0x62},
		PublicationID: [16]byte{0x51}, Segments: []publication.SnapshotSegment{segment},
	}
	material := publicationstate.AcceptedMaterial{
		SnapshotRecord: []byte{0x01},
		Segments: []publicationstate.AcceptedMaterialSegment{{
			Summary: carryTestSummary(segment), Blob: tampered,
		}},
	}
	_, err := publicationCarryOf(accepted, material, carryTestConfiguration("current", "navi"), nil)
	require.ErrorIs(t, err, ErrPublicationCarry)

	material.Segments[0].Blob = definition.payload
	carry, err := publicationCarryOf(accepted, material, carryTestConfiguration("current", "navi"), nil)
	require.NoError(t, err)
	assert.False(t, carry.Empty())
}

func TestPublicationCarryRefusesAnEntryWhoseContentDoesNotMatchTheRecord(t *testing.T) {
	target := carryTestTarget("retired", "carried")
	_, segment, material := carryTestEntries(t, target)
	material[0].Content = []byte("substituted content")
	accepted := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: [32]byte{0x62},
		PublicationID: [16]byte{0x51}, Segments: []publication.SnapshotSegment{segment},
	}
	acceptedMaterial := publicationstate.AcceptedMaterial{
		SnapshotRecord: []byte{0x01},
		Segments: []publicationstate.AcceptedMaterialSegment{{
			Summary: carryTestSummary(segment), Entries: material,
		}},
	}
	_, err := publicationCarryOf(
		accepted, acceptedMaterial, carryTestConfiguration("current", "navi"), nil,
	)
	require.ErrorIs(t, err, ErrPublicationCarry)
}

func TestPublicationCarryIgnoresAConfiguredTarget(t *testing.T) {
	target := carryTestTarget("retired", "carried")
	definition, segment := carryTestPacked(t, target)
	accepted := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: [32]byte{0x62},
		PublicationID: [16]byte{0x51}, Segments: []publication.SnapshotSegment{segment},
	}
	material := publicationstate.AcceptedMaterial{
		SnapshotRecord: []byte{0x01},
		Segments: []publicationstate.AcceptedMaterialSegment{{
			Summary: carryTestSummary(segment), Blob: definition.payload,
		}},
	}
	carry, err := publicationCarryOf(
		accepted, material, carryTestConfiguration("retired", "carried"), nil,
	)
	require.NoError(t, err)
	assert.True(t, carry.Empty())
}

func TestPublicationCarryRefusesWithoutTheAcceptedMaterialForASegment(t *testing.T) {
	target := carryTestTarget("retired", "carried")
	_, segment := carryTestPacked(t, target)
	accepted := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: [32]byte{0x62},
		PublicationID: [16]byte{0x51}, Segments: []publication.SnapshotSegment{segment},
	}
	_, err := publicationCarryOf(
		accepted,
		publicationstate.AcceptedMaterial{SnapshotRecord: []byte{0x01}},
		carryTestConfiguration("current", "navi"),
		nil,
	)
	require.ErrorIs(t, err, ErrPublicationCarry)
}

func TestPublicationDropRefusalRequiresASortedUniquePublishedSubset(t *testing.T) {
	first := carryTestTarget("first", "first")
	second := carryTestTarget("second", "second")
	accepted := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: [32]byte{0x62},
		PublicationID: [16]byte{0x51},
		Segments: []publication.SnapshotSegment{
			{Target: first, Form: publication.SegmentFormSettings},
			{Target: second, Form: publication.SegmentFormSettings},
		},
	}
	configuration := carryTestConfiguration("current", "navi")

	require.NoError(t, publicationDropRefusal([]string{"first"}, accepted, configuration))
	require.NoError(t, publicationDropRefusal(nil, accepted, configuration))
	require.ErrorIs(
		t, publicationDropRefusal([]string{"second", "first"}, accepted, configuration),
		ErrPublicationCarry, "an unsorted drop set was accepted",
	)
	require.ErrorIs(
		t, publicationDropRefusal([]string{"first", "first"}, accepted, configuration),
		ErrPublicationCarry, "a duplicated drop id was accepted",
	)
	require.ErrorIs(
		t, publicationDropRefusal([]string{"unknown"}, accepted, configuration),
		ErrPublicationCarry, "an unpublished drop id was accepted",
	)
	require.ErrorIs(
		t, publicationDropRefusal(
			[]string{"first", "second"}, accepted, config.Config{Version: config.Version},
		),
		ErrPublicationCarry, "a drop set that empties the union was accepted",
	)
	require.NoError(
		t, publicationDropRefusal([]string{"first", "second"}, accepted, configuration),
		"dropping every accepted target beside a new configured one was refused",
	)
}

func TestPublicationDropRefusalAllowsDroppingEveryAcceptedTargetWhenANewOneJoins(t *testing.T) {
	accepted := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: [32]byte{0x62},
		PublicationID: [16]byte{0x51},
		Segments: []publication.SnapshotSegment{{
			Target: carryTestTarget("first", "first"), Form: publication.SegmentFormSettings,
		}},
	}
	configuration := carryTestConfiguration("current", "navi")
	require.NoError(t, publicationDropRefusal([]string{"first"}, accepted, configuration))
}

func TestPublicationCarryComposesAnEmptyUnionAsARefusal(t *testing.T) {
	accepted := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: [32]byte{0x62},
		PublicationID: [16]byte{0x51},
		Segments: []publication.SnapshotSegment{{
			Target: carryTestTarget("first", "first"), Form: publication.SegmentFormSettings,
		}},
	}
	material := publicationstate.AcceptedMaterial{
		SnapshotRecord: []byte{0x01},
		Segments: []publicationstate.AcceptedMaterialSegment{{
			Summary: carryTestSummary(accepted.Segments[0]),
		}},
	}
	carry, err := publicationCarryOf(accepted, material, config.Config{Version: config.Version}, []string{"first"})
	require.NoError(t, err)
	assert.True(t, carry.Empty())
	snapshot := model.Snapshot{Version: model.SnapshotVersion}
	_, err = encodePublicationCandidateWithCarry(
		carryTestBinding(), snapshot, publicationstate.Floor{}, false, nil, carry, [16]byte{0x53},
	)
	require.ErrorIs(t, err, ErrPublicationCarry)
}

var _ = context.Background

func TestPublicationCarryOfRecordKeepsUnconfiguredSegmentsOnly(t *testing.T) {
	first := carryTestTarget("first", "first")
	second := carryTestTarget("second", "second")
	_, firstSegment := carryTestPacked(t, first)
	_, secondSegment := carryTestPacked(t, second)
	record := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: [32]byte{0x62},
		PublicationID: [16]byte{0x51},
		Segments:      []publication.SnapshotSegment{firstSegment, secondSegment},
	}
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)

	carry, err := PublicationCarryOfRecord(raw, carryTestConfiguration("first", "first"), nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"second"}, carry.TargetIDs())

	carry, err = PublicationCarryOfRecord(
		raw, carryTestConfiguration("first", "first"), []string{"second"},
	)
	require.NoError(t, err)
	assert.True(t, carry.Empty())

	_, err = PublicationCarryOfRecord([]byte{0x00}, carryTestConfiguration("first", "first"), nil)
	require.ErrorIs(t, err, ErrPublicationCarry)
}

func TestPublicationCarryOfRecordAndMaterialEncodeTheSameRecord(t *testing.T) {
	target := carryTestTarget("retired", "carried")
	definition, segment := carryTestPacked(t, target)
	record := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: [32]byte{0x62},
		PublicationID: [16]byte{0x51}, Segments: []publication.SnapshotSegment{segment},
	}
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	configuration := carryTestConfiguration("current", "navi")
	material := publicationstate.AcceptedMaterial{
		SnapshotRecord: raw,
		Segments: []publicationstate.AcceptedMaterialSegment{{
			Summary: carryTestSummary(segment), Blob: definition.payload,
		}},
	}
	verified, err := publicationCarryOf(record, material, configuration, nil)
	require.NoError(t, err)
	previewed, err := PublicationCarryOfRecord(raw, configuration, nil)
	require.NoError(t, err)

	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{carryTestTarget("current", "navi")},
	}
	binding := carryTestBinding()
	fromStore, err := encodePublicationCandidateWithCarry(
		binding, snapshot, publicationstate.Floor{}, false, nil, verified, [16]byte{0x53},
	)
	require.NoError(t, err)
	fromPreview, err := encodePublicationCandidateWithCarry(
		binding, snapshot, publicationstate.Floor{}, false, nil, previewed, [16]byte{0x53},
	)
	require.NoError(t, err)
	storeCID, err := publication.RecordCID(fromStore.SnapshotRecord)
	require.NoError(t, err)
	previewCID, err := publication.RecordCID(fromPreview.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, storeCID, previewCID, "the preview and the store carry produced different records")
	assert.Equal(t, fromStore.SnapshotRecord, fromPreview.SnapshotRecord)
}

func TestVerifyPublicationProposalRecordBindsTheDropSetToTheOmittedTargets(t *testing.T) {
	target := carryTestTarget("retired", "carried")
	_, segment := carryTestPacked(t, target)
	summaries := []publicationstate.SegmentSummary{carryTestSummary(segment)}
	carried, err := publicationstate.EncodeSegmentSummaries(summaries)
	require.NoError(t, err)
	record := PublicationProposalRecord{
		Version:    publicationProposalRecordVersion,
		Binding:    carryTestBinding(),
		DatabaseID: [32]byte{0x64}, Generation: 1, FloorRevision: 1,
		CandidateRecordCID: []byte{0x66}, Form: publication.PayloadFormPacked,
		Segments:       carried,
		Drop:           []string{"retired"},
		PayloadsDigest: [32]byte{0x67},
		Review: publicationstate.LocalReviewContext{
			SelectionDigest: [32]byte{0x68}, SelectionRevision: 1,
			ApprovalDigest: [32]byte{0x69}, ApprovalRevision: 1,
		},
		PublicationID: [16]byte{0x71}, Lifecycle: publicationstate.AttemptPrepared,
		Confirmation: [32]byte{0x6a},
	}
	require.Error(t, VerifyPublicationProposalRecord(record), "a drop id that the record still carries was accepted")

	record.Drop = []string{"elsewhere"}
	require.NoError(t, VerifyPublicationProposalRecord(record))
	record.Drop = []string{"twice", "twice"}
	require.Error(t, VerifyPublicationProposalRecord(record))
}
