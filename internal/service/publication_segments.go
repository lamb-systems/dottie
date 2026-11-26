package service

import (
	"bytes"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
)

func PublicationFloorMatchesRecord(
	floor publicationstate.Floor,
	record publication.SnapshotRecord,
) bool {
	return publicationFloorMatchesRecord(floor, record)
}

func publicationFloorMatchesRecord(
	floor publicationstate.Floor,
	record publication.SnapshotRecord,
) bool {
	if len(floor.Segments) != len(record.Segments) {
		return false
	}
	for index, segment := range record.Segments {
		summary := floor.Segments[index]
		if summary.TargetID != segment.Target.ID || publicationFormOfSegment(segment) != summary.Form {
			return false
		}
		switch segment.Form {
		case publication.SegmentFormPacked:
			if !bytes.Equal(summary.BlobCID, segment.Blob.CID) || summary.BlobSize != segment.Blob.Size ||
				len(summary.Entries) != 0 {
				return false
			}
		case publication.SegmentFormEntries:
			if len(summary.Entries) != len(segment.Entries) || len(summary.BlobCID) != 0 {
				return false
			}
			for entryIndex, entry := range segment.Entries {
				reference := summary.Entries[entryIndex]
				if reference.Path != entry.Path || reference.Size != entry.Size ||
					!bytes.Equal(reference.CID, entry.Blob.CID) {
					return false
				}
			}
		case publication.SegmentFormSettings:
			if summary.Settings != publication.SettingsDigest(segment.Settings) {
				return false
			}
		}
	}
	return true
}

func publicationFormOfSegment(segment publication.SnapshotSegment) publicationstate.PayloadForm {
	switch segment.Form {
	case publication.SegmentFormEntries:
		return publicationstate.PayloadFormFileSet
	case publication.SegmentFormSettings:
		return publicationstate.PayloadFormSettings
	default:
		return publicationstate.PayloadFormPacked
	}
}

func acceptedSnapshotFromSegments(
	record publication.SnapshotRecord,
	material publicationstate.AcceptedMaterial,
) (model.Snapshot, error) {
	snapshot := model.Snapshot{Version: model.SnapshotVersion}
	segments := make(map[string]publicationstate.AcceptedMaterialSegment, len(material.Segments))
	for _, segment := range material.Segments {
		segments[segment.Summary.TargetID] = segment
	}
	for _, segment := range record.Segments {
		materialSegment, present := segments[segment.Target.ID]
		if !present {
			return model.Snapshot{}, publication.ErrInvalidRecord
		}
		switch segment.Form {
		case publication.SegmentFormPacked:
			packed, err := publication.DecodePayload(materialSegment.Blob, segment.Blob)
			if err != nil {
				return model.Snapshot{}, err
			}
			snapshot.Targets = append(snapshot.Targets, packed.Targets...)
			snapshot.Entries = append(snapshot.Entries, packed.Entries...)
		case publication.SegmentFormEntries:
			entries := make([]publication.PayloadEntry, 0, len(materialSegment.Entries))
			for _, entry := range materialSegment.Entries {
				entries = append(entries, publication.PayloadEntry{
					Path: entry.Path, Mode: entry.Mode, Size: uint64(len(entry.Content)),
					Content: bytes.Clone(entry.Content),
				})
			}
			projected, err := fileSetProjection(segment.Target, entries)
			if err != nil {
				return model.Snapshot{}, err
			}
			snapshot.Targets = append(snapshot.Targets, projected.Targets...)
			snapshot.Entries = append(snapshot.Entries, projected.Entries...)
		case publication.SegmentFormSettings:
			snapshot.Targets = append(snapshot.Targets, segment.Target)
			for _, setting := range segment.Settings {
				snapshot.Entries = append(snapshot.Entries, model.Entry{
					TargetID: segment.Target.ID,
					Setting: &model.SettingEntry{
						SchemaID: setting.SchemaID, Path: setting.Path, Key: setting.Key,
						State: setting.State, Value: setting.Value,
					},
				})
			}
		default:
			return model.Snapshot{}, publication.ErrInvalidRecord
		}
	}
	return snapshot, nil
}
