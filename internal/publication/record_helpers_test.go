package publication

import "github.com/lamb-systems/dottie/internal/model"

func entriesOf(record SnapshotRecord) []SnapshotEntry {
	for _, segment := range record.Segments {
		if segment.Form == SegmentFormEntries {
			return segment.Entries
		}
	}
	return nil
}

func targetsOf(record SnapshotRecord) []model.Target {
	targets := make([]model.Target, 0, len(record.Segments))
	for _, segment := range record.Segments {
		targets = append(targets, segment.Target)
	}
	return targets
}

func blobOf(record SnapshotRecord) BlobReference {
	for _, segment := range record.Segments {
		if segment.Form == SegmentFormPacked {
			return segment.Blob
		}
	}
	return BlobReference{}
}
