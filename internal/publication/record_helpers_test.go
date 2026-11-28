package publication

func entriesOf(record SnapshotRecord) []SnapshotEntry {
	for _, segment := range record.Segments {
		if segment.Form == SegmentFormEntries {
			return segment.Entries
		}
	}
	return nil
}

func blobOf(record SnapshotRecord) BlobReference {
	for _, segment := range record.Segments {
		if segment.Form == SegmentFormPacked {
			return segment.Blob
		}
	}
	return BlobReference{}
}
