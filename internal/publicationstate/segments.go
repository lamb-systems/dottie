package publicationstate

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/lamb-systems/dottie/internal/publication"
)

const maxSegmentSummariesBytes = 2 << 20

type SegmentSummary struct {
	TargetID string
	Form     PayloadForm
	BlobCID  []byte
	BlobSize uint64
	Entries  []PayloadEntryReference
	Settings [32]byte
}

type CandidateSegment struct {
	TargetID       string
	Form           PayloadForm
	Blob           *publication.BlobReference
	Entries        []PayloadEntryReference
	SettingsDigest [32]byte
}

func candidateSummary(segment CandidateSegment) (SegmentSummary, error) {
	summary := SegmentSummary{TargetID: segment.TargetID, Form: segment.Form}
	switch segment.Form {
	case PayloadFormPacked:
		if segment.Blob == nil || len(segment.Entries) != 0 || segment.SettingsDigest != ([32]byte{}) {
			return SegmentSummary{}, errors.New("packed candidate segment")
		}
		summary.BlobCID = bytes.Clone(segment.Blob.CID)
		summary.BlobSize = segment.Blob.Size
	case PayloadFormFileSet:
		if segment.Blob != nil || len(segment.Entries) == 0 || segment.SettingsDigest != ([32]byte{}) {
			return SegmentSummary{}, errors.New("entries candidate segment")
		}
		summary.Entries = append([]PayloadEntryReference(nil), segment.Entries...)
	case PayloadFormSettings:
		if segment.Blob != nil || len(segment.Entries) != 0 || segment.SettingsDigest == ([32]byte{}) {
			return SegmentSummary{}, errors.New("settings candidate segment")
		}
		summary.Settings = segment.SettingsDigest
	default:
		return SegmentSummary{}, errors.New("candidate segment form")
	}
	return summary, nil
}

func validateSegmentSummaries(summaries []SegmentSummary) error {
	if len(summaries) == 0 || len(summaries) > publication.MaxSnapshotSettings {
		return errors.New("segment summary count")
	}
	previous := ""
	for index, summary := range summaries {
		if index > 0 && (summary.TargetID == previous || summary.TargetID < previous) {
			return errors.New("segment summary order")
		}
		switch summary.Form {
		case PayloadFormPacked:
			if len(summary.BlobCID) == 0 || summary.BlobSize == 0 ||
				len(summary.Entries) != 0 || summary.Settings != ([32]byte{}) {
				return errors.New("packed segment summary")
			}
		case PayloadFormFileSet:
			if len(summary.BlobCID) != 0 || summary.BlobSize != 0 ||
				len(summary.Entries) == 0 || summary.Settings != ([32]byte{}) {
				return errors.New("entries segment summary")
			}
		case PayloadFormSettings:
			if len(summary.BlobCID) != 0 || summary.BlobSize != 0 ||
				len(summary.Entries) != 0 || summary.Settings == ([32]byte{}) {
				return errors.New("settings segment summary")
			}
		default:
			return errors.New("segment summary form")
		}
		previous = summary.TargetID
	}
	return nil
}

type segmentSummaryWire struct {
	TargetID string                      `json:"target_id"`
	Form     string                      `json:"form"`
	BlobCID  string                      `json:"blob_cid,omitempty"`
	BlobSize uint64                      `json:"blob_size,omitempty"`
	Entries  []PayloadEntryReferenceWire `json:"entries,omitempty"`
	Settings string                      `json:"settings,omitempty"`
}

type PayloadEntryReferenceWire struct {
	Path string `json:"path"`
	CID  string `json:"cid"`
	Size uint64 `json:"size"`
}

func encodeSegmentSummaries(summaries []SegmentSummary) ([]byte, error) {
	if err := validateSegmentSummaries(summaries); err != nil {
		return nil, err
	}
	wire := make([]segmentSummaryWire, 0, len(summaries))
	for _, summary := range summaries {
		item := segmentSummaryWire{
			TargetID: summary.TargetID, Form: string(summary.Form),
			BlobCID: hex.EncodeToString(summary.BlobCID), BlobSize: summary.BlobSize,
		}
		if summary.Settings != ([32]byte{}) {
			item.Settings = hex.EncodeToString(summary.Settings[:])
		}
		for _, entry := range summary.Entries {
			item.Entries = append(item.Entries, PayloadEntryReferenceWire{
				Path: entry.Path, CID: hex.EncodeToString(entry.CID), Size: entry.Size,
			})
		}
		wire = append(wire, item)
	}
	return json.Marshal(wire)
}

func decodeSegmentSummaries(encoded []byte) ([]SegmentSummary, error) {
	var wire []segmentSummaryWire
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return nil, err
	}
	if decoder.More() {
		return nil, errors.New("trailing segment summary data")
	}
	summaries := make([]SegmentSummary, 0, len(wire))
	for _, item := range wire {
		summary := SegmentSummary{TargetID: item.TargetID, Form: PayloadForm(item.Form), BlobSize: item.BlobSize}
		if item.BlobCID != "" {
			cid, err := hex.DecodeString(item.BlobCID)
			if err != nil {
				return nil, err
			}
			summary.BlobCID = cid
		}
		if item.Settings != "" {
			settings, err := hex.DecodeString(item.Settings)
			if err != nil || len(settings) != 32 {
				return nil, errors.New("settings digest")
			}
			copy(summary.Settings[:], settings)
		}
		for _, entry := range item.Entries {
			cid, err := hex.DecodeString(entry.CID)
			if err != nil {
				return nil, err
			}
			summary.Entries = append(summary.Entries, PayloadEntryReference{
				Path: entry.Path, CID: cid, Size: entry.Size,
			})
		}
		summaries = append(summaries, summary)
	}
	if err := validateSegmentSummaries(summaries); err != nil {
		return nil, err
	}
	return summaries, nil
}

func segmentSummariesToWire(summaries []SegmentSummary) []segmentSummaryWire {
	wire := make([]segmentSummaryWire, 0, len(summaries))
	for _, summary := range summaries {
		item := segmentSummaryWire{
			TargetID: summary.TargetID, Form: string(summary.Form),
			BlobCID: hex.EncodeToString(summary.BlobCID), BlobSize: summary.BlobSize,
		}
		if summary.Settings != ([32]byte{}) {
			item.Settings = hex.EncodeToString(summary.Settings[:])
		}
		for _, entry := range summary.Entries {
			item.Entries = append(item.Entries, PayloadEntryReferenceWire{
				Path: entry.Path, CID: hex.EncodeToString(entry.CID), Size: entry.Size,
			})
		}
		wire = append(wire, item)
	}
	return wire
}

func segmentSummariesFromWire(wire []segmentSummaryWire) ([]SegmentSummary, error) {
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, err
	}
	return decodeSegmentSummaries(encoded)
}

func summariesOfRecord(segments []publication.SnapshotSegment) []SegmentSummary {
	summaries := make([]SegmentSummary, 0, len(segments))
	for _, segment := range segments {
		summary := SegmentSummary{TargetID: segment.Target.ID, Form: PayloadForm(segment.Form)}
		if segment.Form == publication.SegmentFormEntries {
			summary.Form = PayloadFormFileSet
			for _, entry := range segment.Entries {
				summary.Entries = append(summary.Entries, PayloadEntryReference{
					Path: entry.Path, CID: bytes.Clone(entry.Blob.CID), Size: entry.Size,
				})
			}
		}
		if segment.Form == publication.SegmentFormSettings {
			summary.Form = PayloadFormSettings
			summary.Settings = publication.SettingsDigest(segment.Settings)
		}
		if segment.Form == publication.SegmentFormPacked {
			summary.Form = PayloadFormPacked
			summary.BlobCID = bytes.Clone(segment.Blob.CID)
			summary.BlobSize = segment.Blob.Size
		}
		summaries = append(summaries, summary)
	}
	return summaries
}

func cloneSegmentSummaries(summaries []SegmentSummary) []SegmentSummary {
	cloned := make([]SegmentSummary, 0, len(summaries))
	for _, summary := range summaries {
		copied := SegmentSummary{
			TargetID: summary.TargetID,
			Form:     summary.Form,
			BlobCID:  bytes.Clone(summary.BlobCID),
			BlobSize: summary.BlobSize,
			Settings: summary.Settings,
		}
		for _, entry := range summary.Entries {
			copied.Entries = append(copied.Entries, PayloadEntryReference{
				Path: entry.Path, CID: bytes.Clone(entry.CID), Size: entry.Size,
			})
		}
		cloned = append(cloned, copied)
	}
	return cloned
}

func EncodeSegmentSummaries(summaries []SegmentSummary) ([]byte, error) {
	return encodeSegmentSummaries(summaries)
}

func DecodeSegmentSummaries(encoded []byte) ([]SegmentSummary, error) {
	return decodeSegmentSummaries(encoded)
}
