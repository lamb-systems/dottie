package publication

import (
	"errors"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"

	"github.com/lamb-systems/dottie/internal/model"
)

const (
	MaxSnapshotEntries    = 64
	MaxEntryPathBytes     = 1024
	SnapshotEntryKindFile = "file"

	maxEntryModeBits       = 0o777
	entryModePrivate       = 0o600
	entryModeShared        = 0o644
	maxShowcaseRecordBytes = 1 << 20
)

var ErrShowcaseEntryUnsupported = errors.New("publication showcase entry unsupported")

type ShowcaseEntryError struct {
	Entry  model.EntryKey
	Field  string
	Reason string
	cause  error
}

func (e *ShowcaseEntryError) Error() string {
	return "publication showcase entry: " + e.Field + ": " + e.Reason
}

func (e *ShowcaseEntryError) Is(target error) bool { return target == ErrShowcaseEntryUnsupported }

func (e *ShowcaseEntryError) Unwrap() error { return e.cause }

type SnapshotEntry struct {
	Path string
	Mode uint32
	Size uint64
	Kind string
	Blob BlobReference
}

func SnapshotEntries(snapshot model.Snapshot) ([]SnapshotEntry, error) {
	entries := make([]SnapshotEntry, 0, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		representable, err := snapshotEntry(entry)
		if err != nil {
			return nil, showcaseEntryViolationFor(entry, err)
		}
		entries = append(entries, representable)
	}
	slices.SortFunc(entries, func(left, right SnapshotEntry) int {
		return strings.Compare(left.Path, right.Path)
	})
	if err := validateEntries(entries); err != nil {
		return nil, showcaseEntryViolation(err)
	}
	return entries, nil
}

func snapshotEntry(entry model.Entry) (SnapshotEntry, error) {
	if entry.Setting != nil {
		return SnapshotEntry{}, violation(ErrShowcaseEntryUnsupported, "entries.setting", "unsupported")
	}
	file := entry.File
	if file == nil {
		return SnapshotEntry{}, violation(ErrShowcaseEntryUnsupported, "entries.entry", "unsupported")
	}
	switch file.State {
	case model.FileDeleted:
		return SnapshotEntry{}, violation(ErrShowcaseEntryUnsupported, "entries.deleted", "unsupported")
	case model.FilePresent:
	default:
		return SnapshotEntry{}, violation(ErrShowcaseEntryUnsupported, "entries.state", "unsupported")
	}
	switch file.Kind {
	case model.FileRegular:
	case model.FileDirectory:
		return SnapshotEntry{}, violation(ErrShowcaseEntryUnsupported, "entries.directory", "unsupported")
	case model.FileSymlink:
		return SnapshotEntry{}, violation(ErrShowcaseEntryUnsupported, "entries.symlink", "unsupported")
	default:
		return SnapshotEntry{}, violation(ErrShowcaseEntryUnsupported, "entries.kind", "unsupported")
	}
	if len(file.Content) == 0 {
		return SnapshotEntry{}, violation(ErrShowcaseEntryUnsupported, "entries.size", "empty")
	}
	blobCID, err := RawPayloadCID(file.Content)
	if err != nil {
		return SnapshotEntry{}, err
	}
	size := uint64(len(file.Content))
	return SnapshotEntry{
		Path: file.Path,
		Mode: file.Mode,
		Size: size,
		Kind: SnapshotEntryKindFile,
		Blob: BlobReference{CID: blobCID, Size: size, MIMEType: BlobMIMEType},
	}, nil
}

func validateEntries(entries []SnapshotEntry) error {
	if len(entries) == 0 {
		return violation(ErrInvalidRecord, "entries", "empty")
	}
	if len(entries) > MaxSnapshotEntries {
		return violation(ErrInvalidRecord, "entries", "count")
	}
	previous := ""
	for index, entry := range entries {
		if index > 0 {
			if entry.Path == previous {
				return violation(ErrInvalidRecord, "entries.path", "duplicate")
			}
			if entry.Path < previous {
				return violation(ErrInvalidRecord, "entries.path", "order")
			}
		}
		if err := validateEntry(entry); err != nil {
			return err
		}
		previous = entry.Path
	}
	return nil
}

func validateEntry(entry SnapshotEntry) error {
	if err := validateEntryPath(entry.Path); err != nil {
		return err
	}
	if entry.Kind != SnapshotEntryKindFile {
		return violation(ErrInvalidRecord, "entries.kind", "unsupported")
	}
	if !supportedEntryMode(entry.Mode) {
		return violation(ErrInvalidRecord, "entries.mode", "unsupported")
	}
	if entry.Size == 0 || entry.Size > MaxBlobBytes {
		return violation(ErrInvalidRecord, "entries.size", "range")
	}
	if entry.Blob.Size != entry.Size {
		return violation(ErrInvalidRecord, "entries.size", "mismatch")
	}
	if !supportedEntryBlobMIMEType(entry.Blob.MIMEType) {
		return violation(ErrInvalidRecord, "entries.blob.mimeType", "unsupported")
	}
	if _, err := castCID(entry.Blob.CID, cid.Raw, "entries.blob.ref"); err != nil {
		return err
	}
	return nil
}

func validateEntryPath(path string) error {
	if len(path) == 0 || len(path) > MaxEntryPathBytes {
		return violation(ErrInvalidRecord, "entries.path", "length")
	}
	if !utf8.ValidString(path) || strings.ContainsRune(path, '\x00') || strings.ContainsRune(path, '\\') {
		return violation(ErrInvalidRecord, "entries.path", "text")
	}
	if strings.HasPrefix(path, "/") || entryPathDrivePrefix(path) {
		return violation(ErrInvalidRecord, "entries.path", "absolute")
	}
	for segment := range strings.SplitSeq(path, "/") {
		if segment == "" {
			return violation(ErrInvalidRecord, "entries.path", "empty_segment")
		}
		if segment == "." || segment == ".." {
			return violation(ErrInvalidRecord, "entries.path", "dot_segment")
		}
	}
	return nil
}

func entryPathDrivePrefix(path string) bool {
	if len(path) < 2 || path[1] != ':' {
		return false
	}
	return (path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z')
}

func supportedEntryMode(mode uint32) bool {
	switch mode {
	case entryModePrivate, entryModeShared:
		return true
	default:
		return false
	}
}

func supportedEntryBlobMIMEType(mimeType string) bool {
	switch mimeType {
	case BlobMIMEType, SnapshotBlobMIMEType:
		return true
	default:
		return false
	}
}

func encodeSnapshotEntries(entries []SnapshotEntry) ([]any, error) {
	encoded := make([]any, 0, len(entries))
	for _, entry := range entries {
		blobCID, err := castCID(entry.Blob.CID, cid.Raw, "entries.blob.ref")
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, map[string]any{
			"path": entry.Path,
			"mode": int64(entry.Mode),
			"size": int64(entry.Size),
			"kind": entry.Kind,
			"blob": atdata.Blob{
				Ref:      atdata.CIDLink(blobCID),
				MimeType: entry.Blob.MIMEType,
				Size:     int64(entry.Blob.Size),
			},
		})
	}
	return encoded, nil
}

func decodeSnapshotEntries(value any) ([]SnapshotEntry, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, violation(ErrInvalidRecord, "entries", "type")
	}
	entries := make([]SnapshotEntry, 0, len(items))
	for _, item := range items {
		entry, err := decodeSnapshotEntry(item)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func decodeSnapshotEntry(value any) (SnapshotEntry, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return SnapshotEntry{}, violation(ErrInvalidRecord, "entries", "type")
	}
	if err := exactKeys(object, "path", "mode", "size", "kind", "blob"); err != nil {
		return SnapshotEntry{}, err
	}
	path, ok := object["path"].(string)
	if !ok {
		return SnapshotEntry{}, violation(ErrInvalidRecord, "entries.path", "type")
	}
	mode, ok := unsignedInteger(object["mode"])
	if !ok || mode > maxEntryModeBits {
		return SnapshotEntry{}, violation(ErrInvalidRecord, "entries.mode", "range")
	}
	size, ok := unsignedInteger(object["size"])
	if !ok || size == 0 || size > MaxBlobBytes {
		return SnapshotEntry{}, violation(ErrInvalidRecord, "entries.size", "range")
	}
	kind, ok := object["kind"].(string)
	if !ok {
		return SnapshotEntry{}, violation(ErrInvalidRecord, "entries.kind", "type")
	}
	if kind != SnapshotEntryKindFile {
		return SnapshotEntry{}, violation(ErrInvalidRecord, "entries.kind", "unsupported")
	}
	blob, ok := object["blob"].(atdata.Blob)
	if !ok {
		return SnapshotEntry{}, violation(ErrInvalidRecord, "entries.blob", "type")
	}
	if !supportedEntryBlobMIMEType(blob.MimeType) {
		return SnapshotEntry{}, violation(ErrInvalidRecord, "entries.blob.mimeType", "unsupported")
	}
	if blob.Size <= 0 || uint64(blob.Size) > MaxBlobBytes {
		return SnapshotEntry{}, violation(ErrInvalidRecord, "entries.blob.size", "range")
	}
	blobCID, err := validateCID(blob.Ref.CID().Bytes(), cid.Raw, "entries.blob.ref")
	if err != nil {
		return SnapshotEntry{}, err
	}
	return SnapshotEntry{
		Path: path,
		Mode: uint32(mode),
		Size: size,
		Kind: kind,
		Blob: BlobReference{CID: blobCID.Bytes(), Size: uint64(blob.Size), MIMEType: blob.MimeType},
	}, nil
}

func showcaseEntryViolation(err error) error {
	if violationErr, ok := errors.AsType[*ViolationError](err); ok {
		return violation(ErrShowcaseEntryUnsupported, violationErr.Field(), violationErr.Reason())
	}
	return err
}

func showcaseEntryViolationFor(entry model.Entry, err error) error {
	violationErr, ok := errors.AsType[*ViolationError](err)
	if !ok {
		return err
	}
	return &ShowcaseEntryError{
		Entry: entry.Identity(), Field: violationErr.Field(), Reason: violationErr.Reason(), cause: err,
	}
}
