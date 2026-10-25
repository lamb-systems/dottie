package vault

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/dottorblaster/dottie/internal/model"
)

const (
	Version        uint32 = 1
	CodecNone             = "none"
	manifestMember        = "000000"
	maxOrdinal            = 999999
)

type Limits struct {
	MaxEntries       int
	MaxDepth         int
	MaxEntryBytes    int64
	MaxTotalBytes    int64
	MaxManifestBytes int64
	MaxPathBytes     int
}

func DefaultLimits() Limits {
	return Limits{
		MaxEntries:       20000,
		MaxDepth:         32,
		MaxEntryBytes:    8 * 1024 * 1024,
		MaxTotalBytes:    256 * 1024 * 1024,
		MaxManifestBytes: 16 * 1024 * 1024,
		MaxPathBytes:     model.MaxRelativePathBytes,
	}
}

type Blob struct {
	Version        uint32
	Codec          string
	Payload        []byte
	Digest         [32]byte
	PlaintextBytes int64
	EntryCount     int
}

type BoundError struct {
	Kind     string
	Path     string
	Limit    int64
	Observed int64
}

func (e *BoundError) Error() string {
	return fmt.Sprintf("snapshot bound %s exceeded at %q: observed %d, limit %d", e.Kind, e.Path, e.Observed, e.Limit)
}

type TargetSize struct {
	TargetID string
	Bytes    int64
}

type SizeEstimate struct {
	Entries        int
	PlaintextBytes int64
	TargetSizes    []TargetSize
	EscapingLinks  []model.EntryKey
}

func Pack(snapshot model.Snapshot) (Blob, error) {
	return PackWithLimits(snapshot, DefaultLimits())
}

func PackWithLimits(snapshot model.Snapshot, limits Limits) (Blob, error) {
	prepared, err := prepare(snapshot, limits)
	if err != nil {
		return Blob{}, err
	}
	var payload bytes.Buffer
	writer := tar.NewWriter(&payload)
	if err := writeMember(writer, manifestMember, prepared.manifest); err != nil {
		return Blob{}, fmt.Errorf("write snapshot manifest: %w", err)
	}
	for _, item := range prepared.entries {
		if err := writeMember(writer, item.wire.Member, item.payload); err != nil {
			return Blob{}, fmt.Errorf("write snapshot entry %q: %w", entryPath(item.entry), err)
		}
	}
	if err := writer.Close(); err != nil {
		return Blob{}, fmt.Errorf("finish snapshot archive: %w", err)
	}
	encoded := payload.Bytes()
	return Blob{
		Version:        Version,
		Codec:          CodecNone,
		Payload:        encoded,
		Digest:         sha256.Sum256(encoded),
		PlaintextBytes: prepared.plaintextBytes,
		EntryCount:     len(prepared.entries),
	}, nil
}

func Unpack(blob Blob) (model.Snapshot, error) {
	return UnpackWithLimits(blob, DefaultLimits())
}

func UnpackWithLimits(blob Blob, limits Limits) (model.Snapshot, error) {
	if err := validateLimits(limits); err != nil {
		return model.Snapshot{}, err
	}
	if blob.Version != Version {
		return model.Snapshot{}, fmt.Errorf("unsupported snapshot blob version %d", blob.Version)
	}
	if blob.Codec != CodecNone {
		return model.Snapshot{}, fmt.Errorf("unsupported snapshot codec %q", blob.Codec)
	}
	reader := bytes.NewReader(blob.Payload)
	archive := tar.NewReader(reader)
	header, err := nextArchiveHeader(archive, reader, 0, true)
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("read snapshot manifest header: %w", err)
	}
	if header.Size < 0 {
		return model.Snapshot{}, errors.New("snapshot manifest has a negative tar size")
	}
	if header.Size > limits.MaxManifestBytes {
		return model.Snapshot{}, &BoundError{Kind: "MaxManifestBytes", Path: "manifest", Limit: limits.MaxManifestBytes, Observed: header.Size}
	}
	if err := checkHeader(header, manifestMember, header.Size); err != nil {
		return model.Snapshot{}, err
	}
	manifestBytes, err := io.ReadAll(io.LimitReader(archive, limits.MaxManifestBytes+1))
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("read snapshot manifest: %w", err)
	}
	if int64(len(manifestBytes)) > limits.MaxManifestBytes {
		return model.Snapshot{}, &BoundError{Kind: "MaxManifestBytes", Path: "manifest", Limit: limits.MaxManifestBytes, Observed: int64(len(manifestBytes))}
	}
	if int64(len(manifestBytes)) != header.Size {
		return model.Snapshot{}, errors.New("snapshot manifest size does not match its tar header")
	}
	manifest, err := decodeManifest(manifestBytes)
	if err != nil {
		return model.Snapshot{}, err
	}
	if manifest.Version != Version || manifest.Codec != CodecNone {
		return model.Snapshot{}, errors.New("unsupported snapshot manifest version or codec")
	}
	if len(manifest.Entries) > limits.MaxEntries {
		return model.Snapshot{}, &BoundError{Kind: "MaxEntries", Path: "manifest", Limit: int64(limits.MaxEntries), Observed: int64(len(manifest.Entries))}
	}
	if len(manifest.Entries) > maxOrdinal {
		return model.Snapshot{}, &BoundError{Kind: "MaxEntries", Path: "manifest", Limit: maxOrdinal, Observed: int64(len(manifest.Entries))}
	}
	if err := checkManifestBounds(manifest, limits); err != nil {
		return model.Snapshot{}, err
	}
	snapshot := model.Snapshot{Version: manifest.SnapshotVersion, Targets: append([]model.Target(nil), manifest.Targets...), Entries: make([]model.Entry, 0, len(manifest.Entries))}
	previousSize := header.Size
	var totalBytes int64
	var plaintextBytes int64
	var entryErrors []error
	for index, wire := range manifest.Entries {
		name := ordinal(index + 1)
		if wire.Member != name {
			return model.Snapshot{}, fmt.Errorf("manifest entry %d has noncanonical member ordinal %q", index, wire.Member)
		}
		header, err = nextArchiveHeader(archive, reader, previousSize, false)
		if err != nil {
			return model.Snapshot{}, fmt.Errorf("read snapshot member %q: %w", name, err)
		}
		logicalPath := wirePath(wire)
		if header.Size > limits.MaxEntryBytes {
			return model.Snapshot{}, &BoundError{Kind: "MaxEntryBytes", Path: logicalPath, Limit: limits.MaxEntryBytes, Observed: header.Size}
		}
		if err := checkHeader(header, name, wire.Size); err != nil {
			return model.Snapshot{}, fmt.Errorf("snapshot member %q: %w", name, err)
		}
		if wire.Size < 0 || wire.Size > limits.MaxEntryBytes {
			return model.Snapshot{}, &BoundError{Kind: "MaxEntryBytes", Path: logicalPath, Limit: limits.MaxEntryBytes, Observed: wire.Size}
		}
		content, err := io.ReadAll(io.LimitReader(archive, limits.MaxEntryBytes+1))
		if err != nil {
			return model.Snapshot{}, fmt.Errorf("read snapshot member %q: %w", name, err)
		}
		if int64(len(content)) > limits.MaxEntryBytes {
			return model.Snapshot{}, &BoundError{Kind: "MaxEntryBytes", Path: logicalPath, Limit: limits.MaxEntryBytes, Observed: int64(len(content))}
		}
		previousSize = header.Size
		if int64(len(content)) != header.Size || int64(len(content)) != wire.Size {
			return model.Snapshot{}, fmt.Errorf("snapshot member %q size does not match its manifest", name)
		}
		observedTotal := totalBytes + int64(len(content))
		if observedTotal > limits.MaxTotalBytes {
			return model.Snapshot{}, &BoundError{Kind: "MaxTotalBytes", Path: logicalPath, Limit: limits.MaxTotalBytes, Observed: observedTotal}
		}
		totalBytes = observedTotal
		if digestHex(content) != wire.SHA256 {
			return model.Snapshot{}, fmt.Errorf("snapshot entry digest mismatch at %q", logicalPath)
		}
		if wire.Source == model.SourceFiles && wire.State == string(model.FilePresent) && wire.Kind == model.FileRegular {
			plaintextBytes += int64(len(content))
		}
		entry, entryErr := entryFromWire(wire, content)
		if entryErr != nil {
			entryErrors = append(entryErrors, fmt.Errorf("invalid snapshot entry %q: %w", logicalPath, entryErr))
		}
		snapshot.Entries = append(snapshot.Entries, entry)
	}
	if _, err := nextArchiveHeader(archive, reader, previousSize, false); !errors.Is(err, io.EOF) {
		if err == nil {
			return model.Snapshot{}, errors.New("snapshot archive contains an unexpected member")
		}
		return model.Snapshot{}, fmt.Errorf("finish snapshot archive: %w", err)
	}
	if reader.Len() != 0 {
		return model.Snapshot{}, errors.New("snapshot archive contains trailing data")
	}
	if sha256.Sum256(blob.Payload) != blob.Digest {
		return model.Snapshot{}, errors.New("snapshot blob digest mismatch")
	}
	if err := snapshot.Validate(); err != nil {
		return model.Snapshot{}, fmt.Errorf("invalid unpacked snapshot: %w", err)
	}
	if len(entryErrors) > 0 {
		return model.Snapshot{}, entryErrors[0]
	}
	if blob.EntryCount != len(manifest.Entries) {
		return model.Snapshot{}, errors.New("snapshot entry count does not match blob metadata")
	}
	if blob.PlaintextBytes != plaintextBytes {
		return model.Snapshot{}, errors.New("snapshot plaintext size does not match blob metadata")
	}
	if !entriesCanonical(snapshot.Entries) {
		return model.Snapshot{}, errors.New("snapshot entries are not in canonical order")
	}
	if !targetsCanonical(snapshot.Targets) {
		return model.Snapshot{}, errors.New("snapshot targets are not in canonical order")
	}
	return snapshot, nil
}

func Estimate(snapshot model.Snapshot) (SizeEstimate, error) {
	return EstimateWithLimits(snapshot, DefaultLimits())
}

func EstimateWithLimits(snapshot model.Snapshot, limits Limits) (SizeEstimate, error) {
	prepared, err := prepare(snapshot, limits)
	if err != nil {
		return SizeEstimate{}, err
	}
	return SizeEstimate{
		Entries:        len(prepared.entries),
		PlaintextBytes: prepared.plaintextBytes,
		TargetSizes:    prepared.targetSizes,
		EscapingLinks:  prepared.escapingLinks,
	}, nil
}

type preparedEntry struct {
	entry   model.Entry
	wire    wireEntry
	payload []byte
}

type preparedSnapshot struct {
	entries        []preparedEntry
	manifest       []byte
	plaintextBytes int64
	targetSizes    []TargetSize
	escapingLinks  []model.EntryKey
}

func prepare(snapshot model.Snapshot, limits Limits) (preparedSnapshot, error) {
	if err := validateLimits(limits); err != nil {
		return preparedSnapshot{}, err
	}
	if err := snapshot.Validate(); err != nil {
		return preparedSnapshot{}, fmt.Errorf("invalid snapshot: %w", err)
	}
	if len(snapshot.Entries) > limits.MaxEntries {
		return preparedSnapshot{}, &BoundError{Kind: "MaxEntries", Path: "snapshot", Limit: int64(limits.MaxEntries), Observed: int64(len(snapshot.Entries))}
	}
	if len(snapshot.Entries) > maxOrdinal {
		return preparedSnapshot{}, &BoundError{Kind: "MaxEntries", Path: "snapshot", Limit: maxOrdinal, Observed: int64(len(snapshot.Entries))}
	}
	for _, target := range snapshot.Targets {
		if target.Root != nil {
			if err := checkPathBound(target.Root.Path, limits); err != nil {
				return preparedSnapshot{}, err
			}
		}
	}
	ordered := append([]model.Entry(nil), snapshot.Entries...)
	sortEntries(ordered)
	prepared := preparedSnapshot{entries: make([]preparedEntry, 0, len(ordered))}
	targetBytes := make(map[string]int64, len(snapshot.Targets))
	wireEntries := make([]wireEntry, 0, len(ordered))
	for index, entry := range ordered {
		wire, content, err := wireFromEntry(entry, ordinal(index+1))
		if err != nil {
			return preparedSnapshot{}, fmt.Errorf("cannot encode snapshot entry %q: %w", entryPath(entry), err)
		}
		path := wirePath(wire)
		if err := checkPathBound(path, limits); err != nil {
			return preparedSnapshot{}, err
		}
		if wire.Source == model.SourceFiles && wire.LinkTarget != "" {
			if len(wire.LinkTarget) > limits.MaxPathBytes {
				return preparedSnapshot{}, &BoundError{Kind: "MaxPathBytes", Path: path, Limit: int64(limits.MaxPathBytes), Observed: int64(len(wire.LinkTarget))}
			}
		}
		depthPath := path
		if wire.Source == model.SourceGNOME && path != "/" {
			depthPath = strings.Trim(path, "/")
		}
		depth := pathDepth(depthPath)
		if depth > limits.MaxDepth {
			return preparedSnapshot{}, &BoundError{Kind: "MaxDepth", Path: path, Limit: int64(limits.MaxDepth), Observed: int64(depth)}
		}
		if wire.Size > limits.MaxEntryBytes {
			return preparedSnapshot{}, &BoundError{Kind: "MaxEntryBytes", Path: path, Limit: limits.MaxEntryBytes, Observed: wire.Size}
		}
		observedTotal := prepared.plaintextBytes + wire.Size
		if observedTotal > limits.MaxTotalBytes {
			return preparedSnapshot{}, &BoundError{Kind: "MaxTotalBytes", Path: path, Limit: limits.MaxTotalBytes, Observed: observedTotal}
		}
		prepared.plaintextBytes = observedTotal
		targetBytes[entry.TargetID] += wire.Size
		if wire.Source == model.SourceFiles && wire.Kind == model.FileSymlink && linkEscapes(wire.Path, wire.LinkTarget) {
			prepared.escapingLinks = append(prepared.escapingLinks, entry.Identity())
		}
		prepared.entries = append(prepared.entries, preparedEntry{entry: entry, wire: wire, payload: content})
		wireEntries = append(wireEntries, wire)
	}
	targets := append([]model.Target{}, snapshot.Targets...)
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	prepared.targetSizes = make([]TargetSize, 0, len(targets))
	for _, target := range targets {
		prepared.targetSizes = append(prepared.targetSizes, TargetSize{TargetID: target.ID, Bytes: targetBytes[target.ID]})
	}
	manifest, err := encodeManifest(wireManifest{
		Version:         Version,
		Codec:           CodecNone,
		SnapshotVersion: snapshot.Version,
		Targets:         targets,
		Entries:         wireEntries,
	})
	if err != nil {
		return preparedSnapshot{}, fmt.Errorf("encode snapshot manifest: %w", err)
	}
	if int64(len(manifest)) > limits.MaxManifestBytes {
		return preparedSnapshot{}, &BoundError{Kind: "MaxManifestBytes", Path: "manifest", Limit: limits.MaxManifestBytes, Observed: int64(len(manifest))}
	}
	prepared.manifest = manifest
	return prepared, nil
}

func validateLimits(limits Limits) error {
	if limits.MaxEntries <= 0 || limits.MaxDepth < 0 || limits.MaxEntryBytes <= 0 || limits.MaxTotalBytes <= 0 || limits.MaxManifestBytes <= 0 || limits.MaxPathBytes <= 0 {
		return errors.New("snapshot limits must be positive, except MaxDepth may be zero")
	}
	if limits.MaxEntryBytes == int64(^uint64(0)>>1) || limits.MaxTotalBytes == int64(^uint64(0)>>1) || limits.MaxManifestBytes == int64(^uint64(0)>>1) {
		return errors.New("snapshot byte limit is too large")
	}
	return nil
}

func checkManifestBounds(manifest wireManifest, limits Limits) error {
	for _, target := range manifest.Targets {
		if target.Root != nil {
			if err := checkPathBound(target.Root.Path, limits); err != nil {
				return err
			}
		}
	}
	for _, wire := range manifest.Entries {
		path := wirePath(wire)
		if err := checkPathBound(path, limits); err != nil {
			return err
		}
		if len(wire.LinkTarget) > limits.MaxPathBytes {
			return &BoundError{Kind: "MaxPathBytes", Path: path, Limit: int64(limits.MaxPathBytes), Observed: int64(len(wire.LinkTarget))}
		}
		depthPath := path
		if wire.Source == model.SourceGNOME && path != "/" {
			depthPath = strings.Trim(path, "/")
		}
		depth := pathDepth(depthPath)
		if depth > limits.MaxDepth {
			return &BoundError{Kind: "MaxDepth", Path: path, Limit: int64(limits.MaxDepth), Observed: int64(depth)}
		}
		if wire.Size < 0 || wire.Size > limits.MaxEntryBytes {
			return &BoundError{Kind: "MaxEntryBytes", Path: path, Limit: limits.MaxEntryBytes, Observed: wire.Size}
		}
	}
	return nil
}

func checkPathBound(path string, limits Limits) error {
	if len(path) > limits.MaxPathBytes {
		return &BoundError{Kind: "MaxPathBytes", Path: path, Limit: int64(limits.MaxPathBytes), Observed: int64(len(path))}
	}
	return nil
}

func writeMember(writer *tar.Writer, name string, data []byte) error {
	header := &tar.Header{
		Name:       name,
		Mode:       0o600,
		Uid:        0,
		Gid:        0,
		Size:       int64(len(data)),
		ModTime:    time.Time{},
		Typeflag:   tar.TypeReg,
		Linkname:   "",
		Uname:      "",
		Gname:      "",
		Devmajor:   0,
		Devminor:   0,
		AccessTime: time.Time{},
		ChangeTime: time.Time{},
		Format:     tar.FormatUSTAR,
	}
	if err := writer.WriteHeader(header); err != nil {
		return err
	}
	_, err := writer.Write(data)
	return err
}

func nextArchiveHeader(archive *tar.Reader, input *bytes.Reader, previousSize int64, first bool) (*tar.Header, error) {
	before := input.Len()
	header, err := archive.Next()
	consumed := before - input.Len()
	expected := int(blockPadding(previousSize) + 512)
	if first {
		expected = 512
	} else if errors.Is(err, io.EOF) {
		expected = int(blockPadding(previousSize) + 1024)
	}
	if consumed != expected {
		return nil, fmt.Errorf("noncanonical tar framing: consumed %d bytes between members, want %d", consumed, expected)
	}
	return header, err
}

func blockPadding(size int64) int64 {
	if remainder := size % 512; remainder != 0 {
		return 512 - remainder
	}
	return 0
}

func checkHeader(header *tar.Header, name string, size int64) error {
	if header.Name != name {
		return fmt.Errorf("unexpected tar member name %q, want %q", header.Name, name)
	}
	if header.Typeflag != tar.TypeReg || header.Format != tar.FormatUSTAR {
		return fmt.Errorf("unsupported tar record type or format for member %q", name)
	}
	if header.Size != size {
		return fmt.Errorf("tar member %q size does not match its manifest", name)
	}
	if header.Mode != 0o600 || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" || header.Linkname != "" || header.Devmajor != 0 || header.Devminor != 0 {
		return fmt.Errorf("tar member %q has noncanonical header fields", name)
	}
	if header.ModTime.Unix() != 0 || header.ModTime.Nanosecond() != 0 || !header.AccessTime.IsZero() || !header.ChangeTime.IsZero() || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 {
		return fmt.Errorf("tar member %q has noncanonical metadata", name)
	}
	return nil
}

func sortEntries(entries []model.Entry) {
	sort.Slice(entries, func(i, j int) bool { return entryLess(entries[i], entries[j]) })
}

func entriesCanonical(entries []model.Entry) bool {
	for index := 1; index < len(entries); index++ {
		if !entryLess(entries[index-1], entries[index]) {
			return false
		}
	}
	return true
}

func entryLess(left, right model.Entry) bool {
	leftKey := left.Identity()
	rightKey := right.Identity()
	if leftKey.Source != rightKey.Source {
		return leftKey.Source < rightKey.Source
	}
	if leftKey.Source == model.SourceFiles {
		if leftKey.FilePath != rightKey.FilePath {
			return leftKey.FilePath < rightKey.FilePath
		}
	} else {
		if leftKey.SchemaID != rightKey.SchemaID {
			return leftKey.SchemaID < rightKey.SchemaID
		}
		if leftKey.SettingsPath != rightKey.SettingsPath {
			return leftKey.SettingsPath < rightKey.SettingsPath
		}
		if leftKey.SettingKey != rightKey.SettingKey {
			return leftKey.SettingKey < rightKey.SettingKey
		}
	}
	return leftKey.TargetID < rightKey.TargetID
}

func targetsCanonical(targets []model.Target) bool {
	for index := 1; index < len(targets); index++ {
		if targets[index-1].ID >= targets[index].ID {
			return false
		}
	}
	return true
}

func ordinal(number int) string {
	return fmt.Sprintf("%06d", number)
}

func digestHex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func wirePath(wire wireEntry) string {
	return wire.Path
}

func entryPath(entry model.Entry) string {
	if entry.File != nil {
		return entry.File.Path
	}
	if entry.Setting != nil {
		return entry.Setting.Path
	}
	return ""
}

func pathDepth(path string) int {
	if path == "." || path == "" || path == "/" {
		return 0
	}
	if strings.HasPrefix(path, "/") && strings.HasSuffix(path, "/") {
		return len(strings.Split(strings.Trim(path, "/"), "/"))
	}
	return strings.Count(path, "/") + 1
}

func linkEscapes(path, target string) bool {
	components := []string(nil)
	if path != "." {
		components = strings.Split(path, "/")
		components = components[:len(components)-1]
	}
	for _, component := range strings.Split(target, "/") {
		switch component {
		case "", ".":
		case "..":
			if len(components) == 0 {
				return true
			}
			components = components[:len(components)-1]
		default:
			components = append(components, component)
		}
	}
	return false
}
