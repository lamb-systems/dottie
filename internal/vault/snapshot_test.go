package vault

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/dottorblaster/dottie/internal/model"
)

func TestRoundTripAcrossTargetsSettingsAndTombstones(t *testing.T) {
	first := fileTarget("first", "first-config", model.SelectionDirectory)
	second := fileTarget("second", "second-config", model.SelectionDirectory)
	settingsTarget := model.Target{ID: "settings", Source: model.SourceGNOME, SourceVersion: model.SourceVersion}
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{second, settingsTarget, first},
		Entries: []model.Entry{
			fileEntry("first", "init.lua", model.FileRegular, model.FilePresent, []byte("one")),
			fileEntry("second", "init.lua", model.FileRegular, model.FilePresent, []byte("two")),
			fileEntry("first", "empty", model.FileRegular, model.FilePresent, []byte{}),
			{TargetID: "settings", Setting: &model.SettingEntry{SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "theme", State: model.SettingPresent, Value: &model.VariantValue{Type: "s", Text: "'dark'"}}},
			{TargetID: "settings", Setting: &model.SettingEntry{SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "enabled", State: model.SettingReset}},
			fileEntry("first", "old.lua", "", model.FileDeleted, nil),
		},
	}
	requireNoError(t, snapshot.Validate())
	blob, err := Pack(snapshot)
	requireNoError(t, err)
	got, err := Unpack(blob)
	requireNoError(t, err)
	expected := canonicalSnapshot(snapshot)
	if !equalSnapshots(got, expected) {
		t.Fatalf("round trip mismatch\ngot: %#v\nwant: %#v", got, expected)
	}
	for _, entry := range got.Entries {
		if entry.File != nil && entry.File.Path == "empty" && entry.File.Content == nil {
			t.Fatal("present empty regular file lost its non-nil content")
		}
	}
}

func TestSingleFileTargetsBothUseDot(t *testing.T) {
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{fileTarget("one", "one.txt", model.SelectionFile), fileTarget("two", "two.txt", model.SelectionFile)},
		Entries: []model.Entry{fileEntry("one", ".", model.FileRegular, model.FilePresent, []byte("1")), fileEntry("two", ".", model.FileRegular, model.FilePresent, []byte("2"))},
	}
	got := mustRoundTrip(t, snapshot)
	if len(got.Entries) != 2 || got.Entries[0].Identity() == got.Entries[1].Identity() {
		t.Fatalf("single-file identities were not distinct: %#v", got.Entries)
	}
}

func TestPackDoesNotInventTombstonesAndOrdersThem(t *testing.T) {
	empty := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{fileTarget("files", "config", model.SelectionDirectory)}}
	blob, err := Pack(empty)
	requireNoError(t, err)
	unpacked, err := Unpack(blob)
	requireNoError(t, err)
	if len(unpacked.Entries) != 0 {
		t.Fatalf("empty snapshot acquired entries: %#v", unpacked.Entries)
	}
	empty.Entries = []model.Entry{
		fileEntry("files", "z", "", model.FileDeleted, nil),
		fileEntry("files", "a", "", model.FileDeleted, nil),
		fileEntry("files", "m", "", model.FileDeleted, nil),
	}
	got := mustRoundTrip(t, empty)
	paths := []string{got.Entries[0].File.Path, got.Entries[1].File.Path, got.Entries[2].File.Path}
	if strings.Join(paths, ",") != "a,m,z" {
		t.Fatalf("tombstones are not in canonical order: %v", paths)
	}
	for _, entry := range got.Entries {
		if entry.File.State != model.FileDeleted || entry.File.Content != nil {
			t.Fatalf("tombstone was changed: %#v", entry)
		}
	}
}

func TestDuplicateIdentitiesRejectedByPackAndUnpack(t *testing.T) {
	duplicate := fileEntry("files", "same", model.FileRegular, model.FilePresent, []byte("x"))
	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{fileTarget("files", "config", model.SelectionDirectory)}, Entries: []model.Entry{duplicate, duplicate}}
	if _, err := Pack(snapshot); err == nil {
		t.Fatal("Pack accepted duplicate identities")
	}
	deleted := fileEntry("files", "same", "", model.FileDeleted, nil)
	first, _, err := wireFromEntry(deleted, ordinal(1))
	requireNoError(t, err)
	second := first
	second.Member = ordinal(2)
	manifest := wireManifest{Version: Version, Codec: CodecNone, SnapshotVersion: model.SnapshotVersion, Targets: []model.Target{fileTarget("files", "config", model.SelectionDirectory)}, Entries: []wireEntry{first, second}}
	blob := blobFromManifest(t, manifest, [][]byte{nil, nil}, 0)
	if _, err := Unpack(blob); err == nil || !strings.Contains(err.Error(), "duplicate entry identity") {
		t.Fatalf("Unpack did not reject duplicate identities: %v", err)
	}
}

func TestPortablePathsUseOpaqueOrdinals(t *testing.T) {
	longComponent := strings.Repeat("a", 101)
	threeParts := []string{strings.Repeat("b", 100), strings.Repeat("c", 99), strings.Repeat("d", 99)}
	threeHundred := strings.Join(threeParts, "/")
	longParts := make([]string, 32)
	for index := range longParts {
		length := 128
		if index == len(longParts)-1 {
			length = 97
		}
		longParts[index] = strings.Repeat("x", length)
	}
	fourThousandNinetySix := strings.Join(longParts, "/")
	if len(threeHundred) != 300 || len(fourThousandNinetySix) != 4096 {
		t.Fatalf("bad test paths: nested=%d maximum=%d", len(threeHundred), len(fourThousandNinetySix))
	}
	entries := []model.Entry{
		fileEntry("files", "配置/主题.lua", model.FileRegular, model.FilePresent, []byte("unicode")),
		fileEntry("files", longComponent, model.FileRegular, model.FilePresent, []byte("component")),
		fileEntry("files", threeHundred, model.FileRegular, model.FilePresent, []byte("nested")),
		fileEntry("files", fourThousandNinetySix, model.FileRegular, model.FilePresent, []byte("maximum")),
	}
	for _, path := range []string{"配置/主题.lua", threeHundred, fourThousandNinetySix} {
		entries = appendParentDirectories(entries, "files", path)
	}
	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{fileTarget("files", "config", model.SelectionDirectory)}, Entries: entries}
	if len(longComponent) != 101 {
		t.Fatal("test component is not 101 bytes")
	}
	got := mustRoundTrip(t, snapshot)
	if !equalSnapshots(got, canonicalSnapshot(snapshot)) {
		t.Fatal("opaque ordinal archive did not preserve long and Unicode paths")
	}
	limits := DefaultLimits()
	limits.MaxPathBytes = 100
	_, err := EstimateWithLimits(snapshot, limits)
	requireBound(t, err, "MaxPathBytes", 100, 101)
	blob, err := Pack(snapshot)
	requireNoError(t, err)
	_, err = UnpackWithLimits(blob, limits)
	requireBound(t, err, "MaxPathBytes", 100, 101)
}

func TestDepth32AcceptedAndDepth33Rejected(t *testing.T) {
	path32 := strings.Join(repeatParts(32, "d"), "/")
	entries32 := nestedEntries("files", path32)
	snapshot32 := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{fileTarget("files", "config", model.SelectionDirectory)}, Entries: entries32}
	blob32, err := Pack(snapshot32)
	if err != nil {
		t.Fatalf("depth 32 rejected: %v", err)
	}
	if _, err := Unpack(blob32); err != nil {
		t.Fatalf("Unpack rejected depth 32: %v", err)
	}
	path33 := strings.Join(repeatParts(33, "e"), "/")
	entries33 := nestedEntries("files", path33)
	snapshot33 := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{fileTarget("files", "config", model.SelectionDirectory)}, Entries: entries33}
	_, err = Pack(snapshot33)
	requireBound(t, err, "MaxDepth", 32, 33)
	_, err = Estimate(snapshot33)
	requireBound(t, err, "MaxDepth", 32, 33)
	limits := DefaultLimits()
	limits.MaxDepth = 33
	blob33, err := PackWithLimits(snapshot33, limits)
	requireNoError(t, err)
	_, err = Unpack(blob33)
	requireBound(t, err, "MaxDepth", 32, 33)
}

func TestBoundsOnPackEstimateAndUnpack(t *testing.T) {
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{fileTarget("z", "z-config", model.SelectionDirectory), fileTarget("a", "a-config", model.SelectionDirectory)},
		Entries: []model.Entry{fileEntry("z", "z.txt", model.FileRegular, model.FilePresent, []byte("123")), fileEntry("a", "a.txt", model.FileRegular, model.FilePresent, []byte("4567"))},
	}
	limits := DefaultLimits()
	limits.MaxTotalBytes = 7
	limits.MaxEntryBytes = 4
	estimate, err := EstimateWithLimits(snapshot, limits)
	requireNoError(t, err)
	if estimate.Entries != 2 || estimate.PlaintextBytes != 7 || len(estimate.TargetSizes) != 2 || estimate.TargetSizes[0] != (TargetSize{TargetID: "a", Bytes: 4}) || estimate.TargetSizes[1] != (TargetSize{TargetID: "z", Bytes: 3}) {
		t.Fatalf("unexpected independently computed estimate: %#v", estimate)
	}
	blob, err := PackWithLimits(snapshot, limits)
	requireNoError(t, err)
	if blob.PlaintextBytes != 7 {
		t.Fatalf("pack total disagrees with independent expectation: %d", blob.PlaintextBytes)
	}
	if _, err := UnpackWithLimits(blob, limits); err != nil {
		t.Fatalf("unpack rejected exact-boundary payload: %v", err)
	}
	limits.MaxEntries = 1
	_, err = UnpackWithLimits(blob, limits)
	requireBound(t, err, "MaxEntries", 1, 2)
	limits = DefaultLimits()
	limits.MaxTotalBytes = 6
	_, err = UnpackWithLimits(blob, limits)
	requireBound(t, err, "MaxTotalBytes", 6, 7)
	limits.MaxTotalBytes = 6
	_, estimateErr := EstimateWithLimits(snapshot, limits)
	estimateBound := requireBound(t, estimateErr, "MaxTotalBytes", 6, 7)
	_, packErr := PackWithLimits(snapshot, limits)
	packBound := requireBound(t, packErr, "MaxTotalBytes", 6, 7)
	if *estimateBound != *packBound {
		t.Fatalf("Estimate and Pack bounds differ: %#v %#v", estimateBound, packBound)
	}
}

func TestEntryManifestAndCountBounds(t *testing.T) {
	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{fileTarget("files", "config", model.SelectionDirectory)}, Entries: []model.Entry{fileEntry("files", "a", model.FileRegular, model.FilePresent, []byte("1234")), fileEntry("files", "b", model.FileRegular, model.FilePresent, []byte("5"))}}
	limits := DefaultLimits()
	limits.MaxEntryBytes = 3
	_, err := EstimateWithLimits(snapshot, limits)
	requireBound(t, err, "MaxEntryBytes", 3, 4)
	limits = DefaultLimits()
	limits.MaxEntries = 1
	_, err = PackWithLimits(snapshot, limits)
	requireBound(t, err, "MaxEntries", 1, 2)
	limits = DefaultLimits()
	limits.MaxManifestBytes = 64
	_, err = PackWithLimits(snapshot, limits)
	manifestBound := requireBound(t, err, "MaxManifestBytes", 64, int64(len(manifestForSnapshot(t, snapshot))))
	if manifestBound.Path != "manifest" {
		t.Fatalf("wrong manifest bound path: %#v", manifestBound)
	}
	blob, err := Pack(snapshot)
	requireNoError(t, err)
	limits = DefaultLimits()
	limits.MaxManifestBytes = 64
	_, err = UnpackWithLimits(blob, limits)
	requireBound(t, err, "MaxManifestBytes", 64, int64(len(mustReadManifest(t, blob))))
}

func TestDeclaredSizeBombRejectedBeforeBodyRead(t *testing.T) {
	entry := fileEntry("files", "bomb", model.FileRegular, model.FilePresent, []byte{})
	wire, _, err := wireFromEntry(entry, ordinal(1))
	requireNoError(t, err)
	manifest := wireManifest{Version: Version, Codec: CodecNone, SnapshotVersion: model.SnapshotVersion, Targets: []model.Target{fileTarget("files", "config", model.SelectionDirectory)}, Entries: []wireEntry{wire}}
	manifestData, err := encodeManifest(manifest)
	requireNoError(t, err)
	var payload bytes.Buffer
	writer := tar.NewWriter(&payload)
	requireNoError(t, writeMember(writer, manifestMember, manifestData))
	requireNoError(t, writer.WriteHeader(&tar.Header{Name: ordinal(1), Mode: 0o600, Uid: 0, Gid: 0, Size: 128, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}))
	payload.Write(bytes.Repeat([]byte{0}, 17))
	bytesValue := bytes.Clone(payload.Bytes())
	limits := DefaultLimits()
	limits.MaxEntryBytes = 32
	blob := Blob{Version: Version, Codec: CodecNone, Payload: bytesValue, Digest: sha256.Sum256(bytesValue), PlaintextBytes: 0, EntryCount: 1}
	_, err = UnpackWithLimits(blob, limits)
	requireBound(t, err, "MaxEntryBytes", 32, 128)
}

func TestCorruptionAndArchiveRecordsRejected(t *testing.T) {
	blob := simpleBlob(t)
	t.Run("flipped payload byte", func(t *testing.T) {
		changed := cloneBlob(blob)
		members := readMembers(t, changed.Payload)
		for index := 1; index < len(members); index++ {
			if len(members[index].data) > 0 {
				members[index].data[0] ^= 1
				break
			}
		}
		changed.Payload = encodeMembers(t, members)
		if _, err := Unpack(changed); err == nil || !strings.Contains(err.Error(), "entry digest mismatch") {
			t.Fatalf("payload corruption was not caught by entry digest: %v", err)
		}
	})
	t.Run("flipped entry digest", func(t *testing.T) {
		changed := rewriteManifest(t, blob, func(manifest *wireManifest) {
			manifest.Entries[0].SHA256 = strings.Repeat("0", 64)
		})
		if _, err := Unpack(changed); err == nil || !strings.Contains(err.Error(), "entry digest mismatch") {
			t.Fatalf("entry digest corruption was not rejected: %v", err)
		}
	})
	t.Run("flipped blob digest", func(t *testing.T) {
		changed := cloneBlob(blob)
		changed.Digest[0] ^= 1
		if _, err := Unpack(changed); err == nil || !strings.Contains(err.Error(), "blob digest mismatch") {
			t.Fatalf("blob digest corruption was not rejected: %v", err)
		}
	})
	t.Run("truncated stream", func(t *testing.T) {
		changed := cloneBlob(blob)
		changed.Payload = bytes.Clone(changed.Payload[:len(changed.Payload)-100])
		changed.Digest = sha256.Sum256(changed.Payload)
		if _, err := Unpack(changed); err == nil {
			t.Fatal("truncated stream was accepted")
		}
	})
	t.Run("appended garbage", func(t *testing.T) {
		changed := cloneBlob(blob)
		changed.Payload = append(changed.Payload, 0x7f)
		changed.Digest = sha256.Sum256(changed.Payload)
		if _, err := Unpack(changed); err == nil || !strings.Contains(err.Error(), "trailing data") {
			t.Fatalf("appended garbage was not rejected: %v", err)
		}
	})
	t.Run("reordered members", func(t *testing.T) {
		changed := cloneBlob(blob)
		members := readMembers(t, changed.Payload)
		members[1], members[2] = members[2], members[1]
		changed.Payload = encodeMembers(t, members)
		changed.Digest = sha256.Sum256(changed.Payload)
		if _, err := Unpack(changed); err == nil {
			t.Fatal("reordered members were accepted")
		}
	})
	t.Run("PAX record", func(t *testing.T) {
		changed := prependPAX(t, blob)
		if _, err := Unpack(changed); err == nil {
			t.Fatal("PAX record was accepted")
		}
	})
	t.Run("device record", func(t *testing.T) {
		changed := prependDevice(t, blob)
		if _, err := Unpack(changed); err == nil {
			t.Fatal("device record was accepted")
		}
	})
	t.Run("non-ordinal member name", func(t *testing.T) {
		changed := cloneBlob(blob)
		members := readMembers(t, changed.Payload)
		members[1].header.Name = "logical/path"
		changed.Payload = encodeMembers(t, members)
		changed.Digest = sha256.Sum256(changed.Payload)
		if _, err := Unpack(changed); err == nil {
			t.Fatal("non-ordinal member name was accepted")
		}
	})
}

func TestEstimateSurfacesEscapingLinksWithoutContainment(t *testing.T) {
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{fileTarget("files", "config", model.SelectionDirectory)},
		Entries: []model.Entry{
			fileEntry("files", "nested", model.FileDirectory, model.FilePresent, nil),
			fileEntry("files", "nested/inside", model.FileSymlink, model.FilePresent, nil),
			fileEntry("files", "root-link", model.FileSymlink, model.FilePresent, nil),
		},
	}
	snapshot.Entries[1].File.LinkTarget = "../safe"
	snapshot.Entries[2].File.LinkTarget = "../.."
	estimate, err := Estimate(snapshot)
	requireNoError(t, err)
	if len(estimate.EscapingLinks) != 1 || estimate.EscapingLinks[0] != snapshot.Entries[2].Identity() {
		t.Fatalf("estimate did not surface exactly the escaping link: %#v", estimate.EscapingLinks)
	}
	got := mustRoundTrip(t, snapshot)
	if got.Entries[1].File.LinkTarget != "../.." && got.Entries[0].File.LinkTarget != "../.." {
		found := false
		for _, entry := range got.Entries {
			if entry.File != nil && entry.File.LinkTarget == "../.." {
				found = true
			}
		}
		if !found {
			t.Fatal("escaping link target did not round-trip")
		}
	}
}

var publishedSizes = map[string]struct {
	entries   int
	plaintext int64
	blob      int64
}{
	"tests/testdata/neovim":    {entries: 8, plaintext: 388, blob: 9728},
	"1000-file synthetic tree": {entries: 1001, plaintext: 256000, blob: 1239552},
	"one 4 MiB file":           {entries: 2, plaintext: 4194304, blob: 4197888},
}

func TestNeovimFixtureRoundTripAndSizeMeasurement(t *testing.T) {
	root := filepath.Join("..", "..", "tests", "testdata", "neovim")
	fixture := snapshotFromTree(t, "neovim", root)
	blob, err := Pack(fixture)
	requireNoError(t, err)
	if _, err := Unpack(blob); err != nil {
		t.Fatalf("Neovim fixture failed to round-trip: %v", err)
	}
	large := snapshotWithFiles("large", 1, 4*1024*1024)
	thousand := snapshotWithFiles("thousand", 1000, 256)
	for _, item := range []struct {
		name     string
		snapshot model.Snapshot
	}{
		{name: "tests/testdata/neovim", snapshot: fixture},
		{name: "1000-file synthetic tree", snapshot: thousand},
		{name: "one 4 MiB file", snapshot: large},
	} {
		packed, err := Pack(item.snapshot)
		requireNoError(t, err)
		var compressed bytes.Buffer
		compressor := gzip.NewWriter(&compressed)
		if _, err := compressor.Write(packed.Payload); err != nil {
			t.Fatal(err)
		}
		requireNoError(t, compressor.Close())
		t.Logf("%s: entries=%d plaintext_bytes=%d blob_bytes=%d gzip_reference_bytes=%d", item.name, packed.EntryCount, packed.PlaintextBytes, len(packed.Payload), compressed.Len())
		if expected, ok := publishedSizes[item.name]; ok {
			if packed.EntryCount != expected.entries || packed.PlaintextBytes != expected.plaintext || int64(len(packed.Payload)) != expected.blob {
				t.Fatalf("%s: measured entries=%d plaintext=%d blob=%d does not match the published table %+v", item.name, packed.EntryCount, packed.PlaintextBytes, len(packed.Payload), expected)
			}
		}
	}
}

func TestGoldenBytes(t *testing.T) {
	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{fileTarget("files", ".", model.SelectionDirectory)}, Entries: []model.Entry{fileEntry("files", "a.txt", model.FileRegular, model.FilePresent, []byte("golden\n"))}}
	blob, err := Pack(snapshot)
	requireNoError(t, err)
	path := filepath.Join("testdata", "minimal.golden.hex")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(hex.EncodeToString(blob.Payload)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	golden, err := os.ReadFile(path)
	requireNoError(t, err)
	want, err := hex.DecodeString(strings.TrimSpace(string(golden)))
	requireNoError(t, err)
	if !bytes.Equal(blob.Payload, want) {
		t.Fatalf("golden archive changed: got %x, want %x", blob.Payload, want)
	}
	repeat, err := Pack(snapshot)
	requireNoError(t, err)
	if !bytes.Equal(blob.Payload, repeat.Payload) {
		t.Fatal("packing the same snapshot was not byte-identical")
	}
}

func TestUnpackRejectsUnrepresentableEntryPayload(t *testing.T) {
	setting := model.Entry{TargetID: "settings", Setting: &model.SettingEntry{SchemaID: "org.example.Desktop", Path: "/org/example/", Key: "theme", State: model.SettingReset}}
	wire, _, err := wireFromEntry(setting, ordinal(1))
	requireNoError(t, err)
	wire.Size = 1
	wire.SHA256 = digestHex([]byte("x"))
	manifest := wireManifest{Version: Version, Codec: CodecNone, SnapshotVersion: model.SnapshotVersion, Targets: []model.Target{{ID: "settings", Source: model.SourceGNOME, SourceVersion: model.SourceVersion}}, Entries: []wireEntry{wire}}
	blob := blobFromManifest(t, manifest, [][]byte{[]byte("x")}, 0)
	if _, err := Unpack(blob); err == nil || !strings.Contains(err.Error(), "settings manifest entry has a payload") {
		t.Fatalf("unrepresentable settings payload was silently discarded: %v", err)
	}
}

func TestUnpackRejectsNoncanonicalManifestAndInvalidTarget(t *testing.T) {
	blob := simpleBlob(t)
	changed := rewriteManifest(t, blob, func(manifest *wireManifest) { manifest.Codec = "other" })
	if _, err := Unpack(changed); err == nil {
		t.Fatal("unsupported codec was accepted")
	}
	invalidTarget := rewriteManifest(t, blob, func(manifest *wireManifest) { manifest.Targets[0].SourceVersion++ })
	if _, err := Unpack(invalidTarget); err == nil || !strings.Contains(err.Error(), "invalid unpacked snapshot") {
		t.Fatalf("invalid target was not rejected after digest verification: %v", err)
	}
	members := readMembers(t, blob.Payload)
	members[0].data = append(members[0].data, ' ')
	members[0].header.Size = int64(len(members[0].data))
	changed = cloneBlob(blob)
	changed.Payload = encodeMembers(t, members)
	changed.Digest = sha256.Sum256(changed.Payload)
	if _, err := Unpack(changed); err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("noncanonical manifest whitespace was accepted: %v", err)
	}
}

func fileTarget(id, root string, kind model.SelectionKind) model.Target {
	return model.Target{ID: id, Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: &model.FileRoot{Base: model.RootHome, Path: root, Kind: kind}}
}

func fileEntry(targetID, path string, kind model.FileKind, state model.FileState, content []byte) model.Entry {
	file := &model.FileEntry{Path: path, State: state, Kind: kind, Content: content}
	if state == model.FilePresent && kind == model.FileDirectory {
		file.Mode = 0o755
	}
	return model.Entry{TargetID: targetID, File: file}
}

func mustRoundTrip(t *testing.T, snapshot model.Snapshot) model.Snapshot {
	t.Helper()
	blob, err := Pack(snapshot)
	requireNoError(t, err)
	got, err := Unpack(blob)
	requireNoError(t, err)
	return got
}

func canonicalSnapshot(snapshot model.Snapshot) model.Snapshot {
	result := model.Snapshot{Version: snapshot.Version, Targets: append([]model.Target(nil), snapshot.Targets...), Entries: append([]model.Entry(nil), snapshot.Entries...)}
	sort.Slice(result.Targets, func(i, j int) bool { return result.Targets[i].ID < result.Targets[j].ID })
	sortEntries(result.Entries)
	return result
}

func equalSnapshots(left, right model.Snapshot) bool {
	if reflect.DeepEqual(left, right) {
		return true
	}
	if left.Version != right.Version || len(left.Targets) != len(right.Targets) || len(left.Entries) != len(right.Entries) {
		return false
	}
	for index := range left.Targets {
		if left.Targets[index].ID != right.Targets[index].ID || left.Targets[index].Source != right.Targets[index].Source || left.Targets[index].SourceVersion != right.Targets[index].SourceVersion {
			return false
		}
		if (left.Targets[index].Root == nil) != (right.Targets[index].Root == nil) {
			return false
		}
		if left.Targets[index].Root != nil && *left.Targets[index].Root != *right.Targets[index].Root {
			return false
		}
	}
	for index := range left.Entries {
		if left.Entries[index].TargetID != right.Entries[index].TargetID {
			return false
		}
		if left.Entries[index].File != nil && right.Entries[index].File != nil {
			leftFile, rightFile := left.Entries[index].File, right.Entries[index].File
			if leftFile.Path != rightFile.Path || leftFile.State != rightFile.State || leftFile.Kind != rightFile.Kind || leftFile.Mode != rightFile.Mode || leftFile.LinkTarget != rightFile.LinkTarget || !bytes.Equal(leftFile.Content, rightFile.Content) || (leftFile.Content == nil) != (rightFile.Content == nil) {
				return false
			}
		} else if left.Entries[index].Setting != nil && right.Entries[index].Setting != nil {
			if !reflect.DeepEqual(left.Entries[index].Setting, right.Entries[index].Setting) {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

func appendParentDirectories(entries []model.Entry, targetID, path string) []model.Entry {
	parts := strings.Split(path, "/")
	for index := 1; index < len(parts); index++ {
		entries = append(entries, fileEntry(targetID, strings.Join(parts[:index], "/"), model.FileDirectory, model.FilePresent, nil))
	}
	return entries
}

func repeatParts(count int, part string) []string {
	parts := make([]string, count)
	for index := range parts {
		parts[index] = part
	}
	return parts
}

func nestedEntries(targetID, path string) []model.Entry {
	parts := strings.Split(path, "/")
	entries := make([]model.Entry, 0, len(parts))
	for index := 1; index < len(parts); index++ {
		entries = append(entries, fileEntry(targetID, strings.Join(parts[:index], "/"), model.FileDirectory, model.FilePresent, nil))
	}
	entries = append(entries, fileEntry(targetID, path, model.FileRegular, model.FilePresent, []byte("leaf")))
	return entries
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func requireBound(t *testing.T, err error, kind string, limit, observed int64) *BoundError {
	t.Helper()
	var bound *BoundError
	if !errors.As(err, &bound) {
		t.Fatalf("expected BoundError %s, got %T %v", kind, err, err)
	}
	if bound.Kind != kind || bound.Limit != limit || bound.Observed != observed {
		t.Fatalf("unexpected BoundError: %#v, want kind=%s limit=%d observed=%d", bound, kind, limit, observed)
	}
	return bound
}

func simpleBlob(t *testing.T) Blob {
	t.Helper()
	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{fileTarget("files", "config", model.SelectionDirectory)}, Entries: []model.Entry{fileEntry("files", "a", model.FileRegular, model.FilePresent, []byte("alpha")), fileEntry("files", "b", model.FileRegular, model.FilePresent, []byte("bravo"))}}
	blob, err := Pack(snapshot)
	requireNoError(t, err)
	return blob
}

type testMember struct {
	header tar.Header
	data   []byte
}

func readMembers(t *testing.T, payload []byte) []testMember {
	t.Helper()
	reader := tar.NewReader(bytes.NewReader(payload))
	members := make([]testMember, 0)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return members
		}
		requireNoError(t, err)
		data, err := io.ReadAll(reader)
		requireNoError(t, err)
		copyHeader := *header
		members = append(members, testMember{header: copyHeader, data: data})
	}
}

func encodeMembers(t *testing.T, members []testMember) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, member := range members {
		header := member.header
		header.Size = int64(len(member.data))
		requireNoError(t, writer.WriteHeader(&header))
		if len(member.data) > 0 {
			_, err := writer.Write(member.data)
			requireNoError(t, err)
		}
	}
	requireNoError(t, writer.Close())
	return bytes.Clone(buffer.Bytes())
}

func cloneBlob(blob Blob) Blob {
	blob.Payload = bytes.Clone(blob.Payload)
	return blob
}

func rewriteManifest(t *testing.T, blob Blob, mutate func(*wireManifest)) Blob {
	t.Helper()
	members := readMembers(t, blob.Payload)
	manifest, err := decodeManifest(members[0].data)
	requireNoError(t, err)
	mutate(&manifest)
	members[0].data, err = encodeManifest(manifest)
	requireNoError(t, err)
	changed := cloneBlob(blob)
	changed.Payload = encodeMembers(t, members)
	changed.Digest = sha256.Sum256(changed.Payload)
	return changed
}

func blobFromManifest(t *testing.T, manifest wireManifest, payloads [][]byte, plaintext int64) Blob {
	t.Helper()
	encoded, err := encodeManifest(manifest)
	requireNoError(t, err)
	members := []testMember{{header: tar.Header{Name: manifestMember, Mode: 0o600, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}, data: encoded}}
	for index, payload := range payloads {
		members = append(members, testMember{header: tar.Header{Name: ordinal(index + 1), Mode: 0o600, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}, data: payload})
	}
	archive := encodeMembers(t, members)
	return Blob{Version: Version, Codec: CodecNone, Payload: archive, Digest: sha256.Sum256(archive), PlaintextBytes: plaintext, EntryCount: len(payloads)}
}

func prependPAX(t *testing.T, blob Blob) Blob {
	t.Helper()
	members := readMembers(t, blob.Payload)
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	manifestHeader := members[0].header
	manifestHeader.Size = int64(len(members[0].data))
	manifestHeader.Format = tar.FormatPAX
	manifestHeader.PAXRecords = map[string]string{"comment": "pax record"}
	requireNoError(t, writer.WriteHeader(&manifestHeader))
	_, err := writer.Write(members[0].data)
	requireNoError(t, err)
	for _, member := range members[1:] {
		header := member.header
		header.Size = int64(len(member.data))
		requireNoError(t, writer.WriteHeader(&header))
		if len(member.data) > 0 {
			_, err := writer.Write(member.data)
			requireNoError(t, err)
		}
	}
	requireNoError(t, writer.Close())
	changed := cloneBlob(blob)
	changed.Payload = bytes.Clone(buffer.Bytes())
	changed.Digest = sha256.Sum256(changed.Payload)
	return changed
}

func prependDevice(t *testing.T, blob Blob) Blob {
	t.Helper()
	members := readMembers(t, blob.Payload)
	device := testMember{header: tar.Header{Name: "000000", Mode: 0o600, Typeflag: tar.TypeChar, Format: tar.FormatUSTAR}}
	members = append([]testMember{device}, members...)
	changed := cloneBlob(blob)
	changed.Payload = encodeMembers(t, members)
	changed.Digest = sha256.Sum256(changed.Payload)
	return changed
}

func manifestForSnapshot(t *testing.T, snapshot model.Snapshot) []byte {
	t.Helper()
	prepared, err := prepare(snapshot, DefaultLimits())
	requireNoError(t, err)
	return prepared.manifest
}

func mustReadManifest(t *testing.T, blob Blob) []byte {
	t.Helper()
	members := readMembers(t, blob.Payload)
	return members[0].data
}

func snapshotFromTree(t *testing.T, targetID, root string) model.Snapshot {
	t.Helper()
	entries := make([]model.Entry, 0)
	_, err := os.Stat(root)
	requireNoError(t, err)
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.IsDir() {
			entries = append(entries, fileEntry(targetID, relative, model.FileDirectory, model.FilePresent, nil))
			entries[len(entries)-1].File.Mode = uint32(info.Mode().Perm() & 0o777)
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		file := fileEntry(targetID, relative, model.FileRegular, model.FilePresent, data)
		file.File.Mode = uint32(info.Mode().Perm() & 0o777)
		entries = append(entries, file)
		return nil
	})
	requireNoError(t, err)
	return model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{fileTarget(targetID, "nvim", model.SelectionDirectory)}, Entries: entries}
}

func snapshotWithFiles(targetID string, count, bytesPerFile int) model.Snapshot {
	entries := make([]model.Entry, 0, count+1)
	entries = append(entries, fileEntry(targetID, "config", model.FileDirectory, model.FilePresent, nil))
	entries[0].File.Mode = 0o755
	for index := 0; index < count; index++ {
		content := []byte(strings.Repeat(string(rune('a'+index%26)), bytesPerFile))
		entries = append(entries, fileEntry(targetID, fmt.Sprintf("config/file-%04d.conf", index), model.FileRegular, model.FilePresent, content))
	}
	return model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{fileTarget(targetID, "synthetic", model.SelectionDirectory)}, Entries: entries}
}
