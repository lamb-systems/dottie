package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"path"
	"sort"
	"strings"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
)

var ErrFileSetTarget = errors.New("file-set publication requires the sole local files target")

const fileSetProjectionDirectoryMode uint32 = 0o755

func selectPublicationForm(
	configuration config.Config,
	snapshot model.Snapshot,
	base model.Snapshot,
) (publication.PayloadForm, model.Snapshot, error) {
	if err := configuration.Validate(); err != nil {
		return "", model.Snapshot{}, err
	}
	fileSetSnapshot, ok := fileSetCandidateSnapshot(configuration, snapshot, base)
	if !ok {
		return publication.PayloadFormPacked, snapshot, nil
	}
	return publication.PayloadFormFileSet, fileSetSnapshot, nil
}

func fileSetCandidateSnapshot(
	configuration config.Config,
	snapshot model.Snapshot,
	base model.Snapshot,
) (model.Snapshot, bool) {
	if len(snapshot.Targets) != 1 || len(configuration.Targets) != 1 {
		return model.Snapshot{}, false
	}
	target := snapshot.Targets[0]
	if target.Source != model.SourceFiles || target.Root == nil ||
		(target.Root.Kind != model.SelectionDirectory && target.Root.Kind != model.SelectionFile) {
		return model.Snapshot{}, false
	}
	files := make([]model.Entry, 0, len(snapshot.Entries))
	directories := make([]string, 0, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		if entry.TargetID != target.ID {
			return model.Snapshot{}, false
		}
		if entry.Setting != nil || entry.File == nil {
			return model.Snapshot{}, false
		}
		file := entry.File
		if file.State != model.FilePresent {
			return model.Snapshot{}, false
		}
		if target.Root.Kind == model.SelectionFile && (file.Path != "." || file.Kind != model.FileRegular) {
			return model.Snapshot{}, false
		}
		if file.Kind == model.FileDirectory {
			directories = append(directories, file.Path)
			continue
		}
		if file.Kind != model.FileRegular || len(file.Content) == 0 {
			return model.Snapshot{}, false
		}
		if file.Mode != 0o600 && file.Mode != 0o644 {
			return model.Snapshot{}, false
		}
		files = append(files, entry)
	}
	if len(files) == 0 {
		return model.Snapshot{}, false
	}
	if target.Root.Kind == model.SelectionFile && len(files) != 1 {
		return model.Snapshot{}, false
	}
	candidate := publicationSnapshotPaths(files)
	for _, directory := range directories {
		if !publicationSnapshotHasDescendant(candidate, directory) {
			return model.Snapshot{}, false
		}
	}
	if fileSetSnapshotDeletesPresentFile(base, target.ID, candidate) {
		return model.Snapshot{}, false
	}
	projected := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{cloneSelectionTargetModel(target)},
		Entries: files,
	}
	if _, err := fileSetSnapshotEntries(projected); err != nil {
		return model.Snapshot{}, false
	}
	return projected, true
}

func fileSetSingleFileTarget(snapshot model.Snapshot) (model.Target, bool) {
	if len(snapshot.Targets) != 1 {
		return model.Target{}, false
	}
	target := snapshot.Targets[0]
	if target.Root == nil || target.Root.Kind != model.SelectionFile {
		return model.Target{}, false
	}
	return target, true
}

func fileSetSyntheticPath(target model.Target) (string, bool) {
	base := path.Base(target.Root.Path)
	if base == "" || base == "." || base == ".." || base == "/" {
		return "", false
	}
	return base, true
}

func fileSetSnapshotTargets(snapshot model.Snapshot) ([]model.Target, error) {
	if len(snapshot.Targets) != 1 {
		return nil, publication.ErrInvalidRecord
	}
	target := snapshot.Targets[0]
	if target.Source != model.SourceFiles || target.Root == nil || target.Validate() != nil {
		return nil, publication.ErrInvalidRecord
	}
	return []model.Target{{
		ID:            target.ID,
		Source:        target.Source,
		SourceVersion: target.SourceVersion,
		Root: &model.FileRoot{
			Base: target.Root.Base,
			Path: target.Root.Path,
			Kind: target.Root.Kind,
		},
	}}, nil
}

func fileSetSnapshotEntries(snapshot model.Snapshot) ([]publication.SnapshotEntry, error) {
	target, single := fileSetSingleFileTarget(snapshot)
	if !single {
		return publication.SnapshotEntries(snapshot)
	}
	synthetic, ok := fileSetSyntheticPath(target)
	if !ok {
		return nil, publication.ErrInvalidRecord
	}
	entries := make([]model.Entry, 0, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		if entry.File == nil {
			return nil, publication.ErrInvalidRecord
		}
		file := *entry.File
		file.Path = synthetic
		entries = append(entries, model.Entry{TargetID: entry.TargetID, File: &file})
	}
	return publication.SnapshotEntries(model.Snapshot{Version: snapshot.Version, Entries: entries})
}

func fileSetPayloadEntries(
	snapshot model.Snapshot,
	entries []publication.SnapshotEntry,
) ([]publication.PayloadEntry, error) {
	target, single := fileSetSingleFileTarget(snapshot)
	synthetic := ""
	if single {
		valid := false
		synthetic, valid = fileSetSyntheticPath(target)
		if !valid {
			return nil, publication.ErrInvalidRecord
		}
	}
	published := make(map[string][]byte, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		if entry.File == nil || entry.File.State != model.FilePresent ||
			entry.File.Kind != model.FileRegular || entry.File.Mode == 0 {
			return nil, publication.ErrInvalidRecord
		}
		entryPath := entry.File.Path
		if single {
			entryPath = synthetic
		}
		published[entryPath] = entry.File.Content
	}
	payload := make([]publication.PayloadEntry, 0, len(entries))
	for _, entry := range entries {
		content, present := published[entry.Path]
		if !present {
			return nil, publication.ErrInvalidRecord
		}
		payload = append(payload, publication.PayloadEntry{
			Path: entry.Path, Mode: entry.Mode, Size: entry.Size, Content: bytes.Clone(content),
		})
	}
	return payload, nil
}

func fileSetSnapshotDeletesPresentFile(base model.Snapshot, targetID string, candidate map[string]struct{}) bool {
	for _, entry := range base.Entries {
		if entry.TargetID != targetID || entry.File == nil ||
			entry.File.State != model.FilePresent || entry.File.Kind == model.FileDirectory {
			continue
		}
		if _, present := candidate[entry.File.Path]; !present {
			return true
		}
	}
	return false
}

func publicationSnapshotHasDescendant(paths map[string]struct{}, directory string) bool {
	prefix := directory + "/"
	for path := range paths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func publicationSnapshotPaths(entries []model.Entry) map[string]struct{} {
	paths := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.File != nil && entry.File.State == model.FilePresent {
			paths[entry.File.Path] = struct{}{}
		}
	}
	return paths
}

func fileSetPublicationTarget(configuration config.Config) (config.Target, model.Target, error) {
	if len(configuration.Targets) != 1 {
		return config.Target{}, model.Target{}, ErrFileSetTarget
	}
	target := configuration.Targets[0]
	if target.Source != model.SourceFiles || target.Root == nil ||
		(target.Root.Kind != model.SelectionDirectory && target.Root.Kind != model.SelectionFile) {
		return config.Target{}, model.Target{}, ErrFileSetTarget
	}
	portable, err := target.Model()
	if err != nil {
		return config.Target{}, model.Target{}, ErrFileSetTarget
	}
	return cloneSelectionTarget(target), cloneSelectionTargetModel(portable), nil
}

func fileSetProjection(
	portable model.Target,
	entries []publication.PayloadEntry,
) (model.Snapshot, error) {
	if portable.Source != model.SourceFiles || portable.Root == nil || portable.Validate() != nil {
		return model.Snapshot{}, ErrFileSetTarget
	}
	switch portable.Root.Kind {
	case model.SelectionDirectory:
		return fileSetDirectoryProjection(portable, entries)
	case model.SelectionFile:
		return fileSetSingleFileProjection(portable, entries)
	default:
		return model.Snapshot{}, ErrFileSetTarget
	}
}

func fileSetSingleFileProjection(
	portable model.Target,
	entries []publication.PayloadEntry,
) (model.Snapshot, error) {
	if len(entries) != 1 {
		return model.Snapshot{}, publication.ErrInvalidRecord
	}
	entry := entries[0]
	if entry.Path == "" || entry.Path == "." {
		return model.Snapshot{}, publication.ErrInvalidRecord
	}
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{cloneSelectionTargetModel(portable)},
		Entries: []model.Entry{{
			TargetID: portable.ID,
			File: &model.FileEntry{
				Path: ".", State: model.FilePresent, Kind: model.FileRegular,
				Content: bytes.Clone(entry.Content), Mode: entry.Mode,
			},
		}},
	}
	if err := snapshot.Validate(); err != nil {
		return model.Snapshot{}, err
	}
	return snapshot, nil
}

func fileSetDirectoryProjection(
	portable model.Target,
	entries []publication.PayloadEntry,
) (model.Snapshot, error) {
	byPath := make(map[string]publication.PayloadEntry, len(entries))
	directories := make(map[string]struct{})
	for _, entry := range entries {
		if entry.Path == "" || entry.Path == "." {
			return model.Snapshot{}, publication.ErrInvalidRecord
		}
		if _, duplicate := byPath[entry.Path]; duplicate {
			return model.Snapshot{}, publication.ErrInvalidRecord
		}
		if _, duplicate := directories[entry.Path]; duplicate {
			return model.Snapshot{}, publication.ErrInvalidRecord
		}
		byPath[entry.Path] = entry
		for parent := publicationFileSetParent(entry.Path); parent != "."; parent = publicationFileSetParent(parent) {
			if _, conflict := byPath[parent]; conflict {
				return model.Snapshot{}, publication.ErrInvalidRecord
			}
			directories[parent] = struct{}{}
		}
	}
	if len(directories) != 0 {
		for path := range directories {
			if _, conflict := byPath[path]; conflict {
				return model.Snapshot{}, publication.ErrInvalidRecord
			}
		}
	}
	projected := make([]model.Entry, 0, len(byPath)+len(directories))
	for path, entry := range byPath {
		projected = append(projected, model.Entry{
			TargetID: portable.ID,
			File: &model.FileEntry{
				Path: path, State: model.FilePresent, Kind: model.FileRegular,
				Content: bytes.Clone(entry.Content), Mode: entry.Mode,
			},
		})
	}
	for path := range directories {
		projected = append(projected, model.Entry{
			TargetID: portable.ID,
			File: &model.FileEntry{
				Path: path, State: model.FilePresent, Kind: model.FileDirectory,
				Mode: fileSetProjectionDirectoryMode,
			},
		})
	}
	sort.Slice(projected, func(left, right int) bool {
		return publicationFileSetPathLess(
			projected[left].File.Path,
			projected[right].File.Path,
		)
	})
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{cloneSelectionTargetModel(portable)},
		Entries: projected,
	}
	if err := snapshot.Validate(); err != nil {
		return model.Snapshot{}, err
	}
	return snapshot, nil
}

func publicationFileSetParent(path string) string {
	index := strings.LastIndexByte(path, '/')
	if index < 0 {
		return "."
	}
	return path[:index]
}

func publicationFileSetPathLess(left, right string) bool {
	leftDepth := strings.Count(left, "/")
	rightDepth := strings.Count(right, "/")
	if leftDepth != rightDepth {
		return leftDepth < rightDepth
	}
	return left < right
}

func fileSetEntrySetDigest(entries []publication.SnapshotEntry) [32]byte {
	digest := sha256.New()
	var scratch [8]byte
	writeField := func(value string) {
		binary.BigEndian.PutUint64(scratch[:], uint64(len(value)))
		_, _ = digest.Write(scratch[:])
		_, _ = digest.Write([]byte(value))
	}
	for _, entry := range entries {
		writeField(entry.Path)
		binary.BigEndian.PutUint32(scratch[:4], entry.Mode)
		_, _ = digest.Write(scratch[:4])
		binary.BigEndian.PutUint64(scratch[:], entry.Size)
		_, _ = digest.Write(scratch[:])
		writeField(string(entry.Blob.CID))
	}
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func acceptedPublicationSnapshot(
	material publicationstate.AcceptedMaterial,
	configuration config.Config,
) (model.Snapshot, publication.PayloadForm, error) {
	if len(material.SnapshotRecord) == 0 {
		return model.Snapshot{}, "", publication.ErrInvalidRecord
	}
	record, err := publication.DecodeSnapshot(material.SnapshotRecord)
	if err != nil {
		return model.Snapshot{}, "", err
	}
	if record.PayloadForm() == publication.PayloadFormPacked {
		snapshot, err := publication.DecodePayload(material.Payload, record.Blob)
		return snapshot, publication.PayloadFormPacked, err
	}
	_, portable, err := fileSetPublicationTarget(configuration)
	if err != nil {
		return model.Snapshot{}, "", err
	}
	entries := make([]publication.PayloadEntry, 0, len(material.Entries))
	for _, entry := range material.Entries {
		entries = append(entries, publication.PayloadEntry{
			Path: entry.Path, Mode: entry.Mode, Size: uint64(len(entry.Content)),
			Content: bytes.Clone(entry.Content),
		})
	}
	snapshot, err := fileSetProjection(portable, entries)
	return snapshot, publication.PayloadFormFileSet, err
}

func publicationPayloadSnapshot(
	payload publication.Payload,
	configuration config.Config,
) (model.Snapshot, error) {
	if payload.Form == publication.PayloadFormPacked {
		return payload.Snapshot, nil
	}
	_, portable, err := fileSetPublicationTarget(configuration)
	if err != nil {
		return model.Snapshot{}, err
	}
	return fileSetProjection(portable, payload.Entries)
}

func fileSetPayloadEntriesMatch(record []publication.SnapshotEntry, entries []publication.PayloadEntry) bool {
	if len(record) != len(entries) {
		return false
	}
	for index, want := range record {
		entry := entries[index]
		if entry.Path != want.Path || entry.Mode != want.Mode || entry.Size != want.Size ||
			uint64(len(entry.Content)) != want.Size {
			return false
		}
		cid, err := publication.RawPayloadCID(entry.Content)
		if err != nil || !bytes.Equal(cid, want.Blob.CID) {
			return false
		}
	}
	return true
}

func fileSetFloorMatchesRecord(floor *publicationstate.FileSetPayload, record []publication.SnapshotEntry) bool {
	if floor == nil || len(floor.Entries) != len(record) {
		return false
	}
	for index, want := range record {
		entry := floor.Entries[index]
		if entry.Path != want.Path || entry.Size != want.Size || !bytes.Equal(entry.CID, want.Blob.CID) {
			return false
		}
	}
	return true
}

func clonePublicationPayloadEntries(entries []publication.PayloadEntry) []publication.PayloadEntry {
	if entries == nil {
		return nil
	}
	cloned := make([]publication.PayloadEntry, 0, len(entries))
	for _, entry := range entries {
		cloned = append(cloned, publication.PayloadEntry{
			Path: entry.Path, Mode: entry.Mode, Size: entry.Size, Content: bytes.Clone(entry.Content),
		})
	}
	return cloned
}

func publicationAcceptedTarget(
	configuration config.Config,
	targetID string,
	material acceptedPublicationMaterial,
) (model.Target, bool) {
	if material.form == publication.PayloadFormFileSet {
		target, portable, err := fileSetPublicationTarget(configuration)
		if err != nil || target.ID != targetID {
			return model.Target{}, false
		}
		return portable, true
	}
	for _, target := range material.snapshot.Targets {
		if target.ID == targetID {
			return cloneSelectionTargetModel(target), true
		}
	}
	return model.Target{}, false
}

func validPreviewMaterialInput(request PublicationReconciliationRequest) error {
	if len(request.SnapshotRecord) == 0 ||
		len(request.SnapshotRecord) > publication.MaxFileSetRecordBytes ||
		!validPublicationFloorInput(request.ExpectedFloor) {
		return ErrPublicationReconciliation
	}
	record, err := publication.DecodeSnapshot(request.SnapshotRecord)
	if err != nil {
		return ErrPublicationReconciliation
	}
	if len(request.Payload) > 0 {
		if record.PayloadForm() != publication.PayloadFormPacked ||
			uint64(len(request.Payload)) > publication.MaxBlobBytes || len(request.Entries) != 0 ||
			len(request.SnapshotRecord) > publication.MaxRecordBytes {
			return ErrPublicationReconciliation
		}
		return nil
	}
	if record.PayloadForm() != publication.PayloadFormFileSet {
		return ErrPublicationReconciliation
	}
	if len(request.Entries) == 0 || len(request.Entries) > publication.MaxSnapshotEntries {
		return ErrPublicationReconciliation
	}
	var total uint64
	for _, entry := range request.Entries {
		size := uint64(len(entry.Content))
		if size == 0 || size > publication.MaxBlobBytes || size > publication.MaxBlobBytes-total {
			return ErrPublicationReconciliation
		}
		total += size
	}
	return nil
}

func FileSetPublicationTarget(configuration config.Config) (config.Target, model.Target, error) {
	return fileSetPublicationTarget(configuration)
}

func ProjectFileSetSnapshot(portable model.Target, entries []publication.PayloadEntry) (model.Snapshot, error) {
	return fileSetProjection(portable, entries)
}

func SelectPublicationForm(
	configuration config.Config,
	snapshot model.Snapshot,
	base model.Snapshot,
) (publication.PayloadForm, model.Snapshot, error) {
	return selectPublicationForm(configuration, snapshot, base)
}

func EncodePublicationCandidate(
	binding publicationstate.Binding,
	form publication.PayloadForm,
	snapshot model.Snapshot,
	floor publicationstate.Floor,
	present bool,
	publicationID [16]byte,
) (publicationstate.CandidateInput, publication.BlobReference, error) {
	return encodePublicationCandidate(binding, form, snapshot, floor, present, publicationID)
}

func FileSetEntrySetDigest(entries []publication.SnapshotEntry) [32]byte {
	return fileSetEntrySetDigest(entries)
}

func AcceptedPublicationSnapshot(
	material publicationstate.AcceptedMaterial,
	configuration config.Config,
) (model.Snapshot, publication.PayloadForm, error) {
	return acceptedPublicationSnapshot(material, configuration)
}

func PublicationPayloadSnapshot(
	payload publication.Payload,
	configuration config.Config,
) (model.Snapshot, error) {
	return publicationPayloadSnapshot(payload, configuration)
}
