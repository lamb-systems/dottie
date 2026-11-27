package service

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sort"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
)

var ErrPublicationCandidate = errors.New("publication candidate refused")

type PublicationCandidateRequest struct {
	Configuration  config.Config
	BaseSnapshot   model.Snapshot
	RemoteSnapshot model.Snapshot
	PublicationID  [16]byte
}

func (coordinator *Coordinator) buildPublicationSnapshot(
	ctx context.Context,
	request PublicationCandidateRequest,
) (model.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return model.Snapshot{}, err
	}
	if request.PublicationID == ([16]byte{}) || len(request.Configuration.Targets) == 0 {
		return model.Snapshot{}, ErrPublicationCandidate
	}
	base := func(_ context.Context, target config.Target, _ model.Target) ([]model.Entry, syncengine.BaseStatus, []model.EntryKey, error) {
		entries, defined := publicationSnapshotTargetEntries(request.BaseSnapshot, target.ID)
		if !defined {
			return nil, syncengine.BaseMissing, nil, nil
		}
		return entries, syncengine.BaseKnown, nil, nil
	}
	remote := func(target config.Target) ([]model.Entry, []model.EntryKey) {
		entries, _ := publicationSnapshotTargetEntries(request.RemoteSnapshot, target.ID)
		return entries, nil
	}
	snapshot, _, err := coordinator.composePublicationSnapshot(ctx, request.Configuration, base, remote, nil)
	if err != nil {
		return model.Snapshot{}, err
	}
	return snapshot, nil
}

func publicationSnapshotTargetEntries(snapshot model.Snapshot, targetID string) ([]model.Entry, bool) {
	defined := false
	for _, target := range snapshot.Targets {
		if target.ID == targetID {
			defined = true
			break
		}
	}
	entries := make([]model.Entry, 0)
	for _, entry := range snapshot.Entries {
		if entry.TargetID != targetID {
			continue
		}
		defined = true
		entries = append(entries, entry)
	}
	if !defined {
		return nil, false
	}
	return entries, true
}

func buildPublicationMaterial(
	binding publicationstate.Binding,
	snapshot model.Snapshot,
	floor publicationstate.Floor,
	present bool,
	accepted PublicationAcceptedPaths,
	view publicationstate.SuppliedRepositoryView,
	publicationID [16]byte,
) (publicationstate.CandidateInput, MaterialWriteBatch, error) {
	candidate, err := encodePublicationCandidate(binding, snapshot, floor, present, accepted, publicationID)
	if err != nil {
		return publicationstate.CandidateInput{}, MaterialWriteBatch{}, err
	}
	var captured *publicationstate.Floor
	if present {
		cloned := floor
		cloned.AnchorCID = bytes.Clone(floor.AnchorCID)
		cloned.Head = bytes.Clone(floor.Head)
		cloned.RecordCID = bytes.Clone(floor.RecordCID)
		cloned.Segments = cloneSegmentSummariesService(floor.Segments)
		cloned.SuppliedContext = cloneMaterialContext(floor.SuppliedContext)
		captured = &cloned
	}
	batch, err := newMaterialWriteBatch(binding, captured, view, candidate)
	if err != nil {
		return publicationstate.CandidateInput{}, MaterialWriteBatch{}, err
	}
	return candidate, batch, nil
}

func encodePublicationCandidate(
	binding publicationstate.Binding,
	snapshot model.Snapshot,
	floor publicationstate.Floor,
	present bool,
	accepted PublicationAcceptedPaths,
	publicationID [16]byte,
) (publicationstate.CandidateInput, error) {
	var sequence uint64
	parent := []byte{}
	if present {
		sequence = floor.Sequence + 1
		parent = bytes.Clone(floor.RecordCID)
	}
	key, err := publication.SequenceKey(sequence)
	if err != nil {
		return publicationstate.CandidateInput{}, err
	}
	recordSegments, writeSegments, payloads, entries, err := candidateSegments(snapshot, accepted)
	if err != nil {
		return publicationstate.CandidateInput{}, err
	}
	snapshotRecord, err := publication.EncodeSnapshot(publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationID: publicationID,
		PublicationSeq: sequence, Parent: parent, Segments: recordSegments,
	})
	if err != nil {
		return publicationstate.CandidateInput{}, err
	}
	snapshotCID, err := publication.RecordCID(snapshotRecord)
	if err != nil {
		return publicationstate.CandidateInput{}, err
	}
	headRecord, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationSeq: sequence,
		SnapshotCID: snapshotCID,
	})
	if err != nil {
		return publicationstate.CandidateInput{}, err
	}
	return publicationstate.CandidateInput{
		SnapshotKey:    key,
		SnapshotRecord: snapshotRecord,
		HeadRecord:     headRecord,
		Segments:       writeSegments,
		Payloads:       payloads,
		Entries:        entries,
	}, nil
}

func cloneSegmentSummariesService(summaries []publicationstate.SegmentSummary) []publicationstate.SegmentSummary {
	cloned := make([]publicationstate.SegmentSummary, 0, len(summaries))
	for _, summary := range summaries {
		copy := publicationstate.SegmentSummary{
			TargetID: summary.TargetID, Form: summary.Form,
			BlobCID: bytes.Clone(summary.BlobCID), BlobSize: summary.BlobSize,
			Settings: summary.Settings,
		}
		for _, entry := range summary.Entries {
			copy.Entries = append(copy.Entries, publicationstate.PayloadEntryReference{
				Path: entry.Path, CID: bytes.Clone(entry.CID), Size: entry.Size,
			})
		}
		cloned = append(cloned, copy)
	}
	return cloned
}

func candidateSegments(
	snapshot model.Snapshot,
	accepted PublicationAcceptedPaths,
) ([]publication.SnapshotSegment, []publicationstate.CandidateSegment, [][]byte, []publication.PayloadEntry, error) {
	targets := append([]model.Target(nil), snapshot.Targets...)
	sort.Slice(targets, func(left, right int) bool { return targets[left].ID < targets[right].ID })
	recordSegments := make([]publication.SnapshotSegment, 0, len(targets))
	writeSegments := make([]publicationstate.CandidateSegment, 0, len(targets))
	payloads := make([][]byte, 0, len(targets))
	entries := make([]publication.PayloadEntry, 0)
	for _, target := range targets {
		targetEntries := make([]model.Entry, 0, len(snapshot.Entries))
		for _, entry := range snapshot.Entries {
			if entry.TargetID == target.ID {
				targetEntries = append(targetEntries, entry)
			}
		}
		switch target.Source {
		case model.SourceGNOME:
			segment, err := settingsSegmentForTarget(target, targetEntries)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			recordSegments = append(recordSegments, segment)
			writeSegments = append(writeSegments, publicationstate.CandidateSegment{
				TargetID: target.ID, Form: publicationstate.PayloadFormSettings,
				SettingsDigest: publication.SettingsDigest(segment.Settings),
			})
			payloads = append(payloads, nil)
		case model.SourceFiles:
			segment, targetPayloads, ok := entriesSegmentForTarget(target, targetEntries)
			if ok && publicationTargetDropsAcceptedPath(accepted, target.ID, segment.Entries) {
				ok = false
			}
			if ok {
				recordSegments = append(recordSegments, segment)
				references := make([]publicationstate.PayloadEntryReference, 0, len(segment.Entries))
				for _, entry := range segment.Entries {
					references = append(references, publicationstate.PayloadEntryReference{
						Path: entry.Path, CID: bytes.Clone(entry.Blob.CID), Size: entry.Size,
					})
				}
				writeSegments = append(writeSegments, publicationstate.CandidateSegment{
					TargetID: target.ID, Form: publicationstate.PayloadFormFileSet, Entries: references,
				})
				payloads = append(payloads, nil)
				entries = append(entries, targetPayloads...)
				continue
			}
			packed, err := vault.PackTarget(snapshot, target.ID)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			cid, err := publication.RawPayloadCID(packed.Payload)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			blob := publication.BlobReference{
				CID: cid, Size: uint64(len(packed.Payload)), MIMEType: publication.SnapshotBlobMIMEType,
			}
			recordSegments = append(recordSegments, publication.SnapshotSegment{
				Target: target, Form: publication.SegmentFormPacked, Blob: blob,
			})
			writeSegments = append(writeSegments, publicationstate.CandidateSegment{
				TargetID: target.ID, Form: publicationstate.PayloadFormPacked, Blob: &blob,
			})
			payloads = append(payloads, packed.Payload)
		default:
			return nil, nil, nil, nil, publication.ErrInvalidRecord
		}
	}
	return recordSegments, writeSegments, payloads, entries, nil
}

func settingsSegmentForTarget(target model.Target, entries []model.Entry) (publication.SnapshotSegment, error) {
	settings := make([]publication.SnapshotSetting, 0, len(entries))
	for _, entry := range entries {
		if entry.Setting == nil || entry.File != nil {
			return publication.SnapshotSegment{}, publication.ErrInvalidRecord
		}
		settings = append(settings, publication.SnapshotSetting{
			SchemaID: entry.Setting.SchemaID, Path: entry.Setting.Path, Key: entry.Setting.Key,
			State: entry.Setting.State, Value: entry.Setting.Value,
		})
	}
	sort.Slice(settings, func(left, right int) bool {
		if settings[left].SchemaID != settings[right].SchemaID {
			return settings[left].SchemaID < settings[right].SchemaID
		}
		if settings[left].Path != settings[right].Path {
			return settings[left].Path < settings[right].Path
		}
		return settings[left].Key < settings[right].Key
	})
	return publication.SnapshotSegment{Target: target, Form: publication.SegmentFormSettings, Settings: settings}, nil
}

func entriesSegmentForTarget(
	target model.Target,
	entries []model.Entry,
) (publication.SnapshotSegment, []publication.PayloadEntry, bool) {
	if target.Root == nil ||
		(target.Root.Kind != model.SelectionDirectory && target.Root.Kind != model.SelectionFile) {
		return publication.SnapshotSegment{}, nil, false
	}
	files := make([]model.Entry, 0, len(entries))
	directories := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Setting != nil || entry.File == nil {
			return publication.SnapshotSegment{}, nil, false
		}
		file := entry.File
		if file.State != model.FilePresent {
			return publication.SnapshotSegment{}, nil, false
		}
		if target.Root.Kind == model.SelectionFile && (file.Path != "." || file.Kind != model.FileRegular) {
			return publication.SnapshotSegment{}, nil, false
		}
		if file.Kind == model.FileDirectory {
			if file.Mode != fileSetProjectionDirectoryMode {
				return publication.SnapshotSegment{}, nil, false
			}
			directories = append(directories, file.Path)
			continue
		}
		if file.Kind != model.FileRegular || len(file.Content) == 0 {
			return publication.SnapshotSegment{}, nil, false
		}
		if file.Mode != 0o600 && file.Mode != 0o644 {
			return publication.SnapshotSegment{}, nil, false
		}
		files = append(files, entry)
	}
	if len(files) == 0 {
		return publication.SnapshotSegment{}, nil, false
	}
	if target.Root.Kind == model.SelectionFile && len(files) != 1 {
		return publication.SnapshotSegment{}, nil, false
	}
	candidate := publicationSnapshotPaths(files)
	for _, directory := range directories {
		if !publicationSnapshotHasDescendant(candidate, directory) {
			return publication.SnapshotSegment{}, nil, false
		}
	}
	projected := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{cloneSelectionTargetModel(target)},
		Entries: files,
	}
	snapshotEntries, err := fileSetSnapshotEntries(projected)
	if err != nil {
		return publication.SnapshotSegment{}, nil, false
	}
	payloads, err := fileSetPayloadEntries(projected, snapshotEntries)
	if err != nil {
		return publication.SnapshotSegment{}, nil, false
	}
	return publication.SnapshotSegment{
		Target: target, Form: publication.SegmentFormEntries, Entries: snapshotEntries,
	}, payloads, true
}

type PublicationSyncSnapshotRequest struct {
	Configuration  config.Config
	FloorSnapshot  model.Snapshot
	RemoteSnapshot model.Snapshot
	PublicationID  [16]byte
}

func (coordinator *Coordinator) ComposePublicationSyncSnapshot(
	ctx context.Context,
	request PublicationSyncSnapshotRequest,
) (model.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return model.Snapshot{}, err
	}
	if request.PublicationID == ([16]byte{}) || len(request.Configuration.Targets) == 0 {
		return model.Snapshot{}, ErrPublicationCandidate
	}
	base := func(_ context.Context, target config.Target, _ model.Target) ([]model.Entry, syncengine.BaseStatus, []model.EntryKey, error) {
		entries, defined := publicationSnapshotTargetEntries(request.RemoteSnapshot, target.ID)
		if !defined {
			return nil, syncengine.BaseMissing, nil, nil
		}
		return entries, syncengine.BaseKnown, nil, nil
	}
	remote := func(target config.Target) ([]model.Entry, []model.EntryKey) {
		entries, _ := publicationSnapshotTargetEntries(request.RemoteSnapshot, target.ID)
		return entries, nil
	}
	local := func(target config.Target, entries []model.Entry) []model.Entry {
		remoteEntries, named := publicationSnapshotTargetEntries(request.RemoteSnapshot, target.ID)
		if !named {
			return entries
		}
		floorEntries := []model.Entry(nil)
		if publicationSnapshotSameTarget(request.FloorSnapshot, request.RemoteSnapshot, target.ID) {
			floorEntries, _ = publicationSnapshotTargetEntries(request.FloorSnapshot, target.ID)
		}
		return publicationSyncPostPullEntries(floorEntries, remoteEntries, entries)
	}
	snapshot, _, err := coordinator.composePublicationSnapshotWithLocal(
		ctx,
		request.Configuration,
		base,
		remote,
		local,
		nil,
	)
	if err != nil {
		return model.Snapshot{}, err
	}
	return snapshot, nil
}

func publicationSyncPostPullEntries(floor, remote, local []model.Entry) []model.Entry {
	floorEntries := publicationSyncPresentEntries(floor)
	remoteEntries := publicationSyncPresentEntries(remote)
	present := make(map[model.EntryKey]struct{}, len(local))
	result := make([]model.Entry, 0, len(local)+len(remote))
	for _, entry := range local {
		key := entry.Identity()
		if _, seen := present[key]; seen {
			continue
		}
		if publicationSyncEntryChanged(floorEntries, remoteEntries, key) {
			continue
		}
		present[key] = struct{}{}
		result = append(result, entry)
	}
	for _, entry := range remote {
		key := entry.Identity()
		if _, seen := present[key]; seen {
			continue
		}
		if !publicationSyncEntryChanged(floorEntries, remoteEntries, key) {
			continue
		}
		present[key] = struct{}{}
		if applied, ok := publicationSyncAppliedEntry(entry); ok {
			result = append(result, applied)
		}
	}
	return result
}

func publicationSyncPresentEntries(entries []model.Entry) map[model.EntryKey]model.Entry {
	present := make(map[model.EntryKey]model.Entry, len(entries))
	for _, entry := range entries {
		if entry.File != nil && entry.File.State != model.FilePresent {
			continue
		}
		if entry.Setting != nil && entry.Setting.State != model.SettingPresent {
			continue
		}
		present[entry.Identity()] = entry
	}
	return present
}

func publicationSyncEntryChanged(floor, remote map[model.EntryKey]model.Entry, key model.EntryKey) bool {
	floorEntry, floorPresent := floor[key]
	remoteEntry, remotePresent := remote[key]
	if floorPresent != remotePresent {
		return true
	}
	if !floorPresent {
		return false
	}
	return !publicationSyncEntriesEqual(floorEntry, remoteEntry)
}

func publicationSyncEntriesEqual(left, right model.Entry) bool {
	if (left.File == nil) != (right.File == nil) || (left.Setting == nil) != (right.Setting == nil) {
		return false
	}
	if left.File != nil {
		l, r := left.File, right.File
		return l.Path == r.Path && l.State == r.State && l.Kind == r.Kind && l.Mode == r.Mode &&
			l.LinkTarget == r.LinkTarget &&
			bytes.Equal(l.Content, r.Content)
	}
	l, r := left.Setting, right.Setting
	if l.SchemaID != r.SchemaID || l.Path != r.Path || l.Key != r.Key || l.State != r.State {
		return false
	}
	if (l.Value == nil) != (r.Value == nil) {
		return false
	}
	return l.Value == nil || (l.Value.Type == r.Value.Type && l.Value.Text == r.Value.Text)
}

func publicationSyncAppliedEntry(entry model.Entry) (model.Entry, bool) {
	if entry.File != nil {
		if entry.File.State != model.FilePresent || entry.File.Kind != model.FileRegular {
			return model.Entry{}, false
		}
		return model.Entry{TargetID: entry.TargetID, File: &model.FileEntry{
			Path: entry.File.Path, State: model.FilePresent, Kind: model.FileRegular,
			Content: append([]byte(nil), entry.File.Content...), Mode: entry.File.Mode,
		}}, true
	}
	if entry.Setting != nil && entry.Setting.State == model.SettingPresent {
		clone := model.Entry{TargetID: entry.TargetID, Setting: &model.SettingEntry{
			SchemaID: entry.Setting.SchemaID,
			Path:     entry.Setting.Path,
			Key:      entry.Setting.Key,
			State:    entry.Setting.State,
		}}
		if entry.Setting.Value != nil {
			clone.Setting.Value = &model.VariantValue{Type: entry.Setting.Value.Type, Text: entry.Setting.Value.Text}
		}
		return clone, true
	}
	return model.Entry{}, false
}

var ErrPublicationRebind = errors.New("publication target rebind refused")

type PublicationRebindError struct {
	TargetID string
	Accepted model.Target
	Proposed model.Target
}

func (e *PublicationRebindError) Error() string {
	return "publication rebind refused: target " + e.TargetID + " was accepted at " +
		publicationPortableSelector(e.Accepted) + " and is configured at " +
		publicationPortableSelector(e.Proposed) + "; a machine that moves a target re-adopts it"
}

func (e *PublicationRebindError) Is(target error) bool { return target == ErrPublicationRebind }

func publicationPortableSelector(target model.Target) string {
	if target.Root == nil {
		return target.ID + " without a root"
	}
	return string(target.Root.Base) + ":" + target.Root.Path + " (" + string(target.Root.Kind) + ")"
}

func publicationTargetByID(targets []model.Target, targetID string) (model.Target, bool) {
	for _, target := range targets {
		if target.ID == targetID {
			return target, true
		}
	}
	return model.Target{}, false
}

func publicationRebindRefusal(accepted, proposed []model.Target) error {
	for _, target := range proposed {
		if target.Root == nil || target.Source != model.SourceFiles {
			continue
		}
		existing, ok := publicationTargetByID(accepted, target.ID)
		if !ok || reflect.DeepEqual(existing, target) {
			continue
		}
		return &PublicationRebindError{TargetID: target.ID, Accepted: existing, Proposed: target}
	}
	return nil
}

type PublicationAccepted struct {
	FloorCID []byte
	Targets  []model.Target
	Paths    PublicationAcceptedPaths
}

type PublicationAcceptedPaths map[string]map[string]struct{}

func publicationAcceptedPathsOfSnapshot(snapshot model.Snapshot) PublicationAcceptedPaths {
	if len(snapshot.Targets) == 0 {
		return nil
	}
	kinds := make(map[string]model.FileRoot, len(snapshot.Targets))
	for _, target := range snapshot.Targets {
		if target.Root != nil {
			kinds[target.ID] = *target.Root
		}
	}
	paths := make(PublicationAcceptedPaths, len(snapshot.Targets))
	for _, entry := range snapshot.Entries {
		if entry.File == nil || entry.File.State != model.FilePresent || entry.File.Kind != model.FileRegular {
			continue
		}
		recordPath := entry.File.Path
		if root, ok := kinds[entry.TargetID]; ok && root.Kind == model.SelectionFile && recordPath == "." {
			recordPath = filepath.Base(root.Path)
		}
		target := paths[entry.TargetID]
		if target == nil {
			target = make(map[string]struct{})
			paths[entry.TargetID] = target
		}
		target[recordPath] = struct{}{}
	}
	return paths
}

func publicationAcceptedPathsAs(paths PublicationAcceptedPaths, targetID string) PublicationAcceptedPaths {
	if len(paths) != 1 || targetID == "" {
		return paths
	}
	if _, ok := paths[targetID]; ok {
		return paths
	}
	for _, present := range paths {
		return PublicationAcceptedPaths{targetID: present}
	}
	return paths
}

func publicationAcceptedSnapshotOfMaterial(
	material publicationstate.AcceptedMaterial,
) (model.Snapshot, error) {
	record, err := publication.DecodeSnapshot(material.SnapshotRecord)
	if err != nil {
		return model.Snapshot{}, err
	}
	return acceptedSnapshotFromSegments(record, material)
}

func publicationAcceptedOfSnapshot(
	floorCID []byte,
	snapshot model.Snapshot,
) *PublicationAccepted {
	return &PublicationAccepted{
		FloorCID: bytes.Clone(floorCID),
		Targets:  snapshot.Targets,
		Paths:    publicationAcceptedPathsOfSnapshot(snapshot),
	}
}

func publicationTargetDropsAcceptedPath(
	accepted PublicationAcceptedPaths,
	targetID string,
	entries []publication.SnapshotEntry,
) bool {
	present := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		present[entry.Path] = struct{}{}
	}
	for path := range accepted[targetID] {
		if _, ok := present[path]; !ok {
			return true
		}
	}
	return false
}

func publicationSnapshotSameTarget(left, right model.Snapshot, targetID string) bool {
	leftTarget, ok := publicationApplyPublishedTarget(left, targetID)
	if !ok {
		return false
	}
	rightTarget, ok := publicationApplyPublishedTarget(right, targetID)
	if !ok {
		return false
	}
	return reflect.DeepEqual(leftTarget, rightTarget)
}
