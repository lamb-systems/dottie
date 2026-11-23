package service

import (
	"bytes"
	"context"
	"errors"

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
	form publication.PayloadForm,
	snapshot model.Snapshot,
	floor publicationstate.Floor,
	present bool,
	view publicationstate.SuppliedRepositoryView,
	publicationID [16]byte,
) (publicationstate.CandidateInput, publication.BlobReference, MaterialWriteBatch, error) {
	candidate, blob, err := encodePublicationCandidate(binding, form, snapshot, floor, present, publicationID)
	if err != nil {
		return publicationstate.CandidateInput{}, publication.BlobReference{}, MaterialWriteBatch{}, err
	}
	var captured *publicationstate.Floor
	if present {
		cloned := floor
		cloned.AnchorCID = bytes.Clone(floor.AnchorCID)
		cloned.Head = bytes.Clone(floor.Head)
		cloned.RecordCID = bytes.Clone(floor.RecordCID)
		cloned.BlobCID = bytes.Clone(floor.BlobCID)
		cloned.SuppliedContext = cloneMaterialContext(floor.SuppliedContext)
		captured = &cloned
	}
	batch, err := newMaterialWriteBatch(binding, captured, view, candidate)
	if err != nil {
		return publicationstate.CandidateInput{}, publication.BlobReference{}, MaterialWriteBatch{}, err
	}
	return candidate, blob, batch, nil
}

func encodePublicationCandidate(
	binding publicationstate.Binding,
	form publication.PayloadForm,
	snapshot model.Snapshot,
	floor publicationstate.Floor,
	present bool,
	publicationID [16]byte,
) (publicationstate.CandidateInput, publication.BlobReference, error) {
	var sequence uint64
	parent := []byte{}
	if present {
		sequence = floor.Sequence + 1
		parent = bytes.Clone(floor.RecordCID)
	}
	key, err := publication.SequenceKey(sequence)
	if err != nil {
		return publicationstate.CandidateInput{}, publication.BlobReference{}, err
	}
	switch form {
	case publication.PayloadFormPacked:
		packed, err := vault.Pack(snapshot)
		if err != nil {
			return publicationstate.CandidateInput{}, publication.BlobReference{}, err
		}
		blobCID, err := publication.RawPayloadCID(packed.Payload)
		if err != nil {
			return publicationstate.CandidateInput{}, publication.BlobReference{}, err
		}
		blob := publication.BlobReference{
			CID:      blobCID,
			Size:     uint64(len(packed.Payload)),
			MIMEType: publication.SnapshotBlobMIMEType,
		}
		snapshotRecord, err := publication.EncodeSnapshot(publication.SnapshotRecord{
			SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationID: publicationID,
			PublicationSeq: sequence, Parent: parent, Blob: blob,
		})
		if err != nil {
			return publicationstate.CandidateInput{}, publication.BlobReference{}, err
		}
		snapshotCID, err := publication.RecordCID(snapshotRecord)
		if err != nil {
			return publicationstate.CandidateInput{}, publication.BlobReference{}, err
		}
		headRecord, err := publication.EncodeHead(publication.HeadRecord{
			SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationSeq: sequence,
			SnapshotCID: snapshotCID, BlobCID: blobCID,
		})
		if err != nil {
			return publicationstate.CandidateInput{}, publication.BlobReference{}, err
		}
		return publicationstate.CandidateInput{
			SnapshotKey:    key,
			SnapshotRecord: snapshotRecord,
			HeadRecord:     headRecord,
			Payload:        packed.Payload,
		}, blob, nil
	case publication.PayloadFormFileSet:
		snapshotEntries, err := fileSetSnapshotEntries(snapshot)
		if err != nil {
			return publicationstate.CandidateInput{}, publication.BlobReference{}, err
		}
		snapshotRecord, err := publication.EncodeSnapshot(publication.SnapshotRecord{
			SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationID: publicationID,
			PublicationSeq: sequence, Parent: parent, Entries: snapshotEntries,
		})
		if err != nil {
			return publicationstate.CandidateInput{}, publication.BlobReference{}, err
		}
		snapshotCID, err := publication.RecordCID(snapshotRecord)
		if err != nil {
			return publicationstate.CandidateInput{}, publication.BlobReference{}, err
		}
		headRecord, err := publication.EncodeHead(publication.HeadRecord{
			SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationSeq: sequence,
			SnapshotCID: snapshotCID,
		})
		if err != nil {
			return publicationstate.CandidateInput{}, publication.BlobReference{}, err
		}
		entries, err := fileSetPayloadEntries(snapshot, snapshotEntries)
		if err != nil {
			return publicationstate.CandidateInput{}, publication.BlobReference{}, err
		}
		return publicationstate.CandidateInput{
			SnapshotKey:    key,
			SnapshotRecord: snapshotRecord,
			HeadRecord:     headRecord,
			Entries:        entries,
		}, publication.BlobReference{}, nil
	default:
		return publicationstate.CandidateInput{}, publication.BlobReference{}, publication.ErrPayloadFormMismatch
	}
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
		floorEntries, _ := publicationSnapshotTargetEntries(request.FloorSnapshot, target.ID)
		remoteEntries, _ := publicationSnapshotTargetEntries(request.RemoteSnapshot, target.ID)
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
