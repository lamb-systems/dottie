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

func (coordinator *Coordinator) buildPublicationSnapshot(ctx context.Context, request PublicationCandidateRequest) (model.Snapshot, error) {
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

func buildPublicationMaterial(binding publicationstate.Binding, snapshot model.Snapshot, floor publicationstate.Floor, present bool, view publicationstate.SuppliedRepositoryView, publicationID [16]byte) (publicationstate.CandidateInput, publication.BlobReference, MaterialWriteBatch, error) {
	candidate, blob, err := encodePublicationCandidate(binding, snapshot, floor, present, publicationID)
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

func encodePublicationCandidate(binding publicationstate.Binding, snapshot model.Snapshot, floor publicationstate.Floor, present bool, publicationID [16]byte) (publicationstate.CandidateInput, publication.BlobReference, error) {
	packed, err := vault.Pack(snapshot)
	if err != nil {
		return publicationstate.CandidateInput{}, publication.BlobReference{}, err
	}
	blobCID, err := publication.RawPayloadCID(packed.Payload)
	if err != nil {
		return publicationstate.CandidateInput{}, publication.BlobReference{}, err
	}
	blob := publication.BlobReference{CID: blobCID, Size: uint64(len(packed.Payload))}
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
	return publicationstate.CandidateInput{SnapshotKey: key, SnapshotRecord: snapshotRecord, HeadRecord: headRecord, Payload: packed.Payload}, blob, nil
}
