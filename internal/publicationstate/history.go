package publicationstate

import (
	"bytes"
	"context"

	"github.com/lamb-systems/dottie/internal/publication"
)

func (s *Store) Load(ctx context.Context) (Floor, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageLoad); err != nil {
		return zeroFloor(), false, err
	}
	state, err := s.readState(ctx, s.conn, StageLoad)
	if err != nil {
		return zeroFloor(), false, err
	}
	s.needsReadback = false
	if state.floor == nil {
		return zeroFloor(), false, nil
	}
	return cloneFloor(*state.floor), true, nil
}

func (s *Store) History(ctx context.Context, afterRevision uint64, limit uint32) (HistoryPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkContext(ctx, StageHistory); err != nil {
		return HistoryPage{}, err
	}
	if err := s.requireReadback(StageHistory); err != nil {
		return HistoryPage{}, err
	}
	if limit == 0 || limit > 100 || limit > s.limits.HistoryPageEvents || afterRevision > publication.MaxSequence {
		return HistoryPage{}, classified(ErrInvalid, StageInput, ReasonLimits)
	}
	if _, err := s.readState(ctx, s.conn, StageHistory); err != nil {
		return HistoryPage{}, err
	}
	rows, err := s.conn.QueryContext(ctx, "SELECT revision,mode,reason,stop,old_floor,new_floor,body,digest FROM accepted_events WHERE revision>? ORDER BY revision LIMIT ?", afterRevision, limit+1)
	if err != nil {
		return HistoryPage{}, storageFailure(ctx, StageHistory, err)
	}
	defer rows.Close()
	page := HistoryPage{Events: make([]HistoryEvent, 0, limit), Records: make([]RecordEvidence, 0), NextRevision: afterRevision}
	seenRecords := make(map[string]bool)
	var evidenceBytes uint64
	for rows.Next() {
		values, scanErr := scanRawValues(rows, 8)
		if scanErr != nil {
			return HistoryPage{}, storageFailure(ctx, StageHistory, scanErr)
		}
		revisionValue, revisionOK := rawInt64(values[0])
		mode, modeOK := values[1].(string)
		reason, reasonOK := values[2].(string)
		stop, stopOK := values[3].(string)
		oldRaw, oldOK := rawNullableBytes(values[4])
		newRaw, newOK := rawBytes(values[5])
		body, bodyOK := rawBytes(values[6])
		digest, digestOK := rawBytes(values[7])
		if !revisionOK || revisionValue < 0 || !modeOK || !reasonOK || !stopOK || !oldOK || !newOK || !bodyOK || !digestOK {
			return HistoryPage{}, classified(ErrSchema, StageHistory, ReasonCorrupt)
		}
		revision := uint64(revisionValue)
		if len(page.Events) >= int(limit) {
			page.HasMore = true
			break
		}
		var wire eventBodyWire
		if strictJSON(body, &wire) != nil || wire.Version != 1 || wire.Mode != mode || wire.Reason != reason || wire.Stop != stop || len(digest) != 32 {
			return HistoryPage{}, classified(ErrSchema, StageHistory, ReasonCorrupt)
		}
		calculated := domainHash("systems.lamb.dottie.local-publication-event.v1", body)
		if !bytes.Equal(calculated[:], digest) {
			return HistoryPage{}, classified(ErrSchema, StageHistory, ReasonCorrupt)
		}
		newFloor, err := decodeFloor(newRaw)
		if err != nil {
			return HistoryPage{}, classified(ErrSchema, StageHistory, ReasonCorrupt)
		}
		var oldFloor *Floor
		if len(oldRaw) > 0 {
			floor, err := decodeFloor(oldRaw)
			if err != nil {
				return HistoryPage{}, classified(ErrSchema, StageHistory, ReasonCorrupt)
			}
			oldFloor = &floor
		}
		trace := make([]RecordReference, 0, len(wire.Trace))
		newEvidenceBytes := uint64(len(body) + len(digest) + 8)
		toAdd := make([]RecordEvidence, 0)
		pendingRecords := make(map[string]bool)
		for _, refWire := range wire.Trace {
			if len(refWire.CID) == 0 || len(refWire.CID) > publication.MaxCIDBytes || len(refWire.Key) != publication.SequenceKeyLength {
				return HistoryPage{}, classified(ErrSchema, StageHistory, ReasonCorrupt)
			}
			ref := RecordReference{Key: refWire.Key, CID: bytes.Clone(refWire.CID), Sequence: refWire.Sequence}
			trace = append(trace, ref)
			if seenRecords[string(ref.CID)] || pendingRecords[string(ref.CID)] {
				continue
			}
			record, err := s.loadRecordByCID(ctx, s.conn, ref.CID, ref.Key, ref.Sequence, StageHistory)
			if err != nil {
				return HistoryPage{}, err
			}
			pendingRecords[string(ref.CID)] = true
			toAdd = append(toAdd, RecordEvidence{Reference: cloneReference(ref), Raw: bytes.Clone(record.raw)})
			newEvidenceBytes += recordLogicalBytes(record)
		}
		if oldFloor != nil {
			anchorRef := RecordReference{Key: oldFloor.SnapshotKey, CID: bytes.Clone(oldFloor.RecordCID), Sequence: oldFloor.Sequence}
			if !seenRecords[string(anchorRef.CID)] && !pendingRecords[string(anchorRef.CID)] {
				anchor, err := s.loadRecordByCID(ctx, s.conn, anchorRef.CID, anchorRef.Key, anchorRef.Sequence, StageHistory)
				if err != nil {
					return HistoryPage{}, err
				}
				pendingRecords[string(anchorRef.CID)] = true
				toAdd = append(toAdd, RecordEvidence{Reference: cloneReference(anchorRef), Raw: bytes.Clone(anchor.raw)})
				newEvidenceBytes += recordLogicalBytes(anchor)
			}
		}
		if evidenceBytes+newEvidenceBytes > s.limits.HistoryEvidenceBytes {
			if len(page.Events) == 0 {
				return HistoryPage{}, classified(ErrLimit, StageHistory, ReasonCapacity)
			}
			page.HasMore = true
			break
		}
		event := HistoryEvent{Revision: revision, Mode: Mode(mode), Reason: Reason(reason), Stop: stop, OldFloor: cloneFloorPointer(oldFloor), NewFloor: cloneFloor(newFloor), Trace: cloneReferences(trace), ObservationDigest: copyHash(wire.ObservationDigest), SuppliedSetDigest: copyHash(wire.SuppliedSetDigest), EventDigest: calculated}
		page.Events = append(page.Events, event)
		for _, record := range toAdd {
			seenRecords[string(record.Reference.CID)] = true
			page.Records = append(page.Records, record)
		}
		evidenceBytes += newEvidenceBytes
		page.NextRevision = revision
	}
	if err := rows.Err(); err != nil {
		return HistoryPage{}, storageFailure(ctx, StageHistory, err)
	}
	if err := rows.Close(); err != nil {
		return HistoryPage{}, storageFailure(ctx, StageHistory, err)
	}
	if len(page.Events) == int(limit) {
		var more int
		var moreValue any
		if err := s.conn.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM accepted_events WHERE revision>?)", page.NextRevision).Scan(&moreValue); err != nil {
			return HistoryPage{}, storageFailure(ctx, StageHistory, err)
		}
		moreInt, ok := rawInt64(moreValue)
		if !ok || (moreInt != 0 && moreInt != 1) {
			return HistoryPage{}, classified(ErrSchema, StageHistory, ReasonCorrupt)
		}
		more = int(moreInt)
		page.HasMore = more != 0
	}
	return page, nil
}

func cloneFloorPointer(floor *Floor) *Floor {
	if floor == nil {
		return nil
	}
	copy := cloneFloor(*floor)
	return &copy
}
func copyHash(data []byte) [32]byte { var out [32]byte; copy(out[:], data); return out }
