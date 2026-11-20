package publicationstate

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/publication"
)

type retainedValidationFixture struct {
	store    *Store
	stored   storedAttempt
	snapshot publication.SnapshotRecord
	floor    Floor
	digest   []byte
}

func retainedValidationFloor(
	t *testing.T,
	store *Store,
	stored storedAttempt,
	snapshot publication.SnapshotRecord,
	head []byte,
	key string,
	revision uint64,
	digest []byte,
) Floor {
	t.Helper()
	floor := Floor{
		DatabaseID:        store.databaseID,
		Revision:          revision,
		Generation:        revision,
		Provenance:        ProvenanceFirst,
		AnchorCID:         bytes.Clone(stored.core.SnapshotCID),
		Binding:           store.binding,
		SuppliedContext:   SuppliedContext{RepositoryRevision: "revision-1", RepositoryDigest: []byte{1, 2, 3}},
		Head:              bytes.Clone(head),
		SnapshotKey:       key,
		Sequence:          snapshot.PublicationSeq,
		PublicationID:     snapshot.PublicationID,
		RecordCID:         bytes.Clone(stored.core.SnapshotCID),
		ObservationDigest: [32]byte{4, 5, 6},
	}
	copy(floor.AcceptedEventDigest[:], digest)
	if payloadFormOf(snapshot) == PayloadFormManifest {
		floor.Manifest = manifestPayloadOf(snapshot)
		return floor
	}
	floor.BlobCID = bytes.Clone(stored.core.BlobCID)
	floor.BlobSize = stored.core.BlobSize
	return floor
}

func newRetainedValidationFixture(t *testing.T, form PayloadForm) retainedValidationFixture {
	t.Helper()
	ctx := context.Background()
	var store *Store
	var stored storedAttempt
	var snapshot publication.SnapshotRecord
	var head []byte
	var key string
	switch form {
	case PayloadFormManifest:
		fixtureValue := manifestFixture(t)
		store, _ = newStore(t, fixture{t: t, binding: fixtureValue.binding})
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		attempt := stageManifestAttempt(t, store, fixtureValue, fixtureValue.view(), attemptReview())
		loaded, err := store.loadStoredAttempt(ctx, store.conn, attempt.ID, StageOpen)
		require.NoError(t, err)
		stored = loaded
		snapshot, err = publication.DecodeSnapshot(fixtureValue.raw)
		require.NoError(t, err)
		head = fixtureValue.head
		key = fixtureValue.key
	case PayloadFormPacked:
		f := newFixture(t, BackendPublicRepo)
		f.recordMIMEType = publication.BlobMIMEType
		f.appendRecord(t, 0)
		store, _ = newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		candidate := attemptCandidate(f, 0)
		view := attemptView(f, f.observation(1), true)
		review := attemptReview()
		proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
		require.NoError(t, err)
		created, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
		require.NoError(t, err)
		loaded, err := store.loadStoredAttempt(ctx, store.conn, created.ID, StageOpen)
		require.NoError(t, err)
		stored = loaded
		snapshot, err = publication.DecodeSnapshot(candidate.SnapshotRecord)
		require.NoError(t, err)
		head = candidate.HeadRecord
		key = candidate.SnapshotKey
	default:
		require.FailNowf(t, "unsupported payload form", "%s", form)
	}
	require.Equal(t, form, attemptCoreForm(stored.core))
	digest := bytes.Repeat([]byte{0x11}, 32)
	floor := retainedValidationFloor(t, store, stored, snapshot, head, key, 1, digest)
	encodedFloor, err := encodeFloor(floor)
	require.NoError(t, err)
	_, err = store.conn.ExecContext(
		ctx,
		"INSERT INTO accepted_events(revision,mode,reason,stop,old_floor,new_floor,body,digest,logical_bytes) VALUES(1,'first-use','','first_use',NULL,?,'body',?,9)",
		encodedFloor,
		digest,
	)
	require.NoError(t, err)
	_, err = store.conn.ExecContext(
		ctx,
		"INSERT INTO accepted_records(cid,record_key,sequence,raw,logical_bytes) VALUES(?,?,?,?,?)",
		stored.core.SnapshotCID,
		key,
		int64(snapshot.PublicationSeq),
		bytes.Clone(stored.core.SnapshotRecord),
		int64(len(stored.core.SnapshotRecord)),
	)
	require.NoError(t, err)
	return retainedValidationFixture{
		store:    store,
		stored:   stored,
		snapshot: snapshot,
		floor:    floor,
		digest:   digest,
	}
}

func (f retainedValidationFixture) manifestBytes(t *testing.T) []byte {
	t.Helper()
	encoded, err := encodeRetainedManifest(manifestPayloadOf(f.snapshot))
	require.NoError(t, err)
	return encoded
}

func (f retainedValidationFixture) insertPacked(t *testing.T) {
	t.Helper()
	_, err := f.store.conn.ExecContext(
		context.Background(),
		"INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,?,'packed',?,?,NULL,1)",
		f.stored.core.SnapshotCID,
		f.stored.core.AttemptID,
		int64(f.snapshot.PublicationSeq),
		f.stored.core.BlobCID,
		int64(f.stored.core.BlobSize),
	)
	require.NoError(t, err)
}

func (f retainedValidationFixture) insertManifest(t *testing.T, manifest []byte) {
	t.Helper()
	_, err := f.store.conn.ExecContext(
		context.Background(),
		"INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,?,'manifest',NULL,NULL,?,1)",
		f.stored.core.SnapshotCID,
		f.stored.core.AttemptID,
		int64(f.snapshot.PublicationSeq),
		manifest,
	)
	require.NoError(t, err)
}

func (f retainedValidationFixture) insertManifestText(t *testing.T, manifest string) {
	t.Helper()
	_, err := f.store.conn.ExecContext(
		context.Background(),
		"INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,?,'manifest',NULL,NULL,?,1)",
		f.stored.core.SnapshotCID,
		f.stored.core.AttemptID,
		int64(f.snapshot.PublicationSeq),
		manifest,
	)
	require.NoError(t, err)
}

func retainedValidationColumnType(t *testing.T, store *Store, column string) string {
	t.Helper()
	var columnType string
	require.NoError(t, store.conn.QueryRowContext(
		context.Background(),
		"SELECT typeof("+column+") FROM retained_publications",
	).Scan(&columnType))
	return columnType
}

func (f retainedValidationFixture) validate(t *testing.T) error {
	t.Helper()
	return f.store.validateRetainedPublication(context.Background(), f.store.conn, f.stored, StageOpen)
}

func retainedValidationIgnoreChecks(t *testing.T, store *Store) {
	t.Helper()
	_, err := store.conn.ExecContext(context.Background(), "PRAGMA ignore_check_constraints=ON")
	require.NoError(t, err)
}

func retainedValidationSetFloor(t *testing.T, store *Store, floor Floor) {
	t.Helper()
	encoded, err := encodeFloor(floor)
	require.NoError(t, err)
	_, err = store.conn.ExecContext(
		context.Background(),
		"UPDATE accepted_events SET new_floor=? WHERE revision=1",
		encoded,
	)
	require.NoError(t, err)
}

func TestRetainedPublicationValidatorAcceptsBothPayloadForms(t *testing.T) {
	t.Run("packed", func(t *testing.T) {
		f := newRetainedValidationFixture(t, PayloadFormPacked)
		f.insertPacked(t)
		require.NoError(t, f.validate(t))
	})
	t.Run("manifest", func(t *testing.T) {
		f := newRetainedValidationFixture(t, PayloadFormManifest)
		f.insertManifest(t, f.manifestBytes(t))
		require.NoError(t, f.validate(t))
	})
}

func TestRetainedPublicationValidatorRefusesCorruptManifestPositions(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, f retainedValidationFixture)
	}{
		{
			name: "row manifest differs from the snapshot",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				entries := manifestPayloadOf(f.snapshot)
				entries.Entries[0].Size++
				encoded, err := encodeRetainedManifest(entries)
				require.NoError(t, err)
				f.insertManifest(t, encoded)
			},
		},
		{
			name: "row manifest differs from the accepted floor",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				f.insertManifest(t, f.manifestBytes(t))
				mutated := f.floor
				mutated.Manifest = cloneManifestPayload(f.floor.Manifest)
				mutated.Manifest.Entries[1].Size++
				retainedValidationSetFloor(t, f.store, mutated)
			},
		},
		{
			name: "unknown form",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				retainedValidationIgnoreChecks(t, f.store)
				_, err := f.store.conn.ExecContext(
					context.Background(),
					"INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,?,'hybrid',NULL,NULL,?,1)",
					f.stored.core.SnapshotCID,
					f.stored.core.AttemptID,
					int64(f.snapshot.PublicationSeq),
					f.manifestBytes(t),
				)
				require.NoError(t, err)
			},
		},
		{
			name: "packed position carries a manifest",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				retainedValidationIgnoreChecks(t, f.store)
				_, err := f.store.conn.ExecContext(
					context.Background(),
					"INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,?,'packed',?,?,?,1)",
					f.stored.core.SnapshotCID,
					f.stored.core.AttemptID,
					int64(f.snapshot.PublicationSeq),
					f.stored.core.BlobCID,
					int64(f.stored.core.BlobSize),
					f.manifestBytes(t),
				)
				require.NoError(t, err)
			},
		},
		{
			name: "manifest position carries packed bytes",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				retainedValidationIgnoreChecks(t, f.store)
				other := manifestFixture(t)
				cid, err := publication.RawPayloadCID(other.entries[0].Content)
				require.NoError(t, err)
				_, err = f.store.conn.ExecContext(
					context.Background(),
					"INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,?,'manifest',?,?,?,1)",
					f.stored.core.SnapshotCID,
					f.stored.core.AttemptID,
					int64(f.snapshot.PublicationSeq),
					cid,
					int64(len(other.entries[0].Content)),
					f.manifestBytes(t),
				)
				require.NoError(t, err)
			},
		},
		{
			name: "manifest is not canonical json",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				f.insertManifest(t, []byte("{"))
			},
		},
		{
			name: "manifest json is not canonical",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				f.insertManifest(t, []byte(`[{"size":1,"path":"init.lua","cid":"AVUSIPux4gUzs4+Zd1V8xEPG26F4W6CaUtxAH1fzcaZ+MCdE"}]`))
			},
		},
		{
			name: "manifest is oversized",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				f.insertManifest(t, bytes.Repeat([]byte("a"), publication.MaxManifestRecordBytes+1))
			},
		},
		{
			name: "manifest is null",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				retainedValidationIgnoreChecks(t, f.store)
				_, err := f.store.conn.ExecContext(
					context.Background(),
					"INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,?,'manifest',NULL,NULL,NULL,1)",
					f.stored.core.SnapshotCID,
					f.stored.core.AttemptID,
					int64(f.snapshot.PublicationSeq),
				)
				require.NoError(t, err)
			},
		},
		{
			name: "manifest is stored as text",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				f.insertManifestText(t, string(f.manifestBytes(t)))
				require.Equal(t, "text", retainedValidationColumnType(t, f.store, "manifest"))
			},
		},
		{
			name: "manifest entry is missing from the catalog",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				f.insertManifest(t, f.manifestBytes(t))
				entries := manifestPayloadOf(f.snapshot)
				_, err := f.store.conn.ExecContext(
					context.Background(),
					"DELETE FROM payload_objects WHERE blob_cid=?",
					entries.Entries[1].CID,
				)
				require.NoError(t, err)
			},
		},
		{
			name: "manifest entry size differs from the catalog",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				f.insertManifest(t, f.manifestBytes(t))
				entries := manifestPayloadOf(f.snapshot)
				_, err := f.store.conn.ExecContext(
					context.Background(),
					"UPDATE payload_objects SET size=size+1 WHERE blob_cid=?",
					entries.Entries[1].CID,
				)
				require.NoError(t, err)
			},
		},
		{
			name: "manifest entry basename differs from the catalog",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				f.insertManifest(t, f.manifestBytes(t))
				entries := manifestPayloadOf(f.snapshot)
				_, err := f.store.conn.ExecContext(
					context.Background(),
					"UPDATE payload_objects SET basename=? WHERE blob_cid=?",
					"0000000000000000000000000000000000000000000000000000000000000000.payload",
					entries.Entries[1].CID,
				)
				require.NoError(t, err)
			},
		},
		{
			name: "retained record differs from the snapshot",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				f.insertManifest(t, f.manifestBytes(t))
				other := bytes.Clone(f.stored.core.SnapshotCID)
				other[len(other)-1] ^= 0xff
				_, err := f.store.conn.ExecContext(
					context.Background(),
					"UPDATE retained_publications SET record_cid=?",
					other,
				)
				require.NoError(t, err)
			},
		},
		{
			name: "retained sequence differs from the snapshot",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				f.insertManifest(t, f.manifestBytes(t))
				_, err := f.store.conn.ExecContext(
					context.Background(),
					"UPDATE retained_publications SET sequence=sequence+1",
				)
				require.NoError(t, err)
			},
		},
		{
			name: "retained acceptance revision has no event",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				f.insertManifest(t, f.manifestBytes(t))
				_, err := f.store.conn.ExecContext(
					context.Background(),
					"UPDATE retained_publications SET accepted_revision=2",
				)
				require.NoError(t, err)
			},
		},
		{
			name: "accepted floor carries a foreign binding",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				f.insertManifest(t, f.manifestBytes(t))
				mutated := f.floor
				mutated.Binding.AccountDID = "did:plc:other"
				retainedValidationSetFloor(t, f.store, mutated)
			},
		},
		{
			name: "accepted event digest differs from the floor",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				f.insertManifest(t, f.manifestBytes(t))
				_, err := f.store.conn.ExecContext(
					context.Background(),
					"UPDATE accepted_events SET digest=? WHERE revision=1",
					bytes.Repeat([]byte{0x22}, 32),
				)
				require.NoError(t, err)
			},
		},
		{
			name: "accepted record differs from the retained snapshot",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				f.insertManifest(t, f.manifestBytes(t))
				other := bytes.Clone(f.stored.core.SnapshotRecord)
				other[len(other)-1] ^= 0xff
				_, err := f.store.conn.ExecContext(
					context.Background(),
					"UPDATE accepted_records SET raw=?",
					other,
				)
				require.NoError(t, err)
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			f := newRetainedValidationFixture(t, PayloadFormManifest)
			testCase.mutate(t, f)
			requireErrorMetadata(t, f.validate(t), ErrSchema, StageOpen, ReasonCorrupt)
		})
	}
}

func TestRetainedPublicationValidatorRefusesCorruptPackedPositions(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, f retainedValidationFixture)
	}{
		{
			name: "packed bytes differ from the attempt core",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				f.insertPacked(t)
				_, err := f.store.conn.ExecContext(
					context.Background(),
					"UPDATE retained_publications SET size=size+1",
				)
				require.NoError(t, err)
			},
		},
		{
			name: "packed acceptance revision has no event",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				f.insertPacked(t)
				_, err := f.store.conn.ExecContext(
					context.Background(),
					"UPDATE retained_publications SET accepted_revision=2",
				)
				require.NoError(t, err)
			},
		},
		{
			name: "packed position carries a manifest",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				retainedValidationIgnoreChecks(t, f.store)
				f.insertPacked(t)
				_, err := f.store.conn.ExecContext(
					context.Background(),
					"UPDATE retained_publications SET manifest=?",
					[]byte("x"),
				)
				require.NoError(t, err)
			},
		},
		{
			name: "packed size is stored as text",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				f.insertPacked(t)
				_, err := f.store.conn.ExecContext(
					context.Background(),
					"UPDATE retained_publications SET size=?",
					"not-an-integer",
				)
				require.NoError(t, err)
				require.Equal(t, "text", retainedValidationColumnType(t, f.store, "size"))
			},
		},
		{
			name: "packed blob cid is stored as text",
			mutate: func(t *testing.T, f retainedValidationFixture) {
				cid := string(f.stored.core.BlobCID)
				_, err := f.store.conn.ExecContext(
					context.Background(),
					"INSERT INTO payload_objects(blob_cid,size,basename,logical_bytes) VALUES(?,?,?,?)",
					cid,
					int64(f.stored.core.BlobSize),
					"text-cid.payload",
					int64(f.stored.core.BlobSize),
				)
				require.NoError(t, err)
				_, err = f.store.conn.ExecContext(
					context.Background(),
					"INSERT INTO retained_publications(record_cid,attempt_id,sequence,form,blob_cid,size,manifest,accepted_revision) VALUES(?,?,?,'packed',?,?,NULL,1)",
					f.stored.core.SnapshotCID,
					f.stored.core.AttemptID,
					int64(f.snapshot.PublicationSeq),
					cid,
					int64(f.stored.core.BlobSize),
				)
				require.NoError(t, err)
				require.Equal(t, "text", retainedValidationColumnType(t, f.store, "blob_cid"))
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			f := newRetainedValidationFixture(t, PayloadFormPacked)
			testCase.mutate(t, f)
			requireErrorMetadata(t, f.validate(t), ErrSchema, StageOpen, ReasonCorrupt)
		})
	}
}

func TestRetainedManifestCodecRoundTripsCanonicalEntries(t *testing.T) {
	snapshot := manifestFixture(t)
	snapshotRecord, err := publication.DecodeSnapshot(snapshot.raw)
	require.NoError(t, err)
	payload := manifestPayloadOf(snapshotRecord)
	encoded, err := encodeRetainedManifest(payload)
	require.NoError(t, err)
	require.NotEmpty(t, encoded)
	require.LessOrEqual(t, len(encoded), publication.MaxManifestRecordBytes)
	canonical, err := canonicalJSON(manifestPayloadToWire(payload))
	require.NoError(t, err)
	assert.Equal(t, canonical, encoded)
	decoded, err := decodeRetainedManifest(encoded)
	require.NoError(t, err)
	assert.True(t, sameManifestPayload(payload, decoded))
}

func TestRetainedManifestCodecRefusesInvalidEncodings(t *testing.T) {
	snapshot := manifestFixture(t)
	snapshotRecord, err := publication.DecodeSnapshot(snapshot.raw)
	require.NoError(t, err)
	valid, err := encodeRetainedManifest(manifestPayloadOf(snapshotRecord))
	require.NoError(t, err)
	cases := []struct {
		name  string
		input []byte
	}{
		{name: "empty", input: []byte{}},
		{name: "oversized", input: bytes.Repeat([]byte("a"), publication.MaxManifestRecordBytes+1)},
		{name: "malformed", input: []byte("{")},
		{name: "empty list", input: []byte("[]")},
		{name: "null list", input: []byte("null")},
		{name: "unknown field", input: []byte(`[{"path":"init.lua","cid":"AVUSIPux4gUzs4+Zd1V8xEPG26F4W6CaUtxAH1fzcaZ+MCdE","size":1,"mode":384}]`)},
		{name: "noncanonical whitespace", input: bytes.Replace(valid, []byte(","), []byte(", "), 1)},
		{name: "noncanonical field order", input: []byte(`[{"size":1,"path":"init.lua","cid":"AVUSIPux4gUzs4+Zd1V8xEPG26F4W6CaUtxAH1fzcaZ+MCdE"}]`)},
		{name: "empty path", input: []byte(`[{"path":"","cid":"AVUSIPux4gUzs4+Zd1V8xEPG26F4W6CaUtxAH1fzcaZ+MCdE","size":1}]`)},
		{name: "empty cid", input: []byte(`[{"path":"init.lua","cid":"","size":1}]`)},
		{name: "zero size", input: []byte(`[{"path":"init.lua","cid":"AVUSIPux4gUzs4+Zd1V8xEPG26F4W6CaUtxAH1fzcaZ+MCdE","size":0}]`)},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := decodeRetainedManifest(testCase.input)
			require.Error(t, err)
		})
	}
}

func retainedManifestCeilingPayload(count int) *ManifestPayload {
	entries := make([]PayloadEntryReference, 0, count)
	for index := 0; index < count; index++ {
		entries = append(entries, PayloadEntryReference{
			Path: fmt.Sprintf("entry-%02d", index),
			CID:  []byte{0x01, byte(index)},
			Size: 1,
		})
	}
	return &ManifestPayload{Entries: entries}
}

func retainedManifestCeilingJSON(t *testing.T, count int) []byte {
	t.Helper()
	encoded, err := canonicalJSON(manifestPayloadToWire(retainedManifestCeilingPayload(count)))
	require.NoError(t, err)
	require.LessOrEqual(t, len(encoded), publication.MaxManifestRecordBytes)
	return encoded
}

func TestRetainedManifestCodecAcceptsTheSnapshotEntryCeiling(t *testing.T) {
	encoded := retainedManifestCeilingJSON(t, publication.MaxSnapshotEntries)
	decoded, err := decodeRetainedManifest(encoded)
	require.NoError(t, err)
	require.Len(t, decoded.Entries, publication.MaxSnapshotEntries)
	reencoded, err := encodeRetainedManifest(decoded)
	require.NoError(t, err)
	assert.Equal(t, encoded, reencoded)
}

func TestRetainedManifestCodecRefusesEntriesAboveTheSnapshotCeiling(t *testing.T) {
	_, err := encodeRetainedManifest(retainedManifestCeilingPayload(publication.MaxSnapshotEntries + 1))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrLimit)
	encoded := retainedManifestCeilingJSON(t, publication.MaxSnapshotEntries+1)
	_, err = decodeRetainedManifest(encoded)
	require.Error(t, err)
}

func TestRetainedManifestCodecDefersPublicationValidity(t *testing.T) {
	payload := &ManifestPayload{Entries: []PayloadEntryReference{
		{Path: "../escape", CID: []byte{1}, Size: 1},
	}}
	encoded, err := encodeRetainedManifest(payload)
	require.NoError(t, err)
	decoded, err := decodeRetainedManifest(encoded)
	require.NoError(t, err)
	assert.True(t, sameManifestPayload(payload, decoded))
}
