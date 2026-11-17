package publicationstate

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/publication"
)

func TestStoredAttemptWireKeepsPackedGoldenAndCarriesShowcaseEntries(t *testing.T) {
	packed := attemptCoreWire{
		Version:               1,
		AttemptID:             bytes.Repeat([]byte{1}, 16),
		DatabaseID:            bytes.Repeat([]byte{2}, 32),
		SnapshotCID:           []byte{3},
		HeadCID:               []byte{4},
		BlobCID:               []byte{5},
		BlobSize:              9,
		CandidateConfirmation: bytes.Repeat([]byte{6}, 32),
		InitialViewDigest:     bytes.Repeat([]byte{7}, 32),
	}
	encodedPacked, err := encodeAttemptCore(packed)
	require.NoError(t, err)
	//nolint:testifylint // byte-exact wire golden: key order and spacing are the format
	assert.Equal(
		t,
		[]byte(
			`{"version":1,"attemptId":"AQEBAQEBAQEBAQEBAQEBAQ==","databaseId":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","binding":{"accountDid":"","backend":"","repository":"","vault":null,"profile":""},"kind":"","capturedFloor":null,"capturedRevision":0,"capturedGeneration":0,`+
				`"predecessorKey":"","predecessorRecord":null,"predecessorCid":null,"snapshotKey":"","snapshotRecord":null,"snapshotCid":"Aw==","headRecord":null,"headCid":"BA==","blobCid":"BQ==","blobSize":9,"initialContext":{"repositoryRevision":"","repositoryDigest":null,"policy":nul`+
				`l},"initialViewDigest":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=","review":{"selectionDigest":null,"selectionRevision":0,"approvalDigest":null,"approvalRevision":0},"candidateConfirmation":"BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY=","reservedCompletionBytes":0}`,
		),
		encodedPacked,
	)
	decodedPacked, err := decodeAttemptCore(encodedPacked)
	require.NoError(t, err)
	assert.Equal(t, packed, decodedPacked)
	reencodedPacked, err := encodeAttemptCore(decodedPacked)
	require.NoError(t, err)
	assert.Equal(t, encodedPacked, reencodedPacked)

	showcase := packed
	showcase.Version = 2
	showcase.BlobCID = nil
	showcase.BlobSize = 0
	showcase.Entries = []payloadEntryWire{{Path: "init.lua", CID: []byte{5}, Size: 9}}
	encodedShowcase, err := encodeAttemptCore(showcase)
	require.NoError(t, err)
	//nolint:testifylint // byte-exact wire golden: key order and spacing are the format
	assert.Equal(
		t,
		[]byte(
			`{"version":2,"attemptId":"AQEBAQEBAQEBAQEBAQEBAQ==","databaseId":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","binding":{"accountDid":"","backend":"","repository":"","vault":null,"profile":""},"kind":"","capturedFloor":null,"capturedRevision":0,"capturedGeneration":0,"predece`+
				`ssorKey":"","predecessorRecord":null,"predecessorCid":null,"snapshotKey":"","snapshotRecord":null,"snapshotCid":"Aw==","headRecord":null,"headCid":"BA==","entries":[{"path":"init.lua","cid":"BQ==","size":9}],"initialContext":{"repositoryRevision":"","repositoryDigest":null,"pol`+
				`icy":null},"initialViewDigest":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=","review":{"selectionDigest":null,"selectionRevision":0,"approvalDigest":null,"approvalRevision":0},"candidateConfirmation":"BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY=","reservedCompletionBytes":0}`,
		),
		encodedShowcase,
	)
	decodedShowcase, err := decodeAttemptCore(encodedShowcase)
	require.NoError(t, err)
	assert.Equal(t, showcase, decodedShowcase)
	assert.Equal(t, []payloadEntryWire{{Path: "init.lua", CID: []byte{5}, Size: 9}}, decodedShowcase.Entries)
}

func TestStoredFloorWireKeepsPackedGoldenAndCarriesShowcaseEntries(t *testing.T) {
	packed := payloadUnionFloor(t)
	encodedPacked, err := encodeFloor(packed)
	require.NoError(t, err)
	//nolint:testifylint // byte-exact wire golden: key order and spacing are the format
	assert.Equal(
		t,
		[]byte(
			`{"version":1,"databaseId":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","revision":7,"generation":2,"provenance":"first-use","anchorCid":"AQ==","binding":{"accountDid":"did:plc:abc","backend":"public-repo","repository":"at://did:plc:abc","vault":"AAAAAAA`+
				`AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","profile":"systems.lamb.dottie.vaultSnapshotV2+systems.lamb.dottie.vaultHeadV2;schemaVersion=2"},"suppliedContext":{"repositoryRevision":"r","repositoryDigest":"AQ==","policy":null},"head":"Ag==","snapshotKey":"00000`+
				`00000000001","sequence":1,"publicationId":"AgAAAAAAAAAAAAAAAAAAAA==","recordCid":"Aw==","blobCid":"BA==","blobSize":5,"observationDigest":"AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","acceptedEventDigest":"AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		),
		encodedPacked,
	)
	decodedPacked, err := decodeFloor(encodedPacked)
	require.NoError(t, err)
	assert.Equal(t, packed, decodedPacked)
	assert.Nil(t, decodedPacked.Showcase)

	showcase := packed
	showcase.BlobCID = nil
	showcase.BlobSize = 0
	showcase.Showcase = &ShowcasePayload{
		Entries: []PayloadEntryReference{{Path: "init.lua", CID: []byte{4}, Size: 5}},
	}
	encodedShowcase, err := encodeFloor(showcase)
	require.NoError(t, err)
	//nolint:testifylint // byte-exact wire golden: key order and spacing are the format
	assert.Equal(
		t,
		[]byte(
			`{"version":2,"databaseId":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","revision":7,"generation":2,"provenance":"first-use","anchorCid":"AQ==","binding":{"accountDid":"did:plc:abc","backend":"public-repo","repository":"at://did:plc:abc","vault":"AAAAAAAAAAAAAAA`+
				`AAAAAAAAAAAAAAAAAAAAAAAAAAAA=","profile":"systems.lamb.dottie.vaultSnapshotV2+systems.lamb.dottie.vaultHeadV2;schemaVersion=2"},"suppliedContext":{"repositoryRevision":"r","repositoryDigest":"AQ==","policy":null},"head":"Ag==","snapshotKey":"0000000000000001","se`+
				`quence":1,"publicationId":"AgAAAAAAAAAAAAAAAAAAAA==","recordCid":"Aw==","entries":[{"path":"init.lua","cid":"BA==","size":5}],"observationDigest":"AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","acceptedEventDigest":"AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		),
		encodedShowcase,
	)
	decodedShowcase, err := decodeFloor(encodedShowcase)
	require.NoError(t, err)
	require.NotNil(t, decodedShowcase.Showcase)
	assert.Equal(t, showcase.Showcase.Entries, decodedShowcase.Showcase.Entries)
	assert.Nil(t, decodedShowcase.BlobCID)
	assert.Equal(t, uint64(0), decodedShowcase.BlobSize)
	require.NoError(t, validateFloorPayload(decodedShowcase))
}

func TestShowcasePayloadCapacityLimitsRefuseAtTheDocumentedBounds(t *testing.T) {
	limits := DefaultAttemptLimits()
	assert.Equal(t, uint32(64), limits.ManagedObjects)
	assert.Equal(t, uint64(1610612736), limits.CustodyBytes)
	assert.Equal(t, uint64(262144), limits.CoreBytes)

	entry := func(index int, size uint64) PayloadEntryReference {
		return PayloadEntryReference{Path: fmt.Sprintf("%03d/init.lua", index), CID: []byte{byte(index)}, Size: size}
	}
	atObjectBound := make([]PayloadEntryReference, 0, limits.ManagedObjects)
	for index := range int(limits.ManagedObjects) {
		atObjectBound = append(atObjectBound, entry(index, 1))
	}
	require.NoError(t, validateShowcasePayloadCustody(&ShowcasePayload{Entries: atObjectBound}, limits))
	assert.Equal(t, uint32(64), (&ShowcasePayload{Entries: atObjectBound}).EntryCount())

	overObjectBound := append([]PayloadEntryReference{}, atObjectBound...)
	tightened := limits
	tightened.ManagedObjects = 8
	tightenedEntries := make([]PayloadEntryReference, 0, tightened.ManagedObjects+1)
	for index := range int(tightened.ManagedObjects) + 1 {
		tightenedEntries = append(tightenedEntries, entry(index, 1))
	}
	requireErrorMetadata(
		t,
		validateShowcasePayloadCustody(&ShowcasePayload{Entries: tightenedEntries}, tightened),
		ErrLimit,
		StageInput,
		ReasonCapacity,
	)
	assert.Contains(
		t,
		validateShowcasePayloadCustody(&ShowcasePayload{Entries: tightenedEntries}, tightened).Error(),
		"showcase managed objects: 9 exceeds 8",
	)
	requireErrorMetadata(
		t,
		validateShowcasePayloadCustody(&ShowcasePayload{Entries: overObjectBound}, tightened),
		ErrLimit,
		StageInput,
		ReasonCapacity,
	)

	overCustodyBytes := make([]PayloadEntryReference, 0, limits.ManagedObjects)
	for index := range int(limits.ManagedObjects) {
		overCustodyBytes = append(overCustodyBytes, entry(index, 30_000_000))
	}
	aggregate := (&ShowcasePayload{Entries: overCustodyBytes}).TotalBytes()
	require.Greater(t, aggregate, limits.CustodyBytes)
	requireErrorMetadata(
		t,
		validateShowcasePayloadCustody(&ShowcasePayload{Entries: overCustodyBytes}, limits),
		ErrLimit,
		StageInput,
		ReasonCapacity,
	)
	assert.Contains(
		t,
		validateShowcasePayloadCustody(&ShowcasePayload{Entries: overCustodyBytes}, limits).Error(),
		fmt.Sprintf("showcase custody bytes: %d exceeds %d", aggregate, limits.CustodyBytes),
	)

	tooManyEntries := make([]PayloadEntryReference, 0, publication.MaxSnapshotEntries+1)
	for index := range publication.MaxSnapshotEntries + 1 {
		tooManyEntries = append(tooManyEntries, entry(index, 1))
	}
	tooMany := validateShowcasePayloadCustody(&ShowcasePayload{Entries: tooManyEntries}, limits)
	requireErrorMetadata(t, tooMany, ErrLimit, StageInput, ReasonCapacity)
	assert.Contains(t, tooMany.Error(), "showcase entry count: 65 exceeds 64")
	require.ErrorIs(t, validateShowcasePayload(&ShowcasePayload{Entries: tooManyEntries}), ErrLimit)
	require.Error(t, validateShowcasePayload(&ShowcasePayload{}))
}

func TestShowcaseAttemptPayloadMustMatchItsSnapshotRecord(t *testing.T) {
	snapshot, encoded := payloadUnionShowcaseSnapshot(t)
	core := attemptCoreWire{
		Version:        attemptCoreVersion(snapshot),
		Entries:        showcasePayloadToWire(showcasePayloadOf(snapshot)),
		SnapshotRecord: encoded,
		SnapshotCID:    mustPayloadUnionRecordCID(t, encoded),
	}
	assert.Equal(t, uint32(2), attemptCoreVersion(snapshot))
	require.NoError(t, validateAttemptCorePayload(core, snapshot, DefaultAttemptLimits()))

	wrongEntries := core
	wrongEntries.Entries = []payloadEntryWire{{Path: "init.lua", CID: []byte{9}, Size: 9}}
	require.Error(t, validateAttemptCorePayload(wrongEntries, snapshot, DefaultAttemptLimits()))

	packedForm := core
	packedForm.Version = 1
	packedForm.BlobCID = []byte{9}
	packedForm.BlobSize = 9
	require.Error(t, validateAttemptCorePayload(packedForm, snapshot, DefaultAttemptLimits()))

	projected := projectAttempt(core, AttemptPrepared, OutcomeNotSubmitted, "", 1, AvailabilityUnchecked)
	require.NotNil(t, projected.Showcase)
	assert.Equal(t, uint32(2), projected.Showcase.EntryCount())
	assert.Nil(t, projected.BlobCID)
}

func TestShowcasePayloadRefusesAtConsumersThatNeedThePackedBlob(t *testing.T) {
	snapshot, encoded := payloadUnionShowcaseSnapshot(t)
	key, err := publication.SequenceKey(snapshot.PublicationSeq)
	require.NoError(t, err)
	head := publication.HeadRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          snapshot.Vault,
		PublicationSeq: snapshot.PublicationSeq,
		SnapshotCID:    mustPayloadUnionRecordCID(t, encoded),
	}
	headBytes, err := publication.EncodeHead(head)
	require.NoError(t, err)
	binding := Binding{AccountDID: "did:plc:abcdefghijklmnopqrstuvwx", Backend: BackendPublicRepo}
	binding.Repository = "at://" + binding.AccountDID
	binding.Vault = snapshot.Vault

	_, err = validateCandidateInput(
		CandidateInput{
			SnapshotKey:    key,
			SnapshotRecord: encoded,
			HeadRecord:     headBytes,
			Payload:        []byte("packed candidate payload"),
		},
		binding,
		DefaultAttemptLimits(),
	)
	requireErrorMetadata(t, err, ErrInvalid, StageInput, ReasonRecordSet)

	view, err := validateSuppliedRepositoryView(
		SuppliedRepositoryView{
			Origin:          binding,
			Scope:           ViewScopeWholeRepository,
			SuppliedContext: SuppliedContext{RepositoryRevision: "r1", RepositoryDigest: []byte{1}},
			Head:            headBytes,
			Snapshots:       []SnapshotBlock{{Key: key, Raw: encoded}},
		},
		binding,
		DefaultLimits(),
		false,
	)
	require.NoError(t, err)
	require.Len(t, view.blocks, 1)
	assert.Equal(t, encoded, view.blocks[0].raw)

	packedCID, err := publication.RawPayloadCID([]byte("packed head payload"))
	require.NoError(t, err)
	packedHead := head
	packedHead.BlobCID = packedCID
	packedHeadBytes, err := publication.EncodeHead(packedHead)
	require.NoError(t, err)
	_, err = validateSuppliedRepositoryView(
		SuppliedRepositoryView{
			Origin:          binding,
			Scope:           ViewScopeWholeRepository,
			SuppliedContext: SuppliedContext{RepositoryRevision: "r1", RepositoryDigest: []byte{1}},
			Head:            packedHeadBytes,
			Snapshots:       []SnapshotBlock{{Key: key, Raw: encoded}},
		},
		binding,
		DefaultLimits(),
		false,
	)
	requireErrorMetadata(t, err, ErrInvalid, StageInput, ReasonRecordSet)

	requireErrorMetadata(
		t,
		requirePackedAttemptCore(
			attemptCoreWire{Version: 2, Entries: []payloadEntryWire{{Path: "a", CID: []byte{1}, Size: 1}}},
			StageDispatch,
		),
		ErrUnsupported,
		StageDispatch,
		ReasonPayloadForm,
	)
	require.NoError(
		t,
		requirePackedAttemptCore(attemptCoreWire{Version: 1, BlobCID: []byte{1}, BlobSize: 1}, StageDispatch),
	)
}

func TestShowcaseEvidenceHeadBindingBranchesOnPayloadForm(t *testing.T) {
	snapshot, _ := payloadUnionShowcaseSnapshot(t)
	showcaseHead := publication.HeadRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          snapshot.Vault,
		PublicationSeq: snapshot.PublicationSeq,
	}
	require.NoError(t, headPayloadMatchesRecord(showcaseHead, snapshot))
	packedHead := showcaseHead
	packedHead.BlobCID = []byte{9}
	require.Error(t, headPayloadMatchesRecord(packedHead, snapshot))

	packedSnapshot := publication.SnapshotRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          snapshot.Vault,
		PublicationID:  snapshot.PublicationID,
		PublicationSeq: snapshot.PublicationSeq,
		Blob:           publication.BlobReference{CID: []byte{7}, Size: 3, MIMEType: publication.BlobMIMEType},
	}
	packedHeader := publication.HeadRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          snapshot.Vault,
		PublicationSeq: snapshot.PublicationSeq,
		BlobCID:        []byte{7},
	}
	require.NoError(t, headPayloadMatchesRecord(packedHeader, packedSnapshot))
	packedHeader.BlobCID = []byte{8}
	require.Error(t, headPayloadMatchesRecord(packedHeader, packedSnapshot))
	require.Error(t, headPayloadMatchesRecord(showcaseHead, packedSnapshot))
}

func payloadUnionFloor(t *testing.T) Floor {
	t.Helper()
	var databaseID [32]byte
	var publicationID [16]byte
	var digest [32]byte
	databaseID[0] = 1
	publicationID[0] = 2
	digest[0] = 3
	binding := Binding{AccountDID: "did:plc:abc", Backend: BackendPublicRepo, Repository: "at://did:plc:abc"}
	return Floor{
		DatabaseID:          databaseID,
		Revision:            7,
		Generation:          2,
		Provenance:          ProvenanceFirst,
		AnchorCID:           []byte{1},
		Binding:             binding,
		SuppliedContext:     SuppliedContext{RepositoryRevision: "r", RepositoryDigest: []byte{1}},
		Head:                []byte{2},
		SnapshotKey:         "0000000000000001",
		Sequence:            1,
		PublicationID:       publicationID,
		RecordCID:           []byte{3},
		BlobCID:             []byte{4},
		BlobSize:            5,
		ObservationDigest:   digest,
		AcceptedEventDigest: digest,
	}
}

func payloadUnionShowcaseSnapshot(t *testing.T) (publication.SnapshotRecord, []byte) {
	t.Helper()
	entries := make([]publication.SnapshotEntry, 0, 2)
	for index, content := range [][]byte{[]byte("showcase init"), []byte("showcase options")} {
		cid, err := publication.RawPayloadCID(content)
		require.NoError(t, err)
		entries = append(entries, publication.SnapshotEntry{
			Path: []string{"init.lua", "lua/config/options.lua"}[index],
			Mode: 0o600,
			Size: uint64(len(content)),
			Kind: publication.SnapshotEntryKindFile,
			Blob: publication.BlobReference{CID: cid, Size: uint64(len(content)), MIMEType: publication.BlobMIMEType},
		})
	}
	var vault [32]byte
	vault[0] = 9
	record := publication.SnapshotRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          vault,
		PublicationSeq: 0,
		Parent:         []byte{},
		Entries:        entries,
	}
	record.PublicationID[0] = 0x42
	encoded, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	return record, encoded
}

func mustPayloadUnionRecordCID(t *testing.T, encoded []byte) []byte {
	t.Helper()
	identifier, err := publication.RecordCID(encoded)
	require.NoError(t, err)
	return identifier
}
