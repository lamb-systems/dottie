package service

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
	"github.com/lamb-systems/dottie/internal/remote/atproto/atprototest"
	"github.com/lamb-systems/dottie/internal/vault"
)

const publicationReaderBlobEndpoint = "com.atproto.sync.getBlob"

type publicationReaderTransport struct {
	*atprotoMaterialRepository

	doCalls     int
	streams     int
	blobStreams int
}

func newPublicationReaderTransport(repository *atprotoMaterialRepository) *publicationReaderTransport {
	return &publicationReaderTransport{atprotoMaterialRepository: repository}
}

func (transport *publicationReaderTransport) Do(
	ctx context.Context,
	method, endpoint string,
	query url.Values,
	body []byte,
	contentType string,
) (int, []byte, error) {
	transport.doCalls++
	return transport.atprotoMaterialRepository.Do(ctx, method, endpoint, query, body, contentType)
}

func (transport *publicationReaderTransport) OpenStream(
	ctx context.Context,
	endpoint string,
	query url.Values,
) (int, io.ReadCloser, error) {
	transport.streams++
	if endpoint != publicationReaderBlobEndpoint {
		return transport.atprotoMaterialRepository.OpenStream(ctx, endpoint, query)
	}
	transport.blobStreams++
	identifier, err := cid.Parse(query.Get("cid"))
	if err != nil {
		// A malformed CID is served like a missing blob: a 404 response, not a transport failure.
		return publicationReaderBlobNotFound()
	}
	blob := transport.blob(identifier.Bytes())
	if blob == nil {
		return publicationReaderBlobNotFound()
	}
	return 200, io.NopCloser(bytes.NewReader(blob)), nil
}

func publicationReaderBlobNotFound() (int, io.ReadCloser, error) {
	return 404, io.NopCloser(strings.NewReader(`{"error":"NotFound"}`)), nil
}

func (transport *publicationReaderTransport) storeBlob(t *testing.T, payload []byte) []byte {
	t.Helper()
	blob, err := atprototest.BuildBlob(payload)
	require.NoError(t, err)
	transport.mu.Lock()
	transport.blobs[blob.CID.String()] = bytes.Clone(payload)
	transport.mu.Unlock()
	return blob.CID.Bytes()
}

type publicationReaderFixture struct {
	binding    publicationstate.Binding
	repository *atprotoMaterialRepository
	transport  *publicationReaderTransport
	adapter    *ATProtoMaterialTransport
	session    *atproto.Session
	reader     *PublicationReader
}

func newPublicationReaderFixture(t *testing.T, repository *atprotoMaterialRepository) *publicationReaderFixture {
	t.Helper()
	binding := atprotoMaterialBinding(atprotoMaterialDID)
	transport := newPublicationReaderTransport(repository)
	adapter, err := NewATProtoMaterialTransport(ATProtoMaterialConfig{
		Binding: binding, DID: atprotoMaterialDID, Reader: repository.reader(),
		Transport: transport, BlobUploadLimit: atprotoMaterialUploadCap,
	})
	require.NoError(t, err)
	fixture := &publicationReaderFixture{
		binding: binding, repository: repository, transport: transport, adapter: adapter,
		session: &atproto.Session{DID: atprotoMaterialDID, Scopes: atproto.VaultScopes()},
	}
	fixture.reader = fixture.readerWith(t, binding, atprotoMaterialDID, fixture.session, adapter)
	return fixture
}

func (fixture *publicationReaderFixture) readerWith(
	t *testing.T,
	binding publicationstate.Binding,
	did string,
	session *atproto.Session,
	adapter *ATProtoMaterialTransport,
) *PublicationReader {
	t.Helper()
	reader, err := NewPublicationReader(PublicationReaderConfig{
		Binding: binding, DID: did, Session: session, Adapter: adapter,
		Blobs: atproto.VaultReader{Transport: fixture.transport, Budgets: atproto.DefaultBudgets()},
	})
	require.NoError(t, err)
	return reader
}

func (fixture *publicationReaderFixture) legacyScopeSession() *atproto.Session {
	scopes := make([]string, 0, len(atproto.VaultScopes()))
	for _, scope := range atproto.VaultScopes() {
		if scope == "repo:"+publication.HeadNSID || scope == "repo:"+publication.SnapshotNSID {
			continue
		}
		scopes = append(scopes, scope)
	}
	return &atproto.Session{DID: atprotoMaterialDID, Scopes: scopes}
}

func (fixture *publicationReaderFixture) requireNoTransportUse(t *testing.T) {
	t.Helper()
	assert.Equal(t, 0, fixture.transport.doCalls)
	assert.Equal(t, 0, fixture.transport.streams)
	assert.Equal(t, 0, fixture.transport.blobStreams)
}

func (fixture *publicationReaderFixture) records(
	t *testing.T,
	payload []byte,
	declaredSize uint64,
) map[atproto.RecordKey][]byte {
	t.Helper()
	blobCID, err := publication.RawPayloadCID(payload)
	require.NoError(t, err)
	key, err := publication.SequenceKey(0)
	require.NoError(t, err)
	snapshotRecord, err := publication.EncodeSnapshot(publication.SnapshotRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          fixture.binding.Vault,
		PublicationID:  [16]byte{0x62, 0x01},
		PublicationSeq: 0,
		Blob: publication.BlobReference{
			CID:      blobCID,
			Size:     declaredSize,
			MIMEType: publication.SnapshotBlobMIMEType,
		},
	})
	require.NoError(t, err)
	snapshotCID, err := publication.RecordCID(snapshotRecord)
	require.NoError(t, err)
	headRecord, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: fixture.binding.Vault, PublicationSeq: 0,
		SnapshotCID: snapshotCID, BlobCID: blobCID,
	})
	require.NoError(t, err)
	return map[atproto.RecordKey][]byte{
		{Collection: publication.SnapshotNSID, RKey: key}:         snapshotRecord,
		{Collection: publication.HeadNSID, RKey: materialHeadKey}: headRecord,
	}
}

func TestPublicationReaderReturnsTheAdapterViewAndAcceptedPayload(t *testing.T) {
	ctx := context.Background()
	publisher := newATProtoMaterialFixture(t)
	proposal, _ := publisher.publish(t)
	fixture := newPublicationReaderFixture(t, publisher.repository)

	view, err := fixture.reader.ReadView(ctx)
	require.NoError(t, err)
	assert.Equal(t, fixture.binding, view.Origin)
	assert.Equal(t, publicationstate.ViewScopeWholeRepository, view.Scope)
	require.Len(t, view.Snapshots, 1)
	assert.Equal(t, proposal.Batch.SnapshotRecord, view.Snapshots[0].Raw)
	assert.Equal(t, proposal.Batch.HeadRecord, view.Head)

	accepted, err := fixture.reader.ReadAcceptedPayload(ctx)
	require.NoError(t, err)
	assert.Equal(t, view.Head, accepted.View.Head)
	assert.Equal(t, view.Snapshots, accepted.View.Snapshots)
	assert.Equal(t, publication.PayloadFormPacked, accepted.Payload.Form)
	assert.Equal(t, publisher.snapshot, accepted.Payload.Snapshot)
	assert.Empty(t, accepted.Payload.Entries)
	assert.Equal(t, 1, fixture.transport.blobStreams)
}

func TestPublicationReaderRefusesForeignIdentityBeforeAnyRead(t *testing.T) {
	ctx := context.Background()
	foreignBinding := atprotoMaterialBinding(atprotoMaterialOtherDID)
	foreignVault := atprotoMaterialBinding(atprotoMaterialDID)
	foreignVault.Vault = [32]byte{0x81, 0x82, 0x83}

	cases := []struct {
		name    string
		binding publicationstate.Binding
		did     string
		session *atproto.Session
	}{
		{
			name:    "configured-did-foreign",
			binding: foreignBinding,
			did:     atprotoMaterialOtherDID,
			session: &atproto.Session{DID: atprotoMaterialOtherDID, Scopes: atproto.VaultScopes()},
		},
		{
			name:    "configured-vault-foreign",
			binding: foreignVault,
			did:     atprotoMaterialDID,
			session: &atproto.Session{DID: atprotoMaterialDID, Scopes: atproto.VaultScopes()},
		},
		{
			name:    "session-for-foreign-did",
			binding: atprotoMaterialBinding(atprotoMaterialDID),
			did:     atprotoMaterialDID,
			session: &atproto.Session{DID: atprotoMaterialOtherDID, Scopes: atproto.VaultScopes()},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newPublicationReaderFixture(t, newATProtoMaterialRepository(t, atprotoMaterialDID))
			reader := fixture.readerWith(t, testCase.binding, testCase.did, testCase.session, fixture.adapter)

			view, err := reader.ReadView(ctx)
			require.ErrorIs(t, err, ErrPublicationReaderIdentity)
			assert.Equal(t, publicationstate.SuppliedRepositoryView{}, view)
			_, err = reader.ReadAcceptedPayload(ctx)
			require.ErrorIs(t, err, ErrPublicationReaderIdentity)
			fixture.requireNoTransportUse(t)
		})
	}

	t.Run("nil-adapter", func(t *testing.T) {
		_, err := NewPublicationReader(
			PublicationReaderConfig{DID: atprotoMaterialDID, Session: &atproto.Session{DID: atprotoMaterialDID}},
		)
		require.ErrorIs(t, err, ErrPublicationReaderInput)
	})
}

func TestPublicationReaderRefusesLegacyScopeSessionBeforeAnyRead(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationReaderFixture(t, newATProtoMaterialRepository(t, atprotoMaterialDID))
	reader := fixture.readerWith(t, fixture.binding, atprotoMaterialDID, fixture.legacyScopeSession(), fixture.adapter)

	view, err := reader.ReadView(ctx)
	require.ErrorIs(t, err, atproto.ErrInsufficientPublicationScope)
	var refusal *atproto.PublicationScopeError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, atproto.PublicationScopes(), refusal.Missing)
	assert.Contains(t, err.Error(), "sign in again")
	assert.Equal(t, publicationstate.SuppliedRepositoryView{}, view)

	_, err = reader.ReadAcceptedPayload(ctx)
	require.ErrorIs(t, err, atproto.ErrInsufficientPublicationScope)
	fixture.requireNoTransportUse(t)
}

func TestPublicationReaderPropagatesAdapterViewRefusals(t *testing.T) {
	binding := atprotoMaterialBinding(atprotoMaterialDID)
	snapshotKey := func(t *testing.T, sequence uint64) atproto.RecordKey {
		t.Helper()
		key, err := publication.SequenceKey(sequence)
		require.NoError(t, err)
		return atproto.RecordKey{Collection: publication.SnapshotNSID, RKey: key}
	}
	cases := []struct {
		name     string
		reason   string
		want     error
		records  func(t *testing.T) map[atproto.RecordKey][]byte
		readers  func(t *testing.T, repository *atprotoMaterialRepository) atproto.RevisionReader
		serveCar func(t *testing.T, repository *atprotoMaterialRepository) []byte
	}{
		{
			name: "foreign-signing-key", reason: "revision", want: atproto.ErrSignature,
			records: func(t *testing.T) map[atproto.RecordKey][]byte {
				return atprotoMaterialGenesisRecords(t, binding)
			},
			readers: func(t *testing.T, repository *atprotoMaterialRepository) atproto.RevisionReader {
				foreign := newATProtoMaterialRepository(t, atprotoMaterialDID)
				return atproto.RevisionReader{
					Transport: repository, DIDDocumentID: atprotoMaterialDID,
					VerificationMethods: foreign.verificationMethods(),
				}
			},
		},
		{
			name: "tampered-car", reason: "revision", want: atproto.ErrUntrustedCar,
			records: func(t *testing.T) map[atproto.RecordKey][]byte {
				return atprotoMaterialGenesisRecords(t, binding)
			},
			serveCar: func(t *testing.T, repository *atprotoMaterialRepository) []byte {
				genesis := atprotoMaterialGenesisRecords(t, binding)
				committed, err := publication.RecordCID(genesis[snapshotKey(t, 0)])
				require.NoError(t, err)
				identifier, err := cid.Cast(committed)
				require.NoError(t, err)
				substitute := materialTestCandidate(
					t,
					binding,
					[16]byte{0x62, 0x11},
					0,
					nil,
					[]byte("synthetic substitute payload"),
				)
				return atprotoMaterialTamperSnapshot(t, repository.car(), identifier, substitute.SnapshotRecord)
			},
		},
		{
			name: "broken-chain", reason: "chain",
			records: func(t *testing.T) map[atproto.RecordKey][]byte {
				first, _ := atprotoMaterialRecords(t, binding, [16]byte{0x62, 0x12}, 0, nil)
				firstCID, err := publication.RecordCID(first)
				require.NoError(t, err)
				third, head := atprotoMaterialRecords(t, binding, [16]byte{0x62, 0x13}, 2, firstCID)
				return map[atproto.RecordKey][]byte{
					snapshotKey(t, 0): first,
					snapshotKey(t, 2): third,
					{Collection: publication.HeadNSID, RKey: materialHeadKey}: head,
				}
			},
		},
		{
			name: "foreign-vault", reason: "vault",
			records: func(t *testing.T) map[atproto.RecordKey][]byte {
				foreign := binding
				foreign.Vault = [32]byte{0x83, 0x84, 0x85}
				return atprotoMaterialGenesisRecords(t, foreign)
			},
		},
		{
			name: "legacy-record", reason: "legacy_profile",
			records: func(t *testing.T) map[atproto.RecordKey][]byte {
				records := atprotoMaterialGenesisRecords(t, binding)
				legacy, err := atprototest.BuildRecord(
					atproto.VaultSnapshotNSID,
					"self",
					map[string]any{"schemaVersion": int64(1)},
				)
				require.NoError(t, err)
				records[atproto.RecordKey{Collection: atproto.VaultSnapshotNSID, RKey: "self"}] = legacy.Data
				return records
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			repository := newATProtoMaterialRepository(t, atprotoMaterialDID)
			repository.setRecords(t, testCase.records(t))
			fixture := newPublicationReaderFixture(t, repository)
			adapter := fixture.adapter
			if testCase.readers != nil {
				adapter = newATProtoMaterialAdapter(t, fixture, testCase.readers(t, repository))
			}
			if testCase.serveCar != nil {
				repository.serveCar(t, testCase.serveCar(t, repository))
			}
			reader := fixture.readerWith(t, binding, atprotoMaterialDID, fixture.session, adapter)

			accepted, err := reader.ReadAcceptedPayload(context.Background())
			requireATProtoMaterialRefusal(t, err, ErrATProtoMaterialView, testCase.reason)
			require.ErrorIs(t, err, ErrATProtoMaterialView)
			if testCase.want != nil {
				require.ErrorIs(t, err, testCase.want)
			}
			assert.Equal(t, AcceptedPublication{}, accepted)
			assert.Equal(t, 0, fixture.transport.blobStreams)
		})
	}
}

func newATProtoMaterialAdapter(
	t *testing.T,
	fixture *publicationReaderFixture,
	reader atproto.RevisionReader,
) *ATProtoMaterialTransport {
	t.Helper()
	adapter, err := NewATProtoMaterialTransport(ATProtoMaterialConfig{
		Binding: fixture.binding, DID: atprotoMaterialDID, Reader: reader,
		Transport: fixture.transport, BlobUploadLimit: atprotoMaterialUploadCap,
	})
	require.NoError(t, err)
	return adapter
}

func TestPublicationReaderRefusesPayloadAtTheRejectingLayer(t *testing.T) {
	ctx := context.Background()

	t.Run("wrong-cid", func(t *testing.T) {
		publisher := newATProtoMaterialFixture(t)
		proposal, _ := publisher.publish(t)
		fixture := newPublicationReaderFixture(t, publisher.repository)
		record, err := publication.DecodeSnapshot(proposal.Batch.SnapshotRecord)
		require.NoError(t, err)
		identifier, err := cid.Cast(record.Blob.CID)
		require.NoError(t, err)
		fixture.transport.mu.Lock()
		fixture.transport.blobs[identifier.String()] = bytes.Repeat([]byte{0x5a}, int(record.Blob.Size))
		fixture.transport.mu.Unlock()

		_, err = fixture.reader.ReadAcceptedPayload(ctx)
		require.ErrorIs(t, err, ErrPublicationReaderAccepted)
		require.ErrorIs(t, err, atproto.ErrReadBlobCIDMismatch)
	})

	t.Run("wrong-size", func(t *testing.T) {
		fixture := newPublicationReaderFixture(t, newATProtoMaterialRepository(t, atprotoMaterialDID))
		packed := materialTestPackedPayload(t)
		fixture.transport.storeBlob(t, packed)
		fixture.repository.setRecords(t, fixture.records(t, packed, uint64(len(packed)-1)))

		_, err := fixture.reader.ReadAcceptedPayload(ctx)
		require.ErrorIs(t, err, ErrPublicationReaderAccepted)
		require.ErrorIs(t, err, atproto.ErrReadBlobSizeMismatch)
	})

	t.Run("malformed-ustar", func(t *testing.T) {
		fixture := newPublicationReaderFixture(t, newATProtoMaterialRepository(t, atprotoMaterialDID))
		malformed := publicationReaderMalformedPayload(t)
		fixture.transport.storeBlob(t, malformed)
		fixture.repository.setRecords(t, fixture.records(t, malformed, uint64(len(malformed))))

		_, err := fixture.reader.ReadAcceptedPayload(ctx)
		require.ErrorIs(t, err, ErrPublicationReaderAccepted)
		require.ErrorIs(t, err, vault.ErrInvalidPayload)
		require.NotErrorIs(t, err, publication.ErrPayload)
		require.NotErrorIs(t, err, atproto.ErrReadBlobCIDMismatch)
		var payloadError *vault.PayloadError
		require.ErrorAs(t, err, &payloadError)
		assert.Equal(t, "validate", payloadError.Stage)
	})

	t.Run("empty-repository", func(t *testing.T) {
		fixture := newPublicationReaderFixture(t, newATProtoMaterialRepository(t, atprotoMaterialDID))
		view, err := fixture.reader.ReadView(ctx)
		require.NoError(t, err)
		assert.Empty(t, view.Snapshots)
		_, err = fixture.reader.ReadAcceptedPayload(ctx)
		require.ErrorIs(t, err, ErrPublicationReaderAccepted)
		require.ErrorIs(t, err, atproto.ErrReadRecordMissing)
		assert.Equal(t, 0, fixture.transport.blobStreams)
	})
}

func materialTestPackedPayload(t *testing.T) []byte {
	t.Helper()
	packed, err := vault.Pack(materialTestSnapshot("synthetic accepted payload"))
	require.NoError(t, err)
	return packed.Payload
}

func publicationReaderMalformedPayload(t *testing.T) []byte {
	t.Helper()
	packed := materialTestPackedPayload(t)
	input := bytes.NewReader(packed)
	archive := tar.NewReader(input)
	header, err := archive.Next()
	require.NoError(t, err)
	require.NotNil(t, header)
	_, err = io.Copy(io.Discard, archive)
	require.NoError(t, err)
	manifestEnd := len(packed) - input.Len()
	require.Greater(t, manifestEnd, 512)
	require.Less(t, manifestEnd, len(packed))
	malformed := bytes.Clone(packed[:manifestEnd])
	_, unpackErr := vault.UnpackPayload(malformed)
	require.ErrorIs(t, unpackErr, vault.ErrInvalidPayload)
	var payloadError *vault.PayloadError
	require.ErrorAs(t, unpackErr, &payloadError)
	assert.Equal(t, "validate", payloadError.Stage)
	return malformed
}

type publicationReaderManifestFile struct {
	path    string
	mode    uint32
	content []byte
}

func (fixture *publicationReaderFixture) manifestPublication(
	t *testing.T,
	files ...publicationReaderManifestFile,
) (publication.SnapshotRecord, map[string][]byte) {
	t.Helper()
	entries := make([]publication.SnapshotEntry, 0, len(files))
	contents := make(map[string][]byte, len(files))
	for _, file := range files {
		blobCID := fixture.transport.storeBlob(t, file.content)
		entries = append(entries, publication.SnapshotEntry{
			Path: file.path, Mode: file.mode, Size: uint64(len(file.content)),
			Kind: publication.SnapshotEntryKindFile,
			Blob: publication.BlobReference{
				CID: blobCID, Size: uint64(len(file.content)), MIMEType: publication.BlobMIMEType,
			},
		})
		contents[file.path] = file.content
	}
	record := publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: fixture.binding.Vault,
		PublicationID: [16]byte{0x62, 0x21}, Entries: entries,
	}
	snapshotRecord, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	snapshotCID, err := publication.RecordCID(snapshotRecord)
	require.NoError(t, err)
	headRecord, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: fixture.binding.Vault, SnapshotCID: snapshotCID,
	})
	require.NoError(t, err)
	key, err := publication.SequenceKey(0)
	require.NoError(t, err)
	fixture.repository.setRecords(t, map[atproto.RecordKey][]byte{
		{Collection: publication.SnapshotNSID, RKey: key}:         snapshotRecord,
		{Collection: publication.HeadNSID, RKey: materialHeadKey}: headRecord,
	})
	return record, contents
}

func (fixture *publicationReaderFixture) forgetBlob(content []byte) {
	blob, err := atprototest.BuildBlob(content)
	if err != nil {
		panic(err)
	}
	fixture.transport.mu.Lock()
	delete(fixture.transport.blobs, blob.CID.String())
	fixture.transport.mu.Unlock()
}

func (fixture *publicationReaderFixture) substituteBlob(content, substitute []byte) {
	blob, err := atprototest.BuildBlob(content)
	if err != nil {
		panic(err)
	}
	fixture.transport.mu.Lock()
	fixture.transport.blobs[blob.CID.String()] = bytes.Clone(substitute)
	fixture.transport.mu.Unlock()
}

func fixtureManifestFiles() []publicationReaderManifestFile {
	return []publicationReaderManifestFile{
		{path: "init.lua", mode: 0o600, content: []byte("synthetic manifest init")},
		{path: "lua/config/options.lua", mode: 0o644, content: []byte("synthetic manifest options")},
	}
}

func TestPublicationReaderReadsAManifestPublicationWithVerifiedEntries(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationReaderFixture(t, newATProtoMaterialRepository(t, atprotoMaterialDID))
	fixture.manifestPublication(t, fixtureManifestFiles()...)

	view, err := fixture.reader.ReadView(ctx)
	require.NoError(t, err)
	require.Len(t, view.Snapshots, 1)
	headRecord, err := publication.DecodeHead(view.Head)
	require.NoError(t, err)
	assert.Empty(t, headRecord.BlobCID)

	accepted, err := fixture.reader.ReadAcceptedPayload(ctx)
	require.NoError(t, err)
	assert.Equal(t, view.Head, accepted.View.Head)
	assert.Equal(t, publication.PayloadFormManifest, accepted.Payload.Form)
	assert.Equal(t, model.Snapshot{}, accepted.Payload.Snapshot)
	require.Len(t, accepted.Payload.Entries, 2)
	assert.Equal(t, "init.lua", accepted.Payload.Entries[0].Path)
	assert.Equal(t, uint32(0o600), accepted.Payload.Entries[0].Mode)
	assert.Equal(t, []byte("synthetic manifest init"), accepted.Payload.Entries[0].Content)
	assert.Equal(t, "lua/config/options.lua", accepted.Payload.Entries[1].Path)
	assert.Equal(t, uint32(0o644), accepted.Payload.Entries[1].Mode)
	assert.Equal(t, []byte("synthetic manifest options"), accepted.Payload.Entries[1].Content)
	assert.Equal(t, uint64(len("synthetic manifest init")), accepted.Payload.Entries[0].Size)
	assert.Equal(t, uint64(len("synthetic manifest options")), accepted.Payload.Entries[1].Size)
	assert.Equal(t, 2, fixture.transport.blobStreams)

	snapshot, err := accepted.Payload.PackedSnapshot()
	assert.Equal(t, model.Snapshot{}, snapshot)
	require.ErrorIs(t, err, publication.ErrManifestPayload)
}

func TestPublicationReaderRefusesAMissingManifestEntryBlobNamingThePath(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationReaderFixture(t, newATProtoMaterialRepository(t, atprotoMaterialDID))
	files := fixtureManifestFiles()
	fixture.manifestPublication(t, files...)
	fixture.forgetBlob(files[1].content)

	accepted, err := fixture.reader.ReadAcceptedPayload(ctx)
	assert.Equal(t, AcceptedPublication{}, accepted, "a partially fetched manifest payload was exposed")
	require.ErrorIs(t, err, ErrPublicationReaderAccepted)
	require.ErrorIs(t, err, publication.ErrManifestPayload)
	require.ErrorIs(t, err, atproto.ErrReadBlobMissing)
	var refusal *publication.ManifestPayloadError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, files[1].path, refusal.EntryPath())
	assert.Equal(t, publication.ManifestReasonUnavailable, refusal.Reason)
	assert.Contains(t, err.Error(), files[1].path)
	assert.Equal(t, 2, fixture.transport.blobStreams, "the reader kept fetching after the refused entry")
}

func TestPublicationReaderRefusesAMismatchedManifestEntryNamingThePath(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationReaderFixture(t, newATProtoMaterialRepository(t, atprotoMaterialDID))
	files := fixtureManifestFiles()
	fixture.manifestPublication(t, files...)
	fixture.substituteBlob(files[1].content, files[1].content[:len(files[1].content)-1])

	accepted, err := fixture.reader.ReadAcceptedPayload(ctx)
	assert.Equal(t, AcceptedPublication{}, accepted, "a partially fetched manifest payload was exposed")
	require.ErrorIs(t, err, ErrPublicationReaderAccepted)
	require.ErrorIs(t, err, publication.ErrManifestPayload)
	require.ErrorIs(t, err, atproto.ErrReadBlobTruncated)
	var refusal *publication.ManifestPayloadError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, files[1].path, refusal.EntryPath())
	assert.Contains(t, err.Error(), files[1].path)
}

func TestPublicationReaderRefusesAManifestPayloadWithAPartiallyAvailableEntrySet(t *testing.T) {
	ctx := context.Background()
	fixture := newPublicationReaderFixture(t, newATProtoMaterialRepository(t, atprotoMaterialDID))
	files := append(
		fixtureManifestFiles(),
		publicationReaderManifestFile{path: "lua/plugin/manifest.lua", mode: 0o600, content: []byte("manifest plugin")},
	)
	fixture.manifestPublication(t, files...)
	fixture.forgetBlob(files[2].content)

	accepted, err := fixture.reader.ReadAcceptedPayload(ctx)
	assert.Equal(t, AcceptedPublication{}, accepted, "an incomplete manifest payload was exposed")
	assert.Empty(t, accepted.Payload.Entries)
	require.ErrorIs(t, err, publication.ErrManifestPayload)
	var refusal *publication.ManifestPayloadError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, files[2].path, refusal.EntryPath())
	assert.Equal(t, 3, fixture.transport.blobStreams)
}
