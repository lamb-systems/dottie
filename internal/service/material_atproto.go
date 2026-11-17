package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/remote/atproto"
)

var _ MaterialTransport = (*ATProtoMaterialTransport)(nil)

var (
	ErrATProtoMaterialIdentity    = errors.New("AT Protocol material refuses the bound identity")
	ErrATProtoMaterialBatch       = errors.New("AT Protocol material refuses the write batch")
	ErrATProtoMaterialPayload     = errors.New("AT Protocol material refuses the payload")
	ErrATProtoMaterialPrepared    = errors.New("AT Protocol material holds no dispatchable write for that value")
	ErrATProtoMaterialView        = errors.New("AT Protocol material refuses the repository view")
	ErrATProtoMaterialProvider    = errors.New("AT Protocol material provider outcome was not a commit")
	ErrMaterialSubmissionRejected = errors.New(
		"the provider definitively refused the submission batch and committed no record",
	)
)

const (
	atprotoMaterialUploadEndpoint = "com.atproto.repo.uploadBlob"
	atprotoMaterialApplyEndpoint  = "com.atproto.repo.applyWrites"
	atprotoMaterialCreateAction   = "com.atproto.repo.applyWrites#create"
	atprotoMaterialUpdateAction   = "com.atproto.repo.applyWrites#update"
	atprotoMaterialBlobType       = "blob"
)

var atprotoMaterialLegacyCollections = map[string]struct{}{
	atproto.VaultHeadNSID:        {},
	atproto.VaultControlNSID:     {},
	atproto.VaultSnapshotNSID:    {},
	atproto.VaultPolicyNSID:      {},
	atproto.VaultCertificateNSID: {},
	atproto.VaultCheckpointNSID:  {},
	atproto.VaultAttestationNSID: {},
}

type atprotoMaterialError struct {
	class  error
	reason string
	cause  error
}

func (e *atprotoMaterialError) Error() string { return e.class.Error() + ": " + e.reason }

func (e *atprotoMaterialError) Unwrap() error { return errors.Join(e.class, e.cause) }

func (e *atprotoMaterialError) Class() error { return e.class }

func (e *atprotoMaterialError) Reason() string { return e.reason }

func atprotoMaterialRefusal(class error, reason string, cause error) error {
	return &atprotoMaterialError{class: class, reason: reason, cause: cause}
}

type atprotoMaterialPreparedWrites struct {
	mu     sync.Mutex
	writes map[string][]byte
}

func (prepared *atprotoMaterialPreparedWrites) retain(body []byte) (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	token := hex.EncodeToString(secret)
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if prepared.writes == nil {
		prepared.writes = make(map[string][]byte)
	}
	prepared.writes[token] = bytes.Clone(body)
	return token, nil
}

func (prepared *atprotoMaterialPreparedWrites) take(secret string) ([]byte, bool) {
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	body, retained := prepared.writes[secret]
	if !retained {
		return nil, false
	}
	delete(prepared.writes, secret)
	return body, true
}

type ATProtoMaterialConfig struct {
	Binding         publicationstate.Binding
	DID             string
	Reader          atproto.RevisionReader
	Transport       atproto.Transport
	BlobUploadLimit int64
}

type ATProtoMaterialTransport struct {
	binding         publicationstate.Binding
	did             string
	reader          atproto.RevisionReader
	transport       atproto.Transport
	blobUploadLimit int64
	prepared        *atprotoMaterialPreparedWrites
}

func NewATProtoMaterialTransport(config ATProtoMaterialConfig) (*ATProtoMaterialTransport, error) {
	transport := &ATProtoMaterialTransport{
		binding: config.Binding, did: config.DID, reader: config.Reader,
		transport: config.Transport, blobUploadLimit: config.BlobUploadLimit,
		prepared: &atprotoMaterialPreparedWrites{writes: make(map[string][]byte)},
	}
	if err := transport.join(); err != nil {
		return nil, err
	}
	if atprotoMaterialPayloadLimit(transport.blobUploadLimit) == 0 {
		return nil, atprotoMaterialRefusal(ErrATProtoMaterialPayload, "payload_limit", nil)
	}
	return transport, nil
}

func (transport *ATProtoMaterialTransport) join() error {
	if transport == nil || transport.prepared == nil || transport.transport == nil ||
		transport.reader.Transport == nil {
		return atprotoMaterialRefusal(ErrATProtoMaterialIdentity, "identity", nil)
	}
	if transport.did == "" || len(transport.did) > 2048 || transport.binding.AccountDID != transport.did {
		return atprotoMaterialRefusal(ErrATProtoMaterialIdentity, "identity", nil)
	}
	did, err := syntax.ParseDID(transport.did)
	if err != nil || did.String() != transport.did {
		return atprotoMaterialRefusal(ErrATProtoMaterialIdentity, "identity", nil)
	}
	if transport.binding.Backend != publicationstate.BackendPublicRepo {
		return atprotoMaterialRefusal(ErrATProtoMaterialIdentity, "identity", nil)
	}
	if transport.binding.Repository != "at://"+transport.did || transport.binding.Vault == ([32]byte{}) {
		return atprotoMaterialRefusal(ErrATProtoMaterialIdentity, "identity", nil)
	}
	if transport.reader.DIDDocumentID != transport.did {
		return atprotoMaterialRefusal(ErrATProtoMaterialIdentity, "identity", nil)
	}
	return nil
}

func (transport *ATProtoMaterialTransport) UploadPayload(
	ctx context.Context,
	payload []byte,
) (publication.BlobReference, error) {
	if err := transport.join(); err != nil {
		return publication.BlobReference{}, err
	}
	if err := ctx.Err(); err != nil {
		return publication.BlobReference{}, atprotoMaterialRefusal(ErrATProtoMaterialPayload, "canceled", err)
	}
	if len(payload) == 0 || uint64(len(payload)) > atprotoMaterialPayloadLimit(transport.blobUploadLimit) {
		return publication.BlobReference{}, atprotoMaterialRefusal(ErrATProtoMaterialPayload, "payload_size", nil)
	}
	payloadCID, err := publication.RawPayloadCID(payload)
	if err != nil {
		return publication.BlobReference{}, atprotoMaterialRefusal(ErrATProtoMaterialPayload, "payload_cid", err)
	}
	status, response, err := transport.transport.Do(
		ctx,
		"POST",
		atprotoMaterialUploadEndpoint,
		nil,
		payload,
		publication.BlobMIMEType,
	)
	if err != nil {
		if status >= 400 && status < 500 {
			return publication.BlobReference{}, atprotoMaterialRefusal(
				ErrATProtoMaterialProvider,
				"upload_rejected",
				atprotoMaterialUploadStatus(status, response),
			)
		}
		return publication.BlobReference{}, atprotoMaterialRefusal(
			ErrATProtoMaterialProvider,
			"upload_ambiguous",
			atprotoMaterialAmbiguous(ctx),
		)
	}
	if status < 200 || status >= 300 {
		return publication.BlobReference{}, atprotoMaterialRefusal(
			ErrATProtoMaterialProvider,
			"upload_rejected",
			atprotoMaterialUploadStatus(status, response),
		)
	}
	reference, err := atprotoMaterialUploadReference(response)
	if err != nil {
		return publication.BlobReference{}, atprotoMaterialRefusal(ErrATProtoMaterialProvider, "upload_ambiguous",
			errors.Join(atproto.ErrAmbiguousTransport, atproto.ErrCandidateMayBeDisclosed, err))
	}
	if reference.mimeType == "" {
		return publication.BlobReference{}, atprotoMaterialRefusal(
			ErrATProtoMaterialProvider,
			"upload_reference_mime:empty",
			errors.Join(
				atproto.ErrCandidateMayBeDisclosed,
				errors.New("provider blob reference reports no media type"),
			),
		)
	}
	if reference.size != uint64(len(payload)) {
		return publication.BlobReference{}, atprotoMaterialRefusal(
			ErrATProtoMaterialProvider,
			"upload_reference_size",
			errors.Join(
				atproto.ErrCandidateMayBeDisclosed,
				fmt.Errorf(
					"provider blob reference reports %d bytes for a %d byte payload",
					reference.size,
					len(payload),
				),
			),
		)
	}
	if !bytes.Equal(reference.cid, payloadCID) {
		return publication.BlobReference{}, atprotoMaterialRefusal(
			ErrATProtoMaterialProvider,
			"upload_reference_cid",
			errors.Join(
				atproto.ErrCandidateMayBeDisclosed,
				errors.New("provider blob reference CID does not match the uploaded payload CID"),
			),
		)
	}
	return publication.BlobReference{CID: reference.cid, Size: reference.size, MIMEType: reference.mimeType}, nil
}

func (transport *ATProtoMaterialTransport) PrepareWrites(
	ctx context.Context,
	batch MaterialWriteBatch,
) (MaterialPreparedWrites, error) {
	if err := transport.join(); err != nil {
		return MaterialPreparedWrites{}, err
	}
	if err := ctx.Err(); err != nil {
		return MaterialPreparedWrites{}, atprotoMaterialRefusal(ErrATProtoMaterialBatch, "canceled", err)
	}
	body, err := transport.encodeWriteBatch(batch)
	if err != nil {
		return MaterialPreparedWrites{}, err
	}
	secret, err := transport.prepared.retain(body)
	if err != nil {
		return MaterialPreparedWrites{}, atprotoMaterialRefusal(ErrATProtoMaterialPrepared, "secret", err)
	}
	return MaterialPreparedWrites{Secret: secret, Dispatch: 1}, nil
}

func (transport *ATProtoMaterialTransport) SendWrites(
	ctx context.Context,
	prepared MaterialPreparedWrites,
) (MaterialWriteOutcome, error) {
	if err := transport.join(); err != nil {
		return MaterialWriteOutcome{}, err
	}
	if prepared.Secret == "" || prepared.Dispatch != 1 {
		return MaterialWriteOutcome{}, atprotoMaterialRefusal(ErrATProtoMaterialPrepared, "prepared", nil)
	}
	if err := ctx.Err(); err != nil {
		return MaterialWriteOutcome{}, atprotoMaterialRefusal(ErrATProtoMaterialPrepared, "canceled", err)
	}
	body, retained := transport.prepared.take(prepared.Secret)
	if !retained {
		return MaterialWriteOutcome{}, atprotoMaterialRefusal(ErrATProtoMaterialPrepared, "consumed", nil)
	}
	status, response, err := transport.transport.Do(
		ctx,
		"POST",
		atprotoMaterialApplyEndpoint,
		nil,
		body,
		"application/json",
	)
	if err != nil {
		if status >= 400 && status < 500 {
			return MaterialWriteOutcome{}, atprotoMaterialRefusal(
				ErrATProtoMaterialProvider,
				atprotoMaterialDispatchReason(status, response),
				atprotoMaterialApplyStatus(status, response),
			)
		}
		return MaterialWriteOutcome{}, atprotoMaterialRefusal(
			ErrATProtoMaterialProvider,
			"dispatch_ambiguous",
			atprotoMaterialAmbiguous(ctx),
		)
	}
	if status < 200 || status >= 300 {
		return MaterialWriteOutcome{}, atprotoMaterialRefusal(
			ErrATProtoMaterialProvider,
			atprotoMaterialDispatchReason(status, response),
			atprotoMaterialApplyStatus(status, response),
		)
	}
	if err := atprotoMaterialCommitReference(response); err != nil {
		return MaterialWriteOutcome{}, atprotoMaterialRefusal(ErrATProtoMaterialProvider, "dispatch_ambiguous",
			errors.Join(atproto.ErrAmbiguousTransport, atproto.ErrCandidateMayBeDisclosed, err))
	}
	return MaterialWriteOutcome{Committed: true}, nil
}

func (transport *ATProtoMaterialTransport) ReadView(
	ctx context.Context,
) (publicationstate.SuppliedRepositoryView, error) {
	if err := transport.join(); err != nil {
		return publicationstate.SuppliedRepositoryView{}, err
	}
	if err := ctx.Err(); err != nil {
		return publicationstate.SuppliedRepositoryView{}, atprotoMaterialRefusal(
			ErrATProtoMaterialView,
			"canceled",
			err,
		)
	}
	revision, err := transport.reader.Read(ctx, transport.did)
	if err != nil {
		return publicationstate.SuppliedRepositoryView{}, atprotoMaterialRefusal(
			ErrATProtoMaterialView,
			"revision",
			err,
		)
	}
	if revision.DID() != transport.did {
		return publicationstate.SuppliedRepositoryView{}, atprotoMaterialRefusal(
			ErrATProtoMaterialView,
			"identity",
			nil,
		)
	}
	return transport.view(revision)
}

func atprotoMaterialHead(revision *atproto.Revision) (publication.HeadRecord, []byte, bool, error) {
	membership := revision.Membership()
	records := revision.Records()
	headKey := atproto.RecordKey{Collection: publication.HeadNSID, RKey: materialHeadKey}
	headPresent := false
	for key := range membership {
		if _, legacy := atprotoMaterialLegacyCollections[key.Collection]; legacy {
			return publication.HeadRecord{}, nil, false, atprotoMaterialRefusal(
				ErrATProtoMaterialView,
				"legacy_profile",
				nil,
			)
		}
		if key.Collection != publication.HeadNSID {
			continue
		}
		if key.RKey != materialHeadKey {
			return publication.HeadRecord{}, nil, false, atprotoMaterialRefusal(ErrATProtoMaterialView, "head_key", nil)
		}
		headPresent = true
	}
	if !headPresent {
		return publication.HeadRecord{}, nil, false, nil
	}
	proven, found := records[headKey]
	if !found {
		return publication.HeadRecord{}, nil, false, atprotoMaterialRefusal(ErrATProtoMaterialView, "head", nil)
	}
	if err := atprotoMaterialRoundTrip(proven, membership[headKey]); err != nil {
		return publication.HeadRecord{}, nil, false, atprotoMaterialRefusal(ErrATProtoMaterialView, "round_trip", err)
	}
	head, err := publication.DecodeHead(proven.Data)
	if err != nil {
		return publication.HeadRecord{}, nil, false, atprotoMaterialRefusal(ErrATProtoMaterialView, "head", err)
	}
	return head, bytes.Clone(proven.Data), true, nil
}

func (transport *ATProtoMaterialTransport) view(
	revision *atproto.Revision,
) (publicationstate.SuppliedRepositoryView, error) {
	membership := revision.Membership()
	records := revision.Records()
	head, headRaw, headPresent, err := atprotoMaterialHead(revision)
	if err != nil {
		return publicationstate.SuppliedRepositoryView{}, err
	}
	if headPresent && head.Vault != transport.binding.Vault {
		return publicationstate.SuppliedRepositoryView{}, atprotoMaterialRefusal(ErrATProtoMaterialView, "vault", nil)
	}
	snapshotKeys := make([]string, 0, len(membership))
	for key := range membership {
		if key.Collection != publication.SnapshotNSID {
			continue
		}
		if _, err := publication.ParseSequenceKey(key.RKey); err != nil {
			return publicationstate.SuppliedRepositoryView{}, atprotoMaterialRefusal(
				ErrATProtoMaterialView,
				"record_key",
				nil,
			)
		}
		snapshotKeys = append(snapshotKeys, key.RKey)
	}
	sort.Strings(snapshotKeys)
	view := publicationstate.SuppliedRepositoryView{
		Origin: transport.binding, Scope: publicationstate.ViewScopeWholeRepository,
		SuppliedContext: publicationstate.SuppliedContext{
			RepositoryRevision: revision.Rev(),
			RepositoryDigest:   []byte(revision.CommitCID()),
		},
		Snapshots: []publicationstate.SnapshotBlock{},
	}
	if len(snapshotKeys) == 0 {
		if headPresent {
			return publicationstate.SuppliedRepositoryView{}, atprotoMaterialRefusal(
				ErrATProtoMaterialView,
				"snapshot",
				nil,
			)
		}
		return view, nil
	}
	if !headPresent {
		return publicationstate.SuppliedRepositoryView{}, atprotoMaterialRefusal(ErrATProtoMaterialView, "head", nil)
	}
	var previous []byte
	for index, key := range snapshotKeys {
		proven, found := records[atproto.RecordKey{Collection: publication.SnapshotNSID, RKey: key}]
		if !found {
			return publicationstate.SuppliedRepositoryView{}, atprotoMaterialRefusal(
				ErrATProtoMaterialView,
				"snapshot",
				nil,
			)
		}
		if err := atprotoMaterialRoundTrip(
			proven,
			membership[atproto.RecordKey{Collection: publication.SnapshotNSID, RKey: key}],
		); err != nil {
			return publicationstate.SuppliedRepositoryView{}, atprotoMaterialRefusal(
				ErrATProtoMaterialView,
				"round_trip",
				err,
			)
		}
		record, err := publication.DecodeSnapshot(proven.Data)
		if err != nil {
			return publicationstate.SuppliedRepositoryView{}, atprotoMaterialRefusal(
				ErrATProtoMaterialView,
				"snapshot",
				err,
			)
		}
		if record.Vault != transport.binding.Vault {
			return publicationstate.SuppliedRepositoryView{}, atprotoMaterialRefusal(
				ErrATProtoMaterialView,
				"vault",
				nil,
			)
		}
		if record.PublicationSeq != uint64(index) {
			return publicationstate.SuppliedRepositoryView{}, atprotoMaterialRefusal(
				ErrATProtoMaterialView,
				"chain",
				nil,
			)
		}
		if index > 0 {
			if err := publication.VerifySuccessor(previous, proven.Data, key); err != nil {
				return publicationstate.SuppliedRepositoryView{}, atprotoMaterialRefusal(
					ErrATProtoMaterialView,
					"chain",
					err,
				)
			}
		}
		previous = proven.Data
		view.Snapshots = append(view.Snapshots, publicationstate.SnapshotBlock{Key: key, Raw: bytes.Clone(proven.Data)})
	}
	terminal := view.Snapshots[len(view.Snapshots)-1]
	terminalCID, err := publication.RecordCID(terminal.Raw)
	if err != nil {
		return publicationstate.SuppliedRepositoryView{}, atprotoMaterialRefusal(
			ErrATProtoMaterialView,
			"head_join",
			err,
		)
	}
	if head.PublicationSeq != uint64(len(view.Snapshots)-1) || !bytes.Equal(head.SnapshotCID, terminalCID) {
		return publicationstate.SuppliedRepositoryView{}, atprotoMaterialRefusal(
			ErrATProtoMaterialView,
			"head_join",
			nil,
		)
	}
	if err := publication.VerifyHeadBinding(headRaw, terminal.Raw, terminal.Key); err != nil {
		return publicationstate.SuppliedRepositoryView{}, atprotoMaterialRefusal(
			ErrATProtoMaterialView,
			"head_join",
			err,
		)
	}
	view.Head = headRaw
	return view, nil
}

func (transport *ATProtoMaterialTransport) encodeWriteBatch(batch MaterialWriteBatch) ([]byte, error) {
	swapCommit, err := transport.validateWriteBatch(batch)
	if err != nil {
		return nil, err
	}
	snapshotValue, err := publication.RecordToJSON(batch.SnapshotRecord)
	if err != nil {
		return nil, atprotoMaterialRefusal(ErrATProtoMaterialBatch, "snapshot_record", err)
	}
	headValue, err := publication.RecordToJSON(batch.HeadRecord)
	if err != nil {
		return nil, atprotoMaterialRefusal(ErrATProtoMaterialBatch, "head_record", err)
	}
	headAction := atprotoMaterialUpdateAction
	if batch.HeadCreate {
		headAction = atprotoMaterialCreateAction
	}
	body, err := json.Marshal(atprotoMaterialApplyWrites{
		Repo: transport.did, SwapCommit: swapCommit,
		Writes: []atprotoMaterialWrite{
			{
				Type:       atprotoMaterialCreateAction,
				Collection: publication.SnapshotNSID,
				RKey:       batch.SnapshotKey,
				Value:      snapshotValue,
			},
			{Type: headAction, Collection: publication.HeadNSID, RKey: materialHeadKey, Value: headValue},
		},
	})
	if err != nil {
		return nil, atprotoMaterialRefusal(ErrATProtoMaterialBatch, "request", err)
	}
	return body, nil
}

func (transport *ATProtoMaterialTransport) validateWriteBatch(batch MaterialWriteBatch) (string, error) {
	if batch.SnapshotCollection != publication.SnapshotNSID || batch.HeadCollection != publication.HeadNSID ||
		batch.HeadKey != materialHeadKey {
		return "", atprotoMaterialRefusal(ErrATProtoMaterialBatch, "collection", nil)
	}
	if !batch.SnapshotCreateOnly {
		return "", atprotoMaterialRefusal(ErrATProtoMaterialBatch, "create_only", nil)
	}
	if !batch.RequiresAtomicBatch || !batch.RequiresCreateExclude || batch.RequiresPolicyCheck {
		return "", atprotoMaterialRefusal(ErrATProtoMaterialBatch, "conditions", nil)
	}
	if len(batch.SnapshotRecord) == 0 || len(batch.ExpectedSnapshotCID) == 0 || len(batch.HeadRecord) == 0 {
		return "", atprotoMaterialRefusal(ErrATProtoMaterialBatch, "record", nil)
	}
	if batch.ExpectedContext.Policy != nil {
		return "", atprotoMaterialRefusal(ErrATProtoMaterialBatch, "policy", nil)
	}
	swapCommit, err := atprotoMaterialCommitDigest(batch.ExpectedContext)
	if err != nil {
		return "", atprotoMaterialRefusal(ErrATProtoMaterialBatch, "context", err)
	}
	snapshot, err := publication.DecodeSnapshot(batch.SnapshotRecord)
	if err != nil {
		return "", atprotoMaterialRefusal(ErrATProtoMaterialBatch, "snapshot_record", err)
	}
	if snapshot.Vault != transport.binding.Vault {
		return "", atprotoMaterialRefusal(ErrATProtoMaterialBatch, "vault", nil)
	}
	key, err := publication.SequenceKey(snapshot.PublicationSeq)
	if err != nil || key != batch.SnapshotKey {
		return "", atprotoMaterialRefusal(ErrATProtoMaterialBatch, "snapshot_key", nil)
	}
	snapshotCID, err := publication.RecordCID(batch.SnapshotRecord)
	if err != nil || !bytes.Equal(snapshotCID, batch.ExpectedSnapshotCID) {
		return "", atprotoMaterialRefusal(ErrATProtoMaterialBatch, "snapshot_cid", nil)
	}
	head, err := publication.DecodeHead(batch.HeadRecord)
	if err != nil {
		return "", atprotoMaterialRefusal(ErrATProtoMaterialBatch, "head_record", err)
	}
	if head.Vault != transport.binding.Vault {
		return "", atprotoMaterialRefusal(ErrATProtoMaterialBatch, "vault", nil)
	}
	if err := publication.VerifyHeadBinding(batch.HeadRecord, batch.SnapshotRecord, batch.SnapshotKey); err != nil {
		return "", atprotoMaterialRefusal(ErrATProtoMaterialBatch, "head_join", err)
	}
	if batch.HeadCreate {
		if batch.ExpectedPredecessor != nil || snapshot.PublicationSeq != 0 || len(snapshot.Parent) != 0 {
			return "", atprotoMaterialRefusal(ErrATProtoMaterialBatch, "predecessor", nil)
		}
		return swapCommit, nil
	}
	if batch.ExpectedPredecessor == nil {
		return "", atprotoMaterialRefusal(ErrATProtoMaterialBatch, "predecessor", nil)
	}
	predecessor := *batch.ExpectedPredecessor
	key, err = publication.SequenceKey(predecessor.Sequence)
	if err != nil || key != predecessor.Key {
		return "", atprotoMaterialRefusal(ErrATProtoMaterialBatch, "predecessor", nil)
	}
	if err := atprotoMaterialRecordCID(predecessor.CID); err != nil {
		return "", atprotoMaterialRefusal(ErrATProtoMaterialBatch, "predecessor", err)
	}
	if snapshot.PublicationSeq != predecessor.Sequence+1 || !bytes.Equal(snapshot.Parent, predecessor.CID) {
		return "", atprotoMaterialRefusal(ErrATProtoMaterialBatch, "predecessor", nil)
	}
	return swapCommit, nil
}

func atprotoMaterialCommitDigest(context publicationstate.SuppliedContext) (string, error) {
	if context.RepositoryRevision == "" || len(context.RepositoryRevision) > 1024 ||
		len(context.RepositoryDigest) == 0 ||
		len(context.RepositoryDigest) > 128 {
		return "", errors.New("expected repository context is incomplete")
	}
	encoded := string(context.RepositoryDigest)
	identifier, err := cid.Parse(encoded)
	if err != nil || identifier.String() != encoded {
		return "", errors.New("expected repository digest is not a canonical CID")
	}
	if err := atprotoMaterialCommitCID(identifier); err != nil {
		return "", err
	}
	return encoded, nil
}

func atprotoMaterialCommitCID(identifier cid.Cid) error {
	prefix := identifier.Prefix()
	if prefix.Version != 1 || prefix.Codec != cid.DagCBOR || prefix.MhType != multihash.SHA2_256 ||
		prefix.MhLength != 32 {
		return errors.New("repository commit CID has the wrong role")
	}
	return nil
}

func atprotoMaterialRecordCID(encoded []byte) error {
	if len(encoded) == 0 || len(encoded) > publication.MaxCIDBytes {
		return errors.New("record CID has the wrong length")
	}
	identifier, err := cid.Cast(encoded)
	if err != nil || !bytes.Equal(identifier.Bytes(), encoded) {
		return errors.New("record CID is not canonical")
	}
	return atprotoMaterialCommitCID(identifier)
}

func atprotoMaterialRoundTrip(record atproto.ProvenRecord, provenCID string) error {
	computed, err := publication.RecordCID(record.Data)
	if err != nil {
		return err
	}
	identifier, err := cid.Cast(computed)
	if err != nil || identifier.String() != provenCID {
		return errors.New("committed record bytes do not match their proven record CID")
	}
	return nil
}

func atprotoMaterialPayloadLimit(configured int64) uint64 {
	if configured <= 0 {
		return 0
	}
	limit := min(uint64(configured), publication.MaxBlobBytes)
	return limit
}

func atprotoMaterialAmbiguous(ctx context.Context) error {
	return errors.Join(atproto.ErrAmbiguousTransport, atproto.ErrCandidateMayBeDisclosed, ctx.Err())
}

type atprotoMaterialApplyWrites struct {
	Repo       string                 `json:"repo"`
	SwapCommit string                 `json:"swapCommit"`
	Writes     []atprotoMaterialWrite `json:"writes"`
}

type atprotoMaterialWrite struct {
	Type       string          `json:"$type"`
	Collection string          `json:"collection"`
	RKey       string          `json:"rkey"`
	Value      json.RawMessage `json:"value"`
}

type atprotoMaterialBlobReference struct {
	cid      []byte
	mimeType string
	size     uint64
}

func atprotoMaterialUploadReference(response []byte) (atprotoMaterialBlobReference, error) {
	var parsed struct {
		Blob struct {
			Type string `json:"$type"`
			Ref  struct {
				Link string `json:"$link"`
			} `json:"ref"`
			MimeType string `json:"mimeType"`
			Size     int64  `json:"size"`
		} `json:"blob"`
	}
	if err := json.Unmarshal(response, &parsed); err != nil {
		return atprotoMaterialBlobReference{}, errors.New("upload response is not a blob reference")
	}
	if parsed.Blob.Type != atprotoMaterialBlobType || parsed.Blob.Size <= 0 {
		return atprotoMaterialBlobReference{}, errors.New("upload response is not a blob reference")
	}
	identifier, err := cid.Parse(parsed.Blob.Ref.Link)
	if err != nil || identifier.String() != parsed.Blob.Ref.Link {
		return atprotoMaterialBlobReference{}, errors.New("uploaded blob CID is not canonical")
	}
	prefix := identifier.Prefix()
	if prefix.Version != 1 || prefix.Codec != cid.Raw || prefix.MhType != multihash.SHA2_256 || prefix.MhLength != 32 {
		return atprotoMaterialBlobReference{}, errors.New("uploaded blob CID has the wrong role")
	}
	return atprotoMaterialBlobReference{
		cid:      identifier.Bytes(),
		mimeType: parsed.Blob.MimeType,
		size:     uint64(parsed.Blob.Size),
	}, nil
}

func atprotoMaterialCommitReference(response []byte) error {
	if len(response) == 0 {
		return nil
	}
	var parsed struct {
		Commit struct {
			CID string `json:"cid"`
		} `json:"commit"`
	}
	if err := json.Unmarshal(response, &parsed); err != nil || parsed.Commit.CID == "" {
		return errors.New("applyWrites response is not a commit reference")
	}
	identifier, err := cid.Parse(parsed.Commit.CID)
	if err != nil || identifier.String() != parsed.Commit.CID {
		return errors.New("applyWrites commit CID is not canonical")
	}
	return atprotoMaterialCommitCID(identifier)
}

func atprotoMaterialDispatchReason(status int, response []byte) string {
	code := atprotoMaterialProviderCode(response)
	if code == "" {
		return fmt.Sprintf("dispatch_rejected:%d", status)
	}
	return fmt.Sprintf("dispatch_rejected:%d:%s", status, code)
}

func atprotoMaterialProviderCode(body []byte) string {
	var response struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &response) != nil || response.Error == "" || len(response.Error) > 64 {
		return ""
	}
	for _, character := range response.Error {
		switch {
		case character >= 'A' && character <= 'Z', character >= 'a' && character <= 'z',
			character >= '0' && character <= '9', character == '_':
		default:
			return ""
		}
	}
	return response.Error
}

func atprotoMaterialApplyStatus(status int, response []byte) error {
	failure := atprotoMaterialApplyRejection(status, response)
	if atprotoMaterialDefiniteRejection(status, response) {
		return errors.Join(failure, ErrMaterialSubmissionRejected)
	}
	return failure
}

func atprotoMaterialDefiniteRejection(status int, response []byte) bool {
	if status < 400 || status >= 500 || status == 401 || status == 403 {
		return false
	}
	return atprotoMaterialXRPCErrorName(response) != ""
}

func atprotoMaterialXRPCErrorName(body []byte) string {
	var response struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &response) != nil {
		return ""
	}
	name := response.Error
	if len(name) == 0 || len(name) > 64 {
		return ""
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
			return ""
		}
	}
	return name
}

func atprotoMaterialApplyRejection(status int, response []byte) error {
	code := atprotoMaterialSafeCode(response)
	statusError := atprotoMaterialProviderStatus(status, response)
	switch {
	case status >= 400 && status < 500 && code == "InvalidSwap":
		return errors.Join(atproto.ErrFenceLost, atproto.ErrCandidateMayBeDisclosed, statusError)
	case status == 429:
		return errors.Join(atproto.ErrPublicationRateLimited, atproto.ErrCandidateMayBeDisclosed, statusError)
	case status >= 400 && status < 500 && (code == "QuotaExceeded" || code == "StorageQuotaExceeded"):
		return errors.Join(atproto.ErrPublicationQuota, atproto.ErrCandidateMayBeDisclosed, statusError)
	case status >= 400 && status < 500 && code == "RateLimitExceeded":
		return errors.Join(atproto.ErrPublicationRateLimited, atproto.ErrCandidateMayBeDisclosed, statusError)
	case status == 401 || status == 403:
		return errors.Join(
			atproto.ErrPublicationQueued,
			atproto.ErrBatchRejected,
			atproto.ErrCandidateMayBeDisclosed,
			statusError,
		)
	case status >= 400 && status < 500 && (status == 413 || code == "RequestTooLarge" || code == "PayloadTooLarge"):
		return errors.Join(atproto.ErrPublicationBatchTooLarge, atproto.ErrCandidateMayBeDisclosed, statusError)
	case status >= 400 && status < 500:
		return errors.Join(atproto.ErrBatchRejected, atproto.ErrCandidateMayBeDisclosed, statusError)
	default:
		return errors.Join(atproto.ErrAmbiguousTransport, atproto.ErrCandidateMayBeDisclosed, statusError)
	}
}

func atprotoMaterialUploadStatus(status int, response []byte) error {
	code := atprotoMaterialSafeCode(response)
	statusError := atprotoMaterialProviderStatus(status, response)
	switch {
	case status == 429:
		return errors.Join(atproto.ErrPublicationRateLimited, atproto.ErrCandidateMayBeDisclosed, statusError)
	case status >= 400 && status < 500 && (code == "QuotaExceeded" || code == "StorageQuotaExceeded"):
		return errors.Join(atproto.ErrPublicationQuota, atproto.ErrCandidateMayBeDisclosed, statusError)
	case status >= 400 && status < 500 && code == "RateLimitExceeded":
		return errors.Join(atproto.ErrPublicationRateLimited, atproto.ErrCandidateMayBeDisclosed, statusError)
	case status == 401 || status == 403:
		return errors.Join(
			atproto.ErrPublicationQueued,
			atproto.ErrBatchRejected,
			atproto.ErrCandidateMayBeDisclosed,
			statusError,
		)
	case status >= 400 && status < 500 && (status == 413 || code == "BlobTooLarge"):
		return errors.Join(atproto.ErrCandidateExceedsBlobUploadLimit, atproto.ErrCandidateMayBeDisclosed, statusError)
	case status >= 400 && status < 500:
		return errors.Join(atproto.ErrBatchRejected, atproto.ErrCandidateMayBeDisclosed, statusError)
	default:
		return errors.Join(atproto.ErrAmbiguousTransport, atproto.ErrCandidateMayBeDisclosed, statusError)
	}
}

func atprotoMaterialProviderStatus(status int, response []byte) *atproto.ProviderStatusError {
	return &atproto.ProviderStatusError{StatusCode: status, Code: atprotoMaterialSafeCode(response)}
}

func atprotoMaterialSafeCode(body []byte) string {
	var response struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &response) != nil {
		return ""
	}
	switch response.Error {
	case "InvalidSwap",
		"QuotaExceeded",
		"StorageQuotaExceeded",
		"RateLimitExceeded",
		"BlobTooLarge",
		"RequestTooLarge",
		"PayloadTooLarge",
		"AuthRequired":
		return response.Error
	default:
		return ""
	}
}
