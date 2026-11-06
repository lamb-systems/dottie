package publicationstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

type bindingWire struct {
	AccountDID string `json:"accountDid"`
	Backend    string `json:"backend"`
	Repository string `json:"repository"`
	Vault      []byte `json:"vault"`
	Profile    string `json:"profile"`
}

type policyWire struct {
	Revision  string `json:"revision"`
	Identity  []byte `json:"identity"`
	OwnerOnly bool   `json:"ownerOnly"`
}

type contextWire struct {
	RepositoryRevision string      `json:"repositoryRevision"`
	RepositoryDigest   []byte      `json:"repositoryDigest"`
	Policy             *policyWire `json:"policy"`
}

type referenceWire struct {
	Key      string `json:"key"`
	CID      []byte `json:"cid"`
	Sequence uint64 `json:"sequence"`
}

type floorCoreWire struct {
	Version           uint32      `json:"version"`
	DatabaseID        []byte      `json:"databaseId"`
	Revision          uint64      `json:"revision"`
	Generation        uint64      `json:"generation"`
	Provenance        string      `json:"provenance"`
	AnchorCID         []byte      `json:"anchorCid"`
	Binding           bindingWire `json:"binding"`
	SuppliedContext   contextWire `json:"suppliedContext"`
	Head              []byte      `json:"head"`
	SnapshotKey       string      `json:"snapshotKey"`
	Sequence          uint64      `json:"sequence"`
	PublicationID     []byte      `json:"publicationId"`
	RecordCID         []byte      `json:"recordCid"`
	BlobCID           []byte      `json:"blobCid"`
	BlobSize          uint64      `json:"blobSize"`
	ObservationDigest []byte      `json:"observationDigest"`
}

type floorWire struct {
	Version             uint32      `json:"version"`
	DatabaseID          []byte      `json:"databaseId"`
	Revision            uint64      `json:"revision"`
	Generation          uint64      `json:"generation"`
	Provenance          string      `json:"provenance"`
	AnchorCID           []byte      `json:"anchorCid"`
	Binding             bindingWire `json:"binding"`
	SuppliedContext     contextWire `json:"suppliedContext"`
	Head                []byte      `json:"head"`
	SnapshotKey         string      `json:"snapshotKey"`
	Sequence            uint64      `json:"sequence"`
	PublicationID       []byte      `json:"publicationId"`
	RecordCID           []byte      `json:"recordCid"`
	BlobCID             []byte      `json:"blobCid"`
	BlobSize            uint64      `json:"blobSize"`
	ObservationDigest   []byte      `json:"observationDigest"`
	AcceptedEventDigest []byte      `json:"acceptedEventDigest"`
}

type observationWire struct {
	Version           uint32      `json:"version"`
	Origin            bindingWire `json:"origin"`
	SuppliedContext   contextWire `json:"suppliedContext"`
	Head              []byte      `json:"head"`
	SuppliedSetDigest []byte      `json:"suppliedSetDigest"`
}

type eventBodyWire struct {
	Version           uint32          `json:"version"`
	Mode              string          `json:"mode"`
	Reason            string          `json:"reason"`
	OldFloor          *floorWire      `json:"oldFloor"`
	NewFloor          floorCoreWire   `json:"newFloor"`
	Trace             []referenceWire `json:"trace"`
	Stop              string          `json:"stop"`
	ObservationDigest []byte          `json:"observationDigest"`
	SuppliedSetDigest []byte          `json:"suppliedSetDigest"`
}

type limitsWire struct {
	SuppliedSnapshotCount uint32 `json:"suppliedSnapshotCount"`
	SuppliedTotalBytes    uint64 `json:"suppliedTotalBytes"`
	SuppliedContextBytes  uint32 `json:"suppliedContextBytes"`
	MaxLineageLinks       uint32 `json:"maxLineageLinks"`
	CacheRecordCount      uint32 `json:"cacheRecordCount"`
	CacheObservationCount uint32 `json:"cacheObservationCount"`
	CacheLogicalBytes     uint64 `json:"cacheLogicalBytes"`
	AcceptedRecordCount   uint32 `json:"acceptedRecordCount"`
	AcceptedEventCount    uint32 `json:"acceptedEventCount"`
	AcceptedLogicalBytes  uint64 `json:"acceptedLogicalBytes"`
	HistoryPageEvents     uint32 `json:"historyPageEvents"`
	HistoryEvidenceBytes  uint64 `json:"historyEvidenceBytes"`
}

type stateTokenWire struct {
	Version    uint32      `json:"version"`
	DatabaseID []byte      `json:"databaseId"`
	Revision   uint64      `json:"revision"`
	Generation uint64      `json:"generation"`
	Binding    bindingWire `json:"binding"`
	Limits     limitsWire  `json:"limits"`
	Floor      *floorWire  `json:"floor"`
}

type confirmationWire struct {
	Version           uint32          `json:"version"`
	DatabaseID        []byte          `json:"databaseId"`
	Binding           bindingWire     `json:"binding"`
	Mode              string          `json:"mode"`
	OldFloor          *floorWire      `json:"oldFloor"`
	StateToken        []byte          `json:"stateToken"`
	ObservationDigest []byte          `json:"observationDigest"`
	Trace             []referenceWire `json:"trace"`
	Stop              string          `json:"stop"`
	Reason            string          `json:"reason"`
	Warning           string          `json:"warning"`
}

func canonicalJSON(value any) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	result := out.Bytes()
	if len(result) == 0 || result[len(result)-1] != '\n' {
		return nil, errors.New("encoding failure")
	}
	return bytes.Clone(result[:len(result)-1]), nil
}

func strictJSON(encoded []byte, target any) error {
	if !utf8.Valid(encoded) || len(encoded) == 0 {
		return errors.New("invalid encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid encoding")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("invalid encoding")
	}
	canonical, err := canonicalJSON(target)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return errors.New("noncanonical encoding")
	}
	return nil
}

func bindingToWire(binding Binding) bindingWire {
	return bindingWire{AccountDID: binding.AccountDID, Backend: string(binding.Backend), Repository: binding.Repository, Vault: bytes.Clone(binding.Vault[:]), Profile: storageProfile}
}

func bindingFromWire(w bindingWire) (Binding, error) {
	if len(w.Vault) != 32 || w.Profile != storageProfile || !validText(w.AccountDID) || !validText(w.Backend) || !validText(w.Repository) {
		return Binding{}, errors.New("invalid binding")
	}
	var binding Binding
	binding.AccountDID = w.AccountDID
	binding.Backend = Backend(w.Backend)
	binding.Repository = w.Repository
	copy(binding.Vault[:], w.Vault)
	return binding, nil
}

func contextToWire(context SuppliedContext) contextWire {
	wire := contextWire{RepositoryRevision: context.RepositoryRevision, RepositoryDigest: bytes.Clone(context.RepositoryDigest), Policy: nil}
	if context.Policy != nil {
		wire.Policy = &policyWire{Revision: context.Policy.Revision, Identity: bytes.Clone(context.Policy.Identity), OwnerOnly: context.Policy.OwnerOnly}
	}
	return wire
}

func contextFromWire(w contextWire) (SuppliedContext, error) {
	context := SuppliedContext{RepositoryRevision: w.RepositoryRevision, RepositoryDigest: bytes.Clone(w.RepositoryDigest)}
	if w.Policy != nil {
		context.Policy = &Policy{Revision: w.Policy.Revision, Identity: bytes.Clone(w.Policy.Identity), OwnerOnly: w.Policy.OwnerOnly}
	}
	if !validContextText(context) {
		return SuppliedContext{}, errors.New("invalid context")
	}
	return context, nil
}

func referenceToWire(ref RecordReference) referenceWire {
	return referenceWire{Key: ref.Key, CID: bytes.Clone(ref.CID), Sequence: ref.Sequence}
}

func referencesToWire(refs []RecordReference) []referenceWire {
	out := make([]referenceWire, 0, len(refs))
	for _, ref := range refs {
		out = append(out, referenceToWire(ref))
	}
	return out
}

func floorCoreToWire(f Floor) floorCoreWire {
	return floorCoreWire{Version: 1, DatabaseID: bytes.Clone(f.DatabaseID[:]), Revision: f.Revision, Generation: f.Generation, Provenance: string(f.Provenance), AnchorCID: bytes.Clone(f.AnchorCID), Binding: bindingToWire(f.Binding), SuppliedContext: contextToWire(f.SuppliedContext), Head: bytes.Clone(f.Head), SnapshotKey: f.SnapshotKey, Sequence: f.Sequence, PublicationID: bytes.Clone(f.PublicationID[:]), RecordCID: bytes.Clone(f.RecordCID), BlobCID: bytes.Clone(f.BlobCID), BlobSize: f.BlobSize, ObservationDigest: bytes.Clone(f.ObservationDigest[:])}
}

func floorToWire(f Floor) floorWire {
	core := floorCoreToWire(f)
	return floorWire{Version: core.Version, DatabaseID: core.DatabaseID, Revision: core.Revision, Generation: core.Generation, Provenance: core.Provenance, AnchorCID: core.AnchorCID, Binding: core.Binding, SuppliedContext: core.SuppliedContext, Head: core.Head, SnapshotKey: core.SnapshotKey, Sequence: core.Sequence, PublicationID: core.PublicationID, RecordCID: core.RecordCID, BlobCID: core.BlobCID, BlobSize: core.BlobSize, ObservationDigest: core.ObservationDigest, AcceptedEventDigest: bytes.Clone(f.AcceptedEventDigest[:])}
}

func floorFromWire(w floorWire) (Floor, error) {
	core := floorCoreWire{Version: w.Version, DatabaseID: w.DatabaseID, Revision: w.Revision, Generation: w.Generation, Provenance: w.Provenance, AnchorCID: w.AnchorCID, Binding: w.Binding, SuppliedContext: w.SuppliedContext, Head: w.Head, SnapshotKey: w.SnapshotKey, Sequence: w.Sequence, PublicationID: w.PublicationID, RecordCID: w.RecordCID, BlobCID: w.BlobCID, BlobSize: w.BlobSize, ObservationDigest: w.ObservationDigest}
	floor, err := floorCoreFromWire(core)
	if err != nil || len(w.AcceptedEventDigest) != 32 {
		return Floor{}, errors.New("invalid floor")
	}
	copy(floor.AcceptedEventDigest[:], w.AcceptedEventDigest)
	return floor, nil
}

func floorCoreFromWire(w floorCoreWire) (Floor, error) {
	binding, err := bindingFromWire(w.Binding)
	if err != nil || w.Version != 1 || len(w.DatabaseID) != 32 || len(w.PublicationID) != 16 || len(w.ObservationDigest) != 32 || len(w.AnchorCID) == 0 || len(w.RecordCID) == 0 || len(w.BlobCID) == 0 || len(w.Head) == 0 || !validText(w.SnapshotKey) || !validText(w.Provenance) {
		return Floor{}, errors.New("invalid floor")
	}
	context, err := contextFromWire(w.SuppliedContext)
	if err != nil {
		return Floor{}, errors.New("invalid floor")
	}
	var floor Floor
	copy(floor.DatabaseID[:], w.DatabaseID)
	copy(floor.PublicationID[:], w.PublicationID)
	copy(floor.ObservationDigest[:], w.ObservationDigest)
	floor.Revision = w.Revision
	floor.Generation = w.Generation
	floor.Provenance = Provenance(w.Provenance)
	floor.AnchorCID = bytes.Clone(w.AnchorCID)
	floor.Binding = binding
	floor.SuppliedContext = context
	floor.Head = bytes.Clone(w.Head)
	floor.SnapshotKey = w.SnapshotKey
	floor.Sequence = w.Sequence
	floor.RecordCID = bytes.Clone(w.RecordCID)
	floor.BlobCID = bytes.Clone(w.BlobCID)
	floor.BlobSize = w.BlobSize
	return floor, nil
}

func encodeFloor(f Floor) ([]byte, error) { return canonicalJSON(floorToWire(f)) }

func decodeFloor(encoded []byte) (Floor, error) {
	var wire floorWire
	if err := strictJSON(encoded, &wire); err != nil {
		return Floor{}, err
	}
	return floorFromWire(wire)
}

func encodeBinding(binding Binding) ([]byte, error) { return canonicalJSON(bindingToWire(binding)) }
func encodeLimits(limits Limits) ([]byte, error)    { return canonicalJSON(limitsToWire(limits)) }

func limitsToWire(l Limits) limitsWire {
	return limitsWire{SuppliedSnapshotCount: l.SuppliedSnapshotCount, SuppliedTotalBytes: l.SuppliedTotalBytes, SuppliedContextBytes: l.SuppliedContextBytes, MaxLineageLinks: l.MaxLineageLinks, CacheRecordCount: l.CacheRecordCount, CacheObservationCount: l.CacheObservationCount, CacheLogicalBytes: l.CacheLogicalBytes, AcceptedRecordCount: l.AcceptedRecordCount, AcceptedEventCount: l.AcceptedEventCount, AcceptedLogicalBytes: l.AcceptedLogicalBytes, HistoryPageEvents: l.HistoryPageEvents, HistoryEvidenceBytes: l.HistoryEvidenceBytes}
}

func makeSetDigest(blocks []SnapshotBlock) [32]byte {
	h := sha256.New()
	h.Write([]byte("systems.lamb.dottie.local-record-set.v1\x00"))
	var number [4]byte
	binary.BigEndian.PutUint32(number[:], uint32(len(blocks)))
	h.Write(number[:])
	for _, block := range blocks {
		h.Write([]byte(block.Key))
		binary.BigEndian.PutUint32(number[:], uint32(len(block.Raw)))
		h.Write(number[:])
		h.Write(block.Raw)
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func makeObservationDigest(origin Binding, context SuppliedContext, head []byte, setDigest [32]byte) ([32]byte, error) {
	wire := observationWire{Version: 1, Origin: bindingToWire(origin), SuppliedContext: contextToWire(context), Head: bytes.Clone(head), SuppliedSetDigest: bytes.Clone(setDigest[:])}
	encoded, err := canonicalJSON(wire)
	if err != nil {
		return [32]byte{}, err
	}
	return domainHash("systems.lamb.dottie.local-observation.v1", encoded), nil
}

func makeStateToken(dbid [32]byte, revision, generation uint64, binding Binding, limits Limits, floor *Floor) ([32]byte, error) {
	wire := stateTokenWire{Version: 1, DatabaseID: bytes.Clone(dbid[:]), Revision: revision, Generation: generation, Binding: bindingToWire(binding), Limits: limitsToWire(limits), Floor: nil}
	if floor != nil {
		encoded := floorToWire(*floor)
		wire.Floor = &encoded
	}
	body, err := canonicalJSON(wire)
	if err != nil {
		return [32]byte{}, err
	}
	return domainHash("systems.lamb.dottie.local-publication-state.v1", body), nil
}

func makeEventBody(mode Mode, reason Reason, old *Floor, next Floor, trace []RecordReference, stop string, observationDigest, setDigest [32]byte) ([]byte, error) {
	var oldWire *floorWire
	if old != nil {
		wire := floorToWire(*old)
		oldWire = &wire
	}
	wire := eventBodyWire{Version: 1, Mode: string(mode), Reason: string(reason), OldFloor: oldWire, NewFloor: floorCoreToWire(next), Trace: referencesToWire(trace), Stop: stop, ObservationDigest: bytes.Clone(observationDigest[:]), SuppliedSetDigest: bytes.Clone(setDigest[:])}
	return canonicalJSON(wire)
}

func makeConfirmation(dbid [32]byte, binding Binding, mode Mode, old *Floor, token, observationDigest [32]byte, trace []RecordReference, stop string, reason Reason, warning string) ([32]byte, error) {
	var oldWire *floorWire
	if old != nil {
		wire := floorToWire(*old)
		oldWire = &wire
	}
	wire := confirmationWire{Version: 1, DatabaseID: bytes.Clone(dbid[:]), Binding: bindingToWire(binding), Mode: string(mode), OldFloor: oldWire, StateToken: bytes.Clone(token[:]), ObservationDigest: bytes.Clone(observationDigest[:]), Trace: referencesToWire(trace), Stop: stop, Reason: string(reason), Warning: warning}
	body, err := canonicalJSON(wire)
	if err != nil {
		return [32]byte{}, err
	}
	return domainHash("systems.lamb.dottie.local-publication-consent.v1", body), nil
}

func domainHash(domain string, body []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(body)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func validText(value string) bool { return utf8.ValidString(value) }

func validContextText(context SuppliedContext) bool {
	if !validText(context.RepositoryRevision) {
		return false
	}
	return context.Policy == nil || validText(context.Policy.Revision)
}
