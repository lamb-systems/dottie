package publicationstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type oracleBinding struct {
	AccountDID string `json:"accountDid"`
	Backend    string `json:"backend"`
	Repository string `json:"repository"`
	Vault      []byte `json:"vault"`
	Profile    string `json:"profile"`
}
type oraclePolicy struct {
	Revision  string `json:"revision"`
	Identity  []byte `json:"identity"`
	OwnerOnly bool   `json:"ownerOnly"`
}
type oracleContext struct {
	RepositoryRevision string        `json:"repositoryRevision"`
	RepositoryDigest   []byte        `json:"repositoryDigest"`
	Policy             *oraclePolicy `json:"policy"`
}
type oracleReference struct {
	Key      string `json:"key"`
	CID      []byte `json:"cid"`
	Sequence uint64 `json:"sequence"`
}
type oracleFloorCore struct {
	Version           uint32        `json:"version"`
	DatabaseID        []byte        `json:"databaseId"`
	Revision          uint64        `json:"revision"`
	Generation        uint64        `json:"generation"`
	Provenance        string        `json:"provenance"`
	AnchorCID         []byte        `json:"anchorCid"`
	Binding           oracleBinding `json:"binding"`
	SuppliedContext   oracleContext `json:"suppliedContext"`
	Head              []byte        `json:"head"`
	SnapshotKey       string        `json:"snapshotKey"`
	Sequence          uint64        `json:"sequence"`
	PublicationID     []byte        `json:"publicationId"`
	RecordCID         []byte        `json:"recordCid"`
	BlobCID           []byte        `json:"blobCid"`
	BlobSize          uint64        `json:"blobSize"`
	ObservationDigest []byte        `json:"observationDigest"`
}
type oracleFloor struct {
	Version             uint32        `json:"version"`
	DatabaseID          []byte        `json:"databaseId"`
	Revision            uint64        `json:"revision"`
	Generation          uint64        `json:"generation"`
	Provenance          string        `json:"provenance"`
	AnchorCID           []byte        `json:"anchorCid"`
	Binding             oracleBinding `json:"binding"`
	SuppliedContext     oracleContext `json:"suppliedContext"`
	Head                []byte        `json:"head"`
	SnapshotKey         string        `json:"snapshotKey"`
	Sequence            uint64        `json:"sequence"`
	PublicationID       []byte        `json:"publicationId"`
	RecordCID           []byte        `json:"recordCid"`
	BlobCID             []byte        `json:"blobCid"`
	BlobSize            uint64        `json:"blobSize"`
	ObservationDigest   []byte        `json:"observationDigest"`
	AcceptedEventDigest []byte        `json:"acceptedEventDigest"`
}
type oracleLimits struct {
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
type oracleObservation struct {
	Version           uint32        `json:"version"`
	Origin            oracleBinding `json:"origin"`
	SuppliedContext   oracleContext `json:"suppliedContext"`
	Head              []byte        `json:"head"`
	SuppliedSetDigest []byte        `json:"suppliedSetDigest"`
}
type oracleEvent struct {
	Version           uint32            `json:"version"`
	Mode              string            `json:"mode"`
	Reason            string            `json:"reason"`
	OldFloor          *oracleFloor      `json:"oldFloor"`
	NewFloor          oracleFloorCore   `json:"newFloor"`
	Trace             []oracleReference `json:"trace"`
	Stop              string            `json:"stop"`
	ObservationDigest []byte            `json:"observationDigest"`
	SuppliedSetDigest []byte            `json:"suppliedSetDigest"`
}
type oracleState struct {
	Version    uint32        `json:"version"`
	DatabaseID []byte        `json:"databaseId"`
	Revision   uint64        `json:"revision"`
	Generation uint64        `json:"generation"`
	Binding    oracleBinding `json:"binding"`
	Limits     oracleLimits  `json:"limits"`
	Floor      *oracleFloor  `json:"floor"`
}
type oracleConsent struct {
	Version           uint32            `json:"version"`
	DatabaseID        []byte            `json:"databaseId"`
	Binding           oracleBinding     `json:"binding"`
	Mode              string            `json:"mode"`
	OldFloor          *oracleFloor      `json:"oldFloor"`
	StateToken        []byte            `json:"stateToken"`
	ObservationDigest []byte            `json:"observationDigest"`
	Trace             []oracleReference `json:"trace"`
	Stop              string            `json:"stop"`
	Reason            string            `json:"reason"`
	Warning           string            `json:"warning"`
}

func TestPrivateWireIndependentTokenOracles(t *testing.T) {
	binding := Binding{AccountDID: "did:plc:abcdefghijklmnopqrstuvwx", Backend: BackendSpaces, Repository: "at://did:plc:abcdefghijklmnopqrstuvwx/systems.lamb.dottie.vaultSnapshotV2/record"}
	for i := range binding.Vault {
		binding.Vault[i] = byte(i + 1)
	}
	ctx := SuppliedContext{RepositoryRevision: "r<>&", RepositoryDigest: []byte{0, 1, 2, 255}, Policy: &Policy{Revision: "p<>&", Identity: []byte{4, 5, 6, 7}, OwnerOnly: true}}
	set := [32]byte{0x89, 0xf3, 0x1e, 0x35, 0xa0, 0x20, 0x74, 0xe8, 0xdb, 0x7c, 0xf6, 0x06, 0x2b, 0x8f, 0x4e, 0x5c, 0x3f, 0x9a, 0xb8, 0x8c, 0x5e, 0x7e, 0xc3, 0x4b, 0x5f, 0xfc, 0x74, 0xd4, 0x64, 0xad, 0xce, 0x7b}
	obsBody := oracleJSON(t, oracleObservation{Version: 1, Origin: oracleBind(binding), SuppliedContext: oracleCtx(ctx), Head: []byte{1, 2, 3, 4}, SuppliedSetDigest: bytes.Clone(set[:])})
	obsExpected := oracleHash("systems.lamb.dottie.local-observation.v1", obsBody)
	obsActual, err := makeObservationDigest(binding, ctx, []byte{1, 2, 3, 4}, set)
	require.NoError(t, err)
	assert.Equal(t, obsExpected, obsActual)
	var dbid [32]byte
	var pubid [16]byte
	var oldDigest, oldEvent [32]byte
	var cid, blob [32]byte
	for i := range dbid {
		dbid[i] = byte(i)
	}
	for i := range pubid {
		pubid[i] = byte(i + 32)
	}
	for i := range oldDigest {
		oldDigest[i] = byte(i + 64)
		oldEvent[i] = byte(i + 96)
	}
	for i := range cid {
		cid[i] = byte(i + 128)
		blob[i] = byte(i + 160)
	}
	old := Floor{DatabaseID: dbid, Revision: 7, Generation: 2, Provenance: ProvenanceFirst, AnchorCID: []byte{1, 2, 3}, Binding: binding, SuppliedContext: ctx, Head: []byte{0, 1, 2}, SnapshotKey: "0000000000000001", Sequence: 1, PublicationID: pubid, RecordCID: bytes.Clone(cid[:]), BlobCID: bytes.Clone(blob[:]), BlobSize: 123, ObservationDigest: oldDigest, AcceptedEventDigest: oldEvent}
	stateBody := oracleJSON(t, oracleState{Version: 1, DatabaseID: bytes.Clone(dbid[:]), Revision: 7, Generation: 2, Binding: oracleBind(binding), Limits: oracleLimitsFrom(DefaultLimits()), Floor: oracleFloorFrom(&old)})
	stateExpected := oracleHash("systems.lamb.dottie.local-publication-state.v1", stateBody)
	stateActual, err := makeStateToken(dbid, 7, 2, binding, DefaultLimits(), &old)
	require.NoError(t, err)
	assert.Equal(t, stateExpected, stateActual)
	newFloor := old
	newFloor.Revision = 8
	newFloor.Head = []byte{9, 8, 7}
	newFloor.SuppliedContext = cloneContext(ctx)
	newFloor.ObservationDigest = obsActual
	newFloor.AcceptedEventDigest = [32]byte{}
	trace := []RecordReference{{Key: "0000000000000001", CID: []byte{1, 0x71, 1}, Sequence: 1}}
	eventBody := oracleJSON(t, oracleEvent{Version: 1, Mode: string(ModeReplaceFloor), Reason: string(ReasonFork), OldFloor: oracleFloorFrom(&old), NewFloor: oracleCoreFrom(newFloor), Trace: oracleRefs(trace), Stop: "fork", ObservationDigest: bytes.Clone(obsActual[:]), SuppliedSetDigest: bytes.Clone(set[:])})
	eventExpected := oracleHash("systems.lamb.dottie.local-publication-event.v1", eventBody)
	productionEvent, err := makeEventBody(ModeReplaceFloor, ReasonFork, &old, newFloor, trace, "fork", obsActual, set)
	require.NoError(t, err)
	assert.Equal(t, eventBody, productionEvent)
	assert.Equal(t, "456a3184c852aa40a19c110a3c02a724d32b71e57435a9fd65e2577dd19f7388", fmt.Sprintf("%x", eventExpected[:]))
	confirmationBody := oracleJSON(t, oracleConsent{Version: 1, DatabaseID: bytes.Clone(dbid[:]), Binding: oracleBind(binding), Mode: string(ModeReplaceFloor), OldFloor: oracleFloorFrom(&old), StateToken: bytes.Clone(stateActual[:]), ObservationDigest: bytes.Clone(obsActual[:]), Trace: oracleRefs(trace), Stop: "fork", Reason: string(ReasonFork), Warning: WarningReplacement})
	confirmationExpected := oracleHash("systems.lamb.dottie.local-publication-consent.v1", confirmationBody)
	confirmationActual, err := makeConfirmation(dbid, binding, ModeReplaceFloor, &old, stateActual, obsActual, trace, "fork", ReasonFork, WarningReplacement)
	require.NoError(t, err)
	assert.Equal(t, confirmationExpected, confirmationActual)
	assert.Equal(t, "f2747ef4cf13d485c9accbb64e03da4e1e19be26bece8539a1226ce4ba610d44", fmt.Sprintf("%x", stateExpected[:]))
	assert.Equal(t, "456a3184c852aa40a19c110a3c02a724d32b71e57435a9fd65e2577dd19f7388", fmt.Sprintf("%x", eventExpected[:]))
	assert.Equal(t, "b19251e57a85c3f4c65a4bda64c169c93f05de8580a79d6fcd962f7659a6ba4c", fmt.Sprintf("%x", confirmationExpected[:]))
}

func oracleJSON(t *testing.T, value any) []byte {
	t.Helper()
	var out bytes.Buffer
	e := json.NewEncoder(&out)
	e.SetEscapeHTML(false)
	require.NoError(t, e.Encode(value))
	return bytes.Clone(bytes.TrimSuffix(out.Bytes(), []byte{'\n'}))
}
func oracleHash(domain string, preimage []byte) [32]byte {
	input := make([]byte, 0, len(domain)+1+len(preimage))
	input = append(input, domain...)
	input = append(input, 0)
	input = append(input, preimage...)
	return sha256.Sum256(input)
}
func oracleBind(b Binding) oracleBinding {
	return oracleBinding{b.AccountDID, string(b.Backend), b.Repository, bytes.Clone(b.Vault[:]), storageProfile}
}
func oracleCtx(c SuppliedContext) oracleContext {
	o := oracleContext{RepositoryRevision: c.RepositoryRevision, RepositoryDigest: bytes.Clone(c.RepositoryDigest)}
	if c.Policy != nil {
		o.Policy = &oraclePolicy{c.Policy.Revision, bytes.Clone(c.Policy.Identity), c.Policy.OwnerOnly}
	}
	return o
}
func oracleCoreFrom(f Floor) oracleFloorCore {
	return oracleFloorCore{1, bytes.Clone(f.DatabaseID[:]), f.Revision, f.Generation, string(f.Provenance), bytes.Clone(f.AnchorCID), oracleBind(f.Binding), oracleCtx(f.SuppliedContext), bytes.Clone(f.Head), f.SnapshotKey, f.Sequence, bytes.Clone(f.PublicationID[:]), bytes.Clone(f.RecordCID), bytes.Clone(f.BlobCID), f.BlobSize, bytes.Clone(f.ObservationDigest[:])}
}
func oracleFloorFrom(f *Floor) *oracleFloor {
	if f == nil {
		return nil
	}
	c := oracleCoreFrom(*f)
	return &oracleFloor{c.Version, c.DatabaseID, c.Revision, c.Generation, c.Provenance, c.AnchorCID, c.Binding, c.SuppliedContext, c.Head, c.SnapshotKey, c.Sequence, c.PublicationID, c.RecordCID, c.BlobCID, c.BlobSize, c.ObservationDigest, bytes.Clone(f.AcceptedEventDigest[:])}
}
func oracleLimitsFrom(l Limits) oracleLimits {
	return oracleLimits{l.SuppliedSnapshotCount, l.SuppliedTotalBytes, l.SuppliedContextBytes, l.MaxLineageLinks, l.CacheRecordCount, l.CacheObservationCount, l.CacheLogicalBytes, l.AcceptedRecordCount, l.AcceptedEventCount, l.AcceptedLogicalBytes, l.HistoryPageEvents, l.HistoryEvidenceBytes}
}
func oracleRefs(refs []RecordReference) []oracleReference {
	out := make([]oracleReference, 0, len(refs))
	for _, r := range refs {
		out = append(out, oracleReference{r.Key, bytes.Clone(r.CID), r.Sequence})
	}
	return out
}
