package publicationstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStrictPrivateJSONRejectsDuplicateUnknownTrailingAndArrayBinary(t *testing.T) {
	wire := bindingToWire(
		Binding{
			AccountDID: "did:plc:abcdefghijklmnopqrstuvwx",
			Backend:    BackendPublicRepo,
			Repository: "at://did:plc:abcdefghijklmnopqrstuvwx",
			Vault:      [32]byte{1},
		},
	)
	encoded, err := canonicalJSON(wire)
	require.NoError(t, err)
	var decoded bindingWire
	require.NoError(t, strictJSON(encoded, &decoded))
	for _, invalid := range [][]byte{
		[]byte(strings.Replace(string(encoded), `"backend":"public-repo"`, `"backend":"public-repo","backend":"spaces"`, 1)),
		[]byte(strings.TrimSuffix(string(encoded), `}`) + `,"extension":true}`),
		append(bytes.Clone(encoded), []byte(` {}`)...),
		[]byte(strings.Replace(string(encoded), `"vault":"`, `"vault":[`, 1)),
	} {
		assert.Error(t, strictJSON(invalid, &decoded))
	}
}

func TestSuppliedSetFramingBindsCountAndLengths(t *testing.T) {
	blocks := []SnapshotBlock{{Key: "0000000000000000", Raw: []byte{1}}, {Key: "0000000000000001", Raw: []byte{2, 3}}}
	framed := makeSetDigest(blocks)
	independentlyFramed := independentSetDigest(blocks)
	assert.Equal(t, independentlyFramed, framed)
	ambiguousPartition := []SnapshotBlock{
		{Key: "0000000000000000", Raw: []byte{1, 2}},
		{Key: "0000000000000001", Raw: []byte{3}},
	}
	assert.NotEqual(t, framed, makeSetDigest(ambiguousPartition))
	assert.NotEqual(t, framed, makeSetDigest(blocks[:1]))
}

func assertConfirmationFieldCoverage(
	t *testing.T,
	dbid [32]byte,
	binding Binding,
	old Floor,
	token, observation [32]byte,
	trace []RecordReference,
	expected [32]byte,
) {
	t.Helper()
	check := func(name string, id [32]byte, b Binding, mode Mode, prior *Floor, state, obs [32]byte, refs []RecordReference, stop string, reason Reason, warning string) {
		t.Helper()
		actual, err := makeConfirmation(id, b, mode, prior, state, obs, refs, stop, reason, warning)
		require.NoError(t, err)
		assert.NotEqual(t, expected, actual, name)
	}
	changedID := dbid
	changedID[0]++
	check(
		"database id",
		changedID,
		binding,
		ModeReplaceFloor,
		&old,
		token,
		observation,
		trace,
		"fork",
		ReasonFork,
		WarningReplacement,
	)
	changedBinding := binding
	changedBinding.AccountDID += "x"
	check(
		"binding",
		dbid,
		changedBinding,
		ModeReplaceFloor,
		&old,
		token,
		observation,
		trace,
		"fork",
		ReasonFork,
		WarningReplacement,
	)
	check("mode", dbid, binding, ModeFirstUse, &old, token, observation, trace, "fork", ReasonFork, WarningReplacement)
	check(
		"absent old floor",
		dbid,
		binding,
		ModeReplaceFloor,
		nil,
		token,
		observation,
		trace,
		"fork",
		ReasonFork,
		WarningReplacement,
	)
	changedToken := token
	changedToken[0]++
	check(
		"state token",
		dbid,
		binding,
		ModeReplaceFloor,
		&old,
		changedToken,
		observation,
		trace,
		"fork",
		ReasonFork,
		WarningReplacement,
	)
	changedObservation := observation
	changedObservation[0]++
	check(
		"observation",
		dbid,
		binding,
		ModeReplaceFloor,
		&old,
		token,
		changedObservation,
		trace,
		"fork",
		ReasonFork,
		WarningReplacement,
	)
	changedTrace := cloneReferences(trace)
	changedTrace[0].Key = "0000000000000002"
	check(
		"trace key",
		dbid,
		binding,
		ModeReplaceFloor,
		&old,
		token,
		observation,
		changedTrace,
		"fork",
		ReasonFork,
		WarningReplacement,
	)
	changedTrace = cloneReferences(trace)
	changedTrace[0].CID[0]++
	check(
		"trace cid",
		dbid,
		binding,
		ModeReplaceFloor,
		&old,
		token,
		observation,
		changedTrace,
		"fork",
		ReasonFork,
		WarningReplacement,
	)
	changedTrace = cloneReferences(trace)
	changedTrace[0].Sequence++
	check(
		"trace sequence",
		dbid,
		binding,
		ModeReplaceFloor,
		&old,
		token,
		observation,
		changedTrace,
		"fork",
		ReasonFork,
		WarningReplacement,
	)
	check(
		"stop",
		dbid,
		binding,
		ModeReplaceFloor,
		&old,
		token,
		observation,
		trace,
		"missing_parent",
		ReasonFork,
		WarningReplacement,
	)
	check(
		"reason",
		dbid,
		binding,
		ModeReplaceFloor,
		&old,
		token,
		observation,
		trace,
		"fork",
		ReasonRollback,
		WarningReplacement,
	)
	check(
		"warning",
		dbid,
		binding,
		ModeReplaceFloor,
		&old,
		token,
		observation,
		trace,
		"fork",
		ReasonFork,
		WarningFirstUse,
	)
	for name, mutate := range map[string]func(*Floor){
		"old revision":           func(f *Floor) { f.Revision++ },
		"old generation":         func(f *Floor) { f.Generation++ },
		"old provenance":         func(f *Floor) { f.Provenance = ProvenanceReplace },
		"old anchor":             func(f *Floor) { f.AnchorCID[0]++ },
		"old repository context": func(f *Floor) { f.SuppliedContext.RepositoryRevision += "x" },
		"old policy":             func(f *Floor) { f.SuppliedContext.Policy.Revision += "x" },
		"old head":               func(f *Floor) { f.Head[0]++ },
		"old key":                func(f *Floor) { f.SnapshotKey = "0000000000000002" },
		"old sequence":           func(f *Floor) { f.Sequence++ },
		"old publication id":     func(f *Floor) { f.PublicationID[0]++ },
		"old record cid":         func(f *Floor) { f.RecordCID[0]++ },
		"old blob cid":           func(f *Floor) { f.Segments[0].BlobCID[0]++ },
		"old blob size":          func(f *Floor) { f.Segments[0].BlobSize++ },
		"old observation digest": func(f *Floor) { f.ObservationDigest[0]++ },
		"old accepted digest":    func(f *Floor) { f.AcceptedEventDigest[0]++ },
	} {
		mutated := cloneFloor(old)
		mutate(&mutated)
		check(
			name,
			dbid,
			binding,
			ModeReplaceFloor,
			&mutated,
			token,
			observation,
			trace,
			"fork",
			ReasonFork,
			WarningReplacement,
		)
	}
}

func independentSetDigest(blocks []SnapshotBlock) [32]byte {
	hash := sha256.New()
	hash.Write([]byte("systems.lamb.dottie.local-record-set.v1"))
	hash.Write([]byte{0})
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(blocks)))
	hash.Write(count[:])
	for _, block := range blocks {
		hash.Write([]byte(block.Key))
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(block.Raw)))
		hash.Write(length[:])
		hash.Write(block.Raw)
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func fmtHex(data []byte) string { return hex.EncodeToString(data) }
