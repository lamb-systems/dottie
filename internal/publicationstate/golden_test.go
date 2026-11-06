package publicationstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrivateWireGoldenVectors(t *testing.T) {
	binding := Binding{AccountDID: "did:plc:abcdefghijklmnopqrstuvwx", Backend: BackendSpaces, Repository: "at://did:plc:abcdefghijklmnopqrstuvwx/systems.lamb.dottie.vaultSnapshotV2/record"}
	for index := range binding.Vault {
		binding.Vault[index] = byte(index + 1)
	}
	context := SuppliedContext{RepositoryRevision: "r<>&", RepositoryDigest: []byte{0, 1, 2, 255}, Policy: &Policy{Revision: "p<>&", Identity: []byte{4, 5, 6, 7}, OwnerOnly: true}}
	wireBytes, err := canonicalJSON(bindingToWire(Binding{AccountDID: "<>&", Backend: BackendSpaces, Repository: "repo", Vault: binding.Vault}))
	require.NoError(t, err)
	assert.Equal(t, `{"accountDid":"<>&","backend":"spaces","repository":"repo","vault":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","profile":"systems.lamb.dottie.vaultSnapshotV2+systems.lamb.dottie.vaultHeadV2;schemaVersion=2"}`, string(wireBytes))
	blocks := []SnapshotBlock{{Key: "0000000000000000", Raw: []byte{0, 1, 2, 3}}, {Key: "0000000000000001", Raw: []byte{0xff, 0x80}}}
	setDigest := makeSetDigest(blocks)
	assert.Equal(t, "89f31e35a02074e8db7cf6062b8f4e5c3f9ab88c5e7ec34b5ffc74d464adce7b", fmtHex(setDigest[:]))
	observationDigest, err := makeObservationDigest(binding, context, []byte{1, 2, 3, 4}, setDigest)
	require.NoError(t, err)
	assert.Equal(t, "9526c407bd57a00cf5b03717b8c1891d21cf80029d0eb93a9fb5f52fdf905fb2", fmtHex(observationDigest[:]))
	var dbid [32]byte
	var pubid [16]byte
	var oldDigest [32]byte
	var oldEvent [32]byte
	var cid [32]byte
	var blob [32]byte
	for index := range dbid {
		dbid[index] = byte(index)
	}
	for index := range pubid {
		pubid[index] = byte(index + 32)
	}
	for index := range oldDigest {
		oldDigest[index] = byte(index + 64)
		oldEvent[index] = byte(index + 96)
	}
	for index := range cid {
		cid[index] = byte(index + 128)
		blob[index] = byte(index + 160)
	}
	old := Floor{DatabaseID: dbid, Revision: 7, Generation: 2, Provenance: ProvenanceFirst, AnchorCID: []byte{1, 2, 3}, Binding: binding, SuppliedContext: context, Head: []byte{0, 1, 2}, SnapshotKey: "0000000000000001", Sequence: 1, PublicationID: pubid, RecordCID: bytes.Clone(cid[:]), BlobCID: bytes.Clone(blob[:]), BlobSize: 123, ObservationDigest: oldDigest, AcceptedEventDigest: oldEvent}
	stateToken, err := makeStateToken(dbid, 7, 2, binding, DefaultLimits(), &old)
	require.NoError(t, err)
	assert.Equal(t, "f2747ef4cf13d485c9accbb64e03da4e1e19be26bece8539a1226ce4ba610d44", fmtHex(stateToken[:]))
	newFloor := old
	newFloor.Revision = 8
	newFloor.Head = []byte{9, 8, 7}
	newFloor.SuppliedContext = cloneContext(context)
	newFloor.ObservationDigest = observationDigest
	newFloor.AcceptedEventDigest = [32]byte{}
	trace := []RecordReference{{Key: "0000000000000001", CID: []byte{0x01, 0x71, 1}, Sequence: 1}}
	body, err := makeEventBody(ModeReplaceFloor, ReasonFork, &old, newFloor, trace, "fork", observationDigest, setDigest)
	require.NoError(t, err)
	eventDigest := domainHash("systems.lamb.dottie.local-publication-event.v1", body)
	assert.Equal(t, `{"version":1,"mode":"replace-floor","reason":"fork","oldFloor":{"version":1,"databaseId":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","revision":7,"generation":2,"provenance":"first-use","anchorCid":"AQID","binding":{"accountDid":"did:plc:abcdefghijklmnopqrstuvwx","backend":"spaces","repository":"at://did:plc:abcdefghijklmnopqrstuvwx/systems.lamb.dottie.vaultSnapshotV2/record","vault":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","profile":"systems.lamb.dottie.vaultSnapshotV2+systems.lamb.dottie.vaultHeadV2;schemaVersion=2"},"suppliedContext":{"repositoryRevision":"r<>&","repositoryDigest":"AAEC/w==","policy":{"revision":"p<>&","identity":"BAUGBw==","ownerOnly":true}},"head":"AAEC","snapshotKey":"0000000000000001","sequence":1,"publicationId":"ICEiIyQlJicoKSorLC0uLw==","recordCid":"gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8=","blobCid":"oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8=","blobSize":123,"observationDigest":"QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=","acceptedEventDigest":"YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8="},"newFloor":{"version":1,"databaseId":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","revision":8,"generation":2,"provenance":"first-use","anchorCid":"AQID","binding":{"accountDid":"did:plc:abcdefghijklmnopqrstuvwx","backend":"spaces","repository":"at://did:plc:abcdefghijklmnopqrstuvwx/systems.lamb.dottie.vaultSnapshotV2/record","vault":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=","profile":"systems.lamb.dottie.vaultSnapshotV2+systems.lamb.dottie.vaultHeadV2;schemaVersion=2"},"suppliedContext":{"repositoryRevision":"r<>&","repositoryDigest":"AAEC/w==","policy":{"revision":"p<>&","identity":"BAUGBw==","ownerOnly":true}},"head":"CQgH","snapshotKey":"0000000000000001","sequence":1,"publicationId":"ICEiIyQlJicoKSorLC0uLw==","recordCid":"gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8=","blobCid":"oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8=","blobSize":123,"observationDigest":"lSbEB71XoAz1sDcXuMGJHSHPgAKdDrk6n7X1L9+QX7I="},"trace":[{"key":"0000000000000001","cid":"AXEB","sequence":1}],"stop":"fork","observationDigest":"lSbEB71XoAz1sDcXuMGJHSHPgAKdDrk6n7X1L9+QX7I=","suppliedSetDigest":"ifMeNaAgdOjbfPYGK49OXD+auIxefsNLX/x01GStzns="}`, string(body))
	assert.Equal(t, "456a3184c852aa40a19c110a3c02a724d32b71e57435a9fd65e2577dd19f7388", fmtHex(eventDigest[:]))
	confirmation, err := makeConfirmation(dbid, binding, ModeReplaceFloor, &old, stateToken, observationDigest, trace, "fork", ReasonFork, WarningReplacement)
	require.NoError(t, err)
	assert.Equal(t, "b19251e57a85c3f4c65a4bda64c169c93f05de8580a79d6fcd962f7659a6ba4c", fmtHex(confirmation[:]))
	assertConfirmationFieldCoverage(t, dbid, binding, old, stateToken, observationDigest, trace, confirmation)
}

func TestStrictPrivateJSONRejectsDuplicateUnknownTrailingAndArrayBinary(t *testing.T) {
	wire := bindingToWire(Binding{AccountDID: "did:plc:abcdefghijklmnopqrstuvwx", Backend: BackendPublicRepo, Repository: "at://did:plc:abcdefghijklmnopqrstuvwx", Vault: [32]byte{1}})
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
	ambiguousPartition := []SnapshotBlock{{Key: "0000000000000000", Raw: []byte{1, 2}}, {Key: "0000000000000001", Raw: []byte{3}}}
	assert.NotEqual(t, framed, makeSetDigest(ambiguousPartition))
	assert.NotEqual(t, framed, makeSetDigest(blocks[:1]))
}

func assertConfirmationFieldCoverage(t *testing.T, dbid [32]byte, binding Binding, old Floor, token, observation [32]byte, trace []RecordReference, expected [32]byte) {
	t.Helper()
	check := func(name string, id [32]byte, b Binding, mode Mode, prior *Floor, state, obs [32]byte, refs []RecordReference, stop string, reason Reason, warning string) {
		t.Helper()
		actual, err := makeConfirmation(id, b, mode, prior, state, obs, refs, stop, reason, warning)
		require.NoError(t, err)
		assert.NotEqual(t, expected, actual, name)
	}
	changedID := dbid
	changedID[0]++
	check("database id", changedID, binding, ModeReplaceFloor, &old, token, observation, trace, "fork", ReasonFork, WarningReplacement)
	changedBinding := binding
	changedBinding.AccountDID += "x"
	check("binding", dbid, changedBinding, ModeReplaceFloor, &old, token, observation, trace, "fork", ReasonFork, WarningReplacement)
	check("mode", dbid, binding, ModeFirstUse, &old, token, observation, trace, "fork", ReasonFork, WarningReplacement)
	check("absent old floor", dbid, binding, ModeReplaceFloor, nil, token, observation, trace, "fork", ReasonFork, WarningReplacement)
	changedToken := token
	changedToken[0]++
	check("state token", dbid, binding, ModeReplaceFloor, &old, changedToken, observation, trace, "fork", ReasonFork, WarningReplacement)
	changedObservation := observation
	changedObservation[0]++
	check("observation", dbid, binding, ModeReplaceFloor, &old, token, changedObservation, trace, "fork", ReasonFork, WarningReplacement)
	changedTrace := cloneReferences(trace)
	changedTrace[0].Key = "0000000000000002"
	check("trace key", dbid, binding, ModeReplaceFloor, &old, token, observation, changedTrace, "fork", ReasonFork, WarningReplacement)
	changedTrace = cloneReferences(trace)
	changedTrace[0].CID[0]++
	check("trace cid", dbid, binding, ModeReplaceFloor, &old, token, observation, changedTrace, "fork", ReasonFork, WarningReplacement)
	changedTrace = cloneReferences(trace)
	changedTrace[0].Sequence++
	check("trace sequence", dbid, binding, ModeReplaceFloor, &old, token, observation, changedTrace, "fork", ReasonFork, WarningReplacement)
	check("stop", dbid, binding, ModeReplaceFloor, &old, token, observation, trace, "missing_parent", ReasonFork, WarningReplacement)
	check("reason", dbid, binding, ModeReplaceFloor, &old, token, observation, trace, "fork", ReasonRollback, WarningReplacement)
	check("warning", dbid, binding, ModeReplaceFloor, &old, token, observation, trace, "fork", ReasonFork, WarningFirstUse)
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
		"old blob cid":           func(f *Floor) { f.BlobCID[0]++ },
		"old blob size":          func(f *Floor) { f.BlobSize++ },
		"old observation digest": func(f *Floor) { f.ObservationDigest[0]++ },
		"old accepted digest":    func(f *Floor) { f.AcceptedEventDigest[0]++ },
	} {
		mutated := cloneFloor(old)
		mutate(&mutated)
		check(name, dbid, binding, ModeReplaceFloor, &mutated, token, observation, trace, "fork", ReasonFork, WarningReplacement)
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

func fmtHex(data []byte) string { return fmt.Sprintf("%x", data) }
