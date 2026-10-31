package atproto

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/repo/mst"
	"github.com/ipfs/go-cid"
	"github.com/ipld/go-car"
	"github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const proofTestDID = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"

type proofBlock struct {
	cid  cid.Cid
	data []byte
}

type proofFixture struct {
	car          []byte
	root         cid.Cid
	private      *atcrypto.PrivateKeyP256
	public       atcrypto.PublicKey
	methods      []VerificationMethod
	blocks       []proofBlock
	recordBlocks map[string]cid.Cid
	commit       *repo.Commit
}

type countedStream struct {
	data []byte
	read int
}

func (s *countedStream) Read(buffer []byte) (int, error) {
	if s.read >= len(s.data) {
		return 0, io.EOF
	}
	count := copy(buffer, s.data[s.read:])
	s.read += count
	return count, nil
}

func (s *countedStream) Close() error {
	return nil
}

type proofTransport struct {
	carBytes      []byte
	streamBody    io.ReadCloser
	latestCIDs    []string
	latestCalls   int
	streamCalls   int
	latestStatus  int
	latestBody    []byte
	streamStatus  int
	streamError   error
	doStatus      int
	doBody        []byte
	doError       error
	requestMethod string
	requestPath   string
	requestBody   []byte
	requestQuery  url.Values
	repoQuery     url.Values
}

func (f *proofTransport) Do(_ context.Context, method, endpoint string, query url.Values, body []byte, _ string) (int, []byte, error) {
	f.requestMethod = method
	f.requestPath = endpoint
	f.requestBody = append([]byte(nil), body...)
	f.requestQuery = cloneURLValues(query)
	if endpoint == "com.atproto.sync.getLatestCommit" {
		index := f.latestCalls
		f.latestCalls++
		if f.latestStatus != 0 {
			return f.latestStatus, append([]byte(nil), f.latestBody...), f.doError
		}
		if index >= len(f.latestCIDs) {
			index = len(f.latestCIDs) - 1
		}
		return 200, []byte(fmt.Sprintf(`{"cid":%q,"rev":"2222222222222"}`, f.latestCIDs[index])), nil
	}
	return f.doStatus, append([]byte(nil), f.doBody...), f.doError
}

func (f *proofTransport) OpenStream(_ context.Context, endpoint string, query url.Values) (int, io.ReadCloser, error) {
	f.streamCalls++
	f.requestPath = endpoint
	f.requestQuery = cloneURLValues(query)
	f.repoQuery = cloneURLValues(query)
	if f.streamError != nil {
		return f.streamStatus, nil, f.streamError
	}
	if f.streamBody != nil {
		return f.streamStatus, f.streamBody, nil
	}
	return f.streamStatus, io.NopCloser(bytes.NewReader(f.carBytes)), nil
}

func makeProofFixture(t *testing.T, recordCount int) proofFixture {
	t.Helper()
	privateKey, err := atcrypto.GeneratePrivateKeyP256()
	if err != nil {
		require.NoError(t, err)
	}
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		require.NoError(t, err)
	}
	tree := mst.NewEmptyTree()
	blocksList := make([]proofBlock, 0, recordCount+16)
	records := make(map[string]cid.Cid, recordCount)
	for index := 0; index < recordCount; index++ {
		recordPath := fmt.Sprintf("systems.lamb.dottie.vaultSnapshot/r%d", index)
		data, err := atdata.MarshalCBOR(map[string]any{"$type": "systems.lamb.dottie.vaultSnapshot", "probe": fmt.Sprintf("p%d", index)})
		if err != nil {
			require.NoError(t, err)
		}
		recordCID := proofCID(t, data)
		if _, err := tree.Insert([]byte(recordPath), recordCID); err != nil {
			require.NoError(t, err)
		}
		records[recordPath] = recordCID
		blocksList = append(blocksList, proofBlock{cid: recordCID, data: data})
	}
	rootCID := storeProofMST(t, tree.Root, &blocksList)
	commit := &repo.Commit{DID: proofTestDID, Version: repo.ATPROTO_REPO_VERSION, Data: rootCID, Rev: "2222222222222"}
	if err := commit.Sign(privateKey); err != nil {
		require.NoError(t, err)
	}
	commitBytes := new(bytes.Buffer)
	if err := commit.MarshalCBOR(commitBytes); err != nil {
		require.NoError(t, err)
	}
	commitCID := proofCID(t, commitBytes.Bytes())
	blocksList = append(blocksList, proofBlock{cid: commitCID, data: commitBytes.Bytes()})
	carBytes := encodeProofCAR(t, commitCID, blocksList)
	return proofFixture{
		car:          carBytes,
		root:         commitCID,
		private:      privateKey,
		public:       publicKey,
		methods:      []VerificationMethod{{ID: proofTestDID + "#atproto", Type: "Multikey", Controller: proofTestDID, PublicKeyMultibase: publicKey.Multibase()}},
		blocks:       blocksList,
		recordBlocks: records,
		commit:       commit,
	}
}

func proofCID(t *testing.T, data []byte) cid.Cid {
	t.Helper()
	result, err := cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256).Sum(data)
	if err != nil {
		require.NoError(t, err)
	}
	return result
}

func storeProofMST(t *testing.T, node *mst.Node, blocksList *[]proofBlock) cid.Cid {
	t.Helper()
	for index := range node.Entries {
		if child := node.Entries[index].Child; child != nil {
			childCID := storeProofMST(t, child, blocksList)
			node.Entries[index].ChildCID = &childCID
		}
	}
	nodeData := node.NodeData()
	encoded, nodeCID, err := nodeData.Bytes()
	if err != nil {
		require.NoError(t, err)
	}
	node.CID = nodeCID
	node.Dirty = false
	*blocksList = append(*blocksList, proofBlock{cid: *nodeCID, data: encoded})
	return *nodeCID
}

func encodeProofCAR(t *testing.T, root cid.Cid, blocksList []proofBlock) []byte {
	t.Helper()
	var output bytes.Buffer
	if err := car.WriteHeader(&car.CarHeader{Roots: []cid.Cid{root}, Version: 1}, &output); err != nil {
		require.NoError(t, err)
	}
	for _, block := range blocksList {
		sectionSize := len(block.cid.Bytes()) + len(block.data)
		var length [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(length[:], uint64(sectionSize))
		output.Write(length[:n])
		output.Write(block.cid.Bytes())
		output.Write(block.data)
	}
	return output.Bytes()
}

func proofReader(fixture proofFixture, transport Transport, budgets Budgets) RevisionReader {
	return RevisionReader{Transport: transport, Budgets: budgets, DIDDocumentID: proofTestDID, VerificationMethods: fixture.methods}
}

func TestRevisionReaderVerifiesSignatureAndCARMembership(t *testing.T) {
	fixture := makeProofFixture(t, 2)
	transport := &proofTransport{carBytes: fixture.car, latestCIDs: []string{fixture.root.String(), fixture.root.String()}, streamStatus: 200}
	revision, err := proofReader(fixture, transport, DefaultBudgets()).Read(context.Background(), proofTestDID)
	if err != nil {
		require.NoError(t, err)
	}
	if revision.commitCID != fixture.root.String() || len(revision.membership) != 2 || len(revision.records) != 2 {
		require.False(t, revision.commitCID != fixture.root.String() || len(revision.membership) != 2 || len(revision.records) != 2, "verified revision=%+v", revision)
	}
	if transport.latestCalls != 2 || transport.streamCalls != 1 {
		require.False(t, transport.latestCalls != 2 || transport.streamCalls != 1, "read call counts latest=%d repo=%d", transport.latestCalls, transport.streamCalls)
	}
	if transport.repoQuery.Get("did") != proofTestDID || transport.repoQuery.Has("since") {
		require.False(t, transport.repoQuery.Get("did") != proofTestDID || transport.repoQuery.Has("since"), "getRepo request query=%v", transport.repoQuery)
	}
	key := RecordKey{Collection: "systems.lamb.dottie.vaultSnapshot", RKey: "r0"}
	membership := revision.Membership()
	membership[key] = "tampered"
	records := revision.Records()
	record := records[key]
	record.Data[0] ^= 0xff
	if !revision.HasRecord(key) || revision.Membership()[key] == "tampered" || bytes.Equal(revision.Records()[key].Data, record.Data) {
		require.False(t, !revision.HasRecord(key) || revision.Membership()[key] == "tampered" || bytes.Equal(revision.Records()[key].Data, record.Data), "revision membership or record bytes were mutable through the public view")
	}
}

func TestRevisionReaderRejectsWrongSignatureKey(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	other, err := atcrypto.GeneratePrivateKeyP256()
	if err != nil {
		require.NoError(t, err)
	}
	otherPublic, err := other.PublicKey()
	if err != nil {
		require.NoError(t, err)
	}
	fixture.methods[0].PublicKeyMultibase = otherPublic.Multibase()
	transport := &proofTransport{carBytes: fixture.car, latestCIDs: []string{fixture.root.String()}, streamStatus: 200}
	_, err = proofReader(fixture, transport, DefaultBudgets()).Read(context.Background(), proofTestDID)
	if !errors.Is(err, ErrSignature) {
		require.ErrorIs(t, err, ErrSignature, "wrong signing key error=%v", err)
	}
}

func TestRevisionReaderRejectsDIDBindingMismatch(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	fixture.commit.DID = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"
	commitBytes := new(bytes.Buffer)
	if err := fixture.commit.Sign(fixture.private); err != nil {
		require.NoError(t, err)
	}
	if err := fixture.commit.MarshalCBOR(commitBytes); err != nil {
		require.NoError(t, err)
	}
	commitCID := proofCID(t, commitBytes.Bytes())
	blocksList := append([]proofBlock(nil), fixture.blocks[:len(fixture.blocks)-1]...)
	blocksList = append(blocksList, proofBlock{cid: commitCID, data: commitBytes.Bytes()})
	fixture.car = encodeProofCAR(t, commitCID, blocksList)
	fixture.root = commitCID
	transport := &proofTransport{carBytes: fixture.car, latestCIDs: []string{commitCID.String()}, streamStatus: 200}
	_, err := proofReader(fixture, transport, DefaultBudgets()).Read(context.Background(), proofTestDID)
	if !errors.Is(err, ErrKeyBinding) {
		require.ErrorIs(t, err, ErrKeyBinding, "commit DID mismatch error=%v", err)
	}
}

func TestRevisionReaderRetriesWhenAdvertisedCommitMoves(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	otherCID := proofCID(t, []byte("other advertised root")).String()
	transport := &proofTransport{carBytes: fixture.car, latestCIDs: []string{fixture.root.String(), otherCID, fixture.root.String(), otherCID, fixture.root.String(), otherCID}, streamStatus: 200}
	_, err := proofReader(fixture, transport, DefaultBudgets()).Read(context.Background(), proofTestDID)
	require.ErrorIs(t, err, ErrRevisionMoving, "moving read error=%v latest=%d repo=%d", err, transport.latestCalls, transport.streamCalls)
	require.Equal(t, 6, transport.latestCalls, "moving read error=%v latest=%d repo=%d", err, transport.latestCalls, transport.streamCalls)
	require.Equal(t, 3, transport.streamCalls, "moving read error=%v latest=%d repo=%d", err, transport.latestCalls, transport.streamCalls)
}

func TestRevisionReaderRejectsOversizedCARDuringIngestion(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	budgets := DefaultBudgets()
	budgets.MaxCarBytes = 32
	stream := &countedStream{data: bytes.Repeat([]byte{0}, 100)}
	transport := &proofTransport{streamBody: stream, latestCIDs: []string{fixture.root.String()}, streamStatus: 200}
	_, err := proofReader(fixture, transport, budgets).Read(context.Background(), proofTestDID)
	require.ErrorIs(t, err, ErrUntrustedCar, "oversized CAR error=%v bytes-read=%d", err, stream.read)
	require.ErrorContains(t, err, "MaxCarBytes", "oversized CAR error=%v bytes-read=%d", err, stream.read)
	require.Equal(t, 33, stream.read, "oversized CAR error=%v bytes-read=%d", err, stream.read)
}

func TestRevisionReaderAppliesEveryCARBudget(t *testing.T) {
	fixture := makeProofFixture(t, 2)
	checks := []struct {
		name   string
		change func(*Budgets)
		want   string
	}{
		{name: "block count", change: func(b *Budgets) { b.MaxBlocks = 1 }, want: "MaxBlocks"},
		{name: "block bytes", change: func(b *Budgets) { b.MaxBlockBytes = 1 }, want: "MaxBlockBytes"},
		{name: "membership count", change: func(b *Budgets) { b.MaxMembershipRecords = 1 }, want: "MaxMembershipRecords"},
		{name: "MST depth", change: func(b *Budgets) { b.MaxMSTDepth = 1 }, want: "MaxMSTDepth"},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			budgets := DefaultBudgets()
			check.change(&budgets)
			testFixture := fixture
			if check.want == "MaxMSTDepth" {
				testFixture = makeProofFixture(t, 300)
			}
			transport := &proofTransport{carBytes: testFixture.car, latestCIDs: []string{testFixture.root.String()}, streamStatus: 200}
			_, err := proofReader(testFixture, transport, budgets).Read(context.Background(), proofTestDID)
			require.ErrorIs(t, err, ErrUntrustedCar, "budget error=%v want bound %s", err, check.want)
			require.ErrorContains(t, err, check.want, "budget error=%v want bound %s", err, check.want)
		})
	}
}

func TestRevisionReaderRejectsPartialMST(t *testing.T) {
	fixture := makeProofFixture(t, 300)
	var kept []proofBlock
	removedNode := false
	for _, block := range fixture.blocks {
		isRecord := false
		for _, recordCID := range fixture.recordBlocks {
			if block.cid.Equals(recordCID) {
				isRecord = true
				break
			}
		}
		if !removedNode && !isRecord && block.cid != fixture.root && block.cid.Prefix().Codec == cid.DagCBOR {
			removedNode = true
			continue
		}
		kept = append(kept, block)
	}
	if !removedNode {
		require.True(t, removedNode, "fixture did not contain a removable MST node")
	}
	partialCAR := encodeProofCAR(t, fixture.root, kept)
	transport := &proofTransport{carBytes: partialCAR, latestCIDs: []string{fixture.root.String()}, streamStatus: 200}
	_, err := proofReader(fixture, transport, DefaultBudgets()).Read(context.Background(), proofTestDID)
	if !errors.Is(err, ErrUnprovenMembership) {
		require.ErrorIs(t, err, ErrUnprovenMembership, "partial MST error=%v", err)
	}
}

func TestRevisionReaderRejectsMissingRecordBlock(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	missing := fixture.recordBlocks["systems.lamb.dottie.vaultSnapshot/r0"]
	var kept []proofBlock
	for _, block := range fixture.blocks {
		if block.cid != missing {
			kept = append(kept, block)
		}
	}
	carBytes := encodeProofCAR(t, fixture.root, kept)
	transport := &proofTransport{carBytes: carBytes, latestCIDs: []string{fixture.root.String()}, streamStatus: 200}
	_, err := proofReader(fixture, transport, DefaultBudgets()).Read(context.Background(), proofTestDID)
	if !errors.Is(err, ErrUnprovenMembership) {
		require.ErrorIs(t, err, ErrUnprovenMembership, "missing record block error=%v", err)
	}
}

func TestRevisionReaderRejectsDuplicateBlocks(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	blocksList := append(append([]proofBlock(nil), fixture.blocks...), fixture.blocks[0])
	carBytes := encodeProofCAR(t, fixture.root, blocksList)
	_, err := validateCARBudgets(carBytes, DefaultBudgets())
	require.ErrorIs(t, err, ErrUntrustedCar, "duplicate block error=%v", err)
	require.ErrorContains(t, err, "duplicate CAR block", "duplicate block error=%v", err)
}

func TestRevisionReaderRejectsDuplicateMSTKeys(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	recordCID := fixture.recordBlocks["systems.lamb.dottie.vaultSnapshot/r0"]
	path := []byte("systems.lamb.dottie.vaultSnapshot/r0")
	nodeData := mst.NodeData{Entries: []mst.EntryData{{KeySuffix: path, Value: recordCID}, {KeySuffix: path, Value: recordCID}}}
	nodeBytes, nodeCID, err := nodeData.Bytes()
	if err != nil {
		require.NoError(t, err)
	}
	commit := &repo.Commit{DID: proofTestDID, Version: repo.ATPROTO_REPO_VERSION, Data: *nodeCID, Rev: fixture.commit.Rev}
	if err := commit.Sign(fixture.private); err != nil {
		require.NoError(t, err)
	}
	commitBytes := new(bytes.Buffer)
	if err := commit.MarshalCBOR(commitBytes); err != nil {
		require.NoError(t, err)
	}
	commitCID := proofCID(t, commitBytes.Bytes())
	carBytes := encodeProofCAR(t, commitCID, []proofBlock{{cid: recordCID, data: mustRecordData(t, fixture, recordCID)}, {cid: *nodeCID, data: nodeBytes}, {cid: commitCID, data: commitBytes.Bytes()}})
	transport := &proofTransport{carBytes: carBytes, latestCIDs: []string{commitCID.String()}, streamStatus: 200}
	revision, err := proofReader(fixture, transport, DefaultBudgets()).Read(context.Background(), proofTestDID)
	if !errors.Is(err, ErrUntrustedCar) {
		require.ErrorIs(t, err, ErrUntrustedCar, "duplicate MST key error=%v", err)
	}
	require.Nil(t, revision, "rejected revision returned a non-nil revision: %+v", revision)
}

func mustRecordData(t *testing.T, fixture proofFixture, target cid.Cid) []byte {
	t.Helper()
	for _, block := range fixture.blocks {
		if block.cid.Equals(target) {
			return block.data
		}
	}
	require.FailNow(t, "record block not found")
	return nil
}

func TestRepositorySigningKeyBindingAndAlgorithm(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	if _, err := repositorySigningKey(fixture.methods, proofTestDID); err != nil {
		require.NoError(t, err)
	}
	relativeMethod := append([]VerificationMethod(nil), fixture.methods...)
	relativeMethod[0].ID = "#atproto"
	if _, err := repositorySigningKey(relativeMethod, proofTestDID); err != nil {
		require.NoError(t, err, "relative #atproto verification method was rejected: %v", err)
	}
	for _, methods := range [][]VerificationMethod{
		{{ID: proofTestDID + "#authentication", Type: "Multikey", Controller: proofTestDID, PublicKeyMultibase: fixture.public.Multibase()}},
		{{ID: proofTestDID + "#atproto", Type: "Multikey", Controller: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", PublicKeyMultibase: fixture.public.Multibase()}},
		{{ID: proofTestDID + "#atproto", Type: "Multikey", Controller: proofTestDID}},
		{fixture.methods[0], fixture.methods[0]},
	} {
		if _, err := repositorySigningKey(methods, proofTestDID); !errors.Is(err, ErrKeyBinding) {
			assert.ErrorIs(t, err, ErrKeyBinding, "invalid verification methods error=%v", err)
		}
	}
	wrongPurpose := []VerificationMethod{{ID: proofTestDID + "#atproto", Type: "JsonWebKey", Controller: proofTestDID, PublicKeyMultibase: fixture.public.Multibase()}}
	_, err := repositorySigningKey(wrongPurpose, proofTestDID)
	require.ErrorIs(t, err, ErrWrongKeyPurpose, "wrong-purpose key error=%v", err)
	require.ErrorIs(t, err, ErrKeyBinding, "wrong-purpose key error=%v", err)
	malformed := []VerificationMethod{{ID: proofTestDID + "#atproto", Type: "Multikey", Controller: proofTestDID, PublicKeyMultibase: "not-multibase"}}
	_, err = repositorySigningKey(malformed, proofTestDID)
	require.ErrorIs(t, err, ErrMalformedPublicKey, "malformed public key error=%v", err)
	require.ErrorIs(t, err, ErrKeyBinding, "malformed public key error=%v", err)
	secp256k1 := "zQ3shcnfWLQN1bY4d2patsEAYFzy4xp1zdckEvHsV7S4ocTnC"
	accepted := []VerificationMethod{{ID: proofTestDID + "#atproto", Type: "Multikey", Controller: proofTestDID, PublicKeyMultibase: secp256k1}}
	if _, err := repositorySigningKey(accepted, proofTestDID); err != nil {
		require.NoError(t, err, "the live network uses secp256k1 Multikey keys and must be accepted: %v", err)
	}
	unsupported := []VerificationMethod{{ID: proofTestDID + "#atproto", Type: "Multikey", Controller: proofTestDID, PublicKeyMultibase: "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"}}
	_, err = repositorySigningKey(unsupported, proofTestDID)
	require.ErrorIs(t, err, ErrUnsupportedSigningAlgorithm, "unsupported signing algorithm error=%v", err)
	require.ErrorIs(t, err, ErrKeyBinding, "unsupported signing algorithm error=%v", err)
}

func TestDefaultBudgetsMatchPublicationFenceLimits(t *testing.T) {
	budgets := DefaultBudgets()
	if budgets.MaxCarBytes != 8<<20 || budgets.MaxBlocks != 8192 || budgets.MaxBlockBytes != 1<<20 || budgets.MaxMembershipRecords != 4096 || budgets.MaxMSTDepth != 32 {
		require.False(t, budgets.MaxCarBytes != 8<<20 || budgets.MaxBlocks != 8192 || budgets.MaxBlockBytes != 1<<20 || budgets.MaxMembershipRecords != 4096 || budgets.MaxMSTDepth != 32, "default budgets=%+v", budgets)
	}
}

func TestCarBlockRehashesAreChecked(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	mutated := append([]proofBlock(nil), fixture.blocks...)
	mutated[0].data = []byte("different bytes")
	carBytes := encodeProofCAR(t, fixture.root, mutated)
	if _, err := validateCARBudgets(carBytes, DefaultBudgets()); !errors.Is(err, ErrUntrustedCar) {
		require.ErrorIs(t, err, ErrUntrustedCar, "mismatched block bytes error=%v", err)
	}
}

func TestTransportStreamErrorIsAmbiguous(t *testing.T) {
	fixture := makeProofFixture(t, 1)
	transport := &proofTransport{latestCIDs: []string{fixture.root.String()}, streamError: errors.New("connection interrupted"), streamStatus: 200}
	_, err := proofReader(fixture, transport, DefaultBudgets()).Read(context.Background(), proofTestDID)
	if !errors.Is(err, ErrAmbiguousTransport) {
		require.ErrorIs(t, err, ErrAmbiguousTransport, "stream failure error=%v", err)
	}
}

func TestPartialTreeDepthFixtureHasMultipleLevels(t *testing.T) {
	fixture := makeProofFixture(t, 300)
	_, loaded, err := repo.LoadRepoFromCAR(context.Background(), bytes.NewReader(fixture.car))
	if err != nil {
		require.NoError(t, err)
	}
	if mstDepth(loaded.MST.Root) < 2 {
		require.GreaterOrEqual(t, mstDepth(loaded.MST.Root), 2, "fixture MST depth=%d", mstDepth(loaded.MST.Root))
	}
}
