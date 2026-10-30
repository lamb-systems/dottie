package atproto

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/repo/mst"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/ipfs/go-cid"
	"github.com/ipld/go-car"
)

var (
	ErrRevisionMoving              = errors.New("repository revision kept moving")
	ErrUnprovenMembership          = errors.New("repository membership could not be proven")
	ErrUntrustedCar                = errors.New("untrusted repository CAR")
	ErrSignature                   = errors.New("repository signature verification failed")
	ErrKeyBinding                  = errors.New("repository signing key is not bound to the DID")
	ErrWrongKeyPurpose             = errors.New("repository verification method has the wrong purpose")
	ErrMalformedPublicKey          = errors.New("repository public key is malformed")
	ErrUnsupportedSigningAlgorithm = errors.New("repository signing algorithm is unsupported")
	ErrFenceLost                   = errors.New("publication commit fence was lost")
	ErrBatchRejected               = errors.New("publication batch was rejected")
	ErrAmbiguousTransport          = errors.New("publication or read transport outcome is ambiguous")
	ErrCandidateMayBeDisclosed     = errors.New("a rejected publication may have left the staged candidate retrievable by CID")
)

type Budgets struct {
	MaxCarBytes          int64
	MaxBlocks            int
	MaxBlockBytes        int64
	MaxMembershipRecords int
	MaxMSTDepth          int
}

func DefaultBudgets() Budgets {
	return Budgets{
		MaxCarBytes:          8 << 20,
		MaxBlocks:            8192,
		MaxBlockBytes:        1 << 20,
		MaxMembershipRecords: 4096,
		MaxMSTDepth:          32,
	}
}

type Transport interface {
	Do(ctx context.Context, method, endpoint string, query url.Values, body []byte, contentType string) (int, []byte, error)
	OpenStream(ctx context.Context, endpoint string, query url.Values) (status int, body io.ReadCloser, err error)
}

type RecordKey struct {
	Collection string
	RKey       string
}

type ProvenRecord struct {
	CID  string
	Data []byte
}

type Revision struct {
	did        string
	commitCID  string
	rev        string
	membership map[RecordKey]string
	records    map[RecordKey]ProvenRecord
}

func (r *Revision) DID() string {
	if r == nil {
		return ""
	}
	return r.did
}

func (r *Revision) CommitCID() string {
	if r == nil {
		return ""
	}
	return r.commitCID
}

func (r *Revision) Rev() string {
	if r == nil {
		return ""
	}
	return r.rev
}

func (r *Revision) Membership() map[RecordKey]string {
	if r == nil {
		return nil
	}
	membership := make(map[RecordKey]string, len(r.membership))
	for key, value := range r.membership {
		membership[key] = value
	}
	return membership
}

func (r *Revision) Records() map[RecordKey]ProvenRecord {
	if r == nil {
		return nil
	}
	records := make(map[RecordKey]ProvenRecord, len(r.records))
	for key, record := range r.records {
		records[key] = ProvenRecord{CID: record.CID, Data: append([]byte(nil), record.Data...)}
	}
	return records
}

func (r *Revision) HasRecord(key RecordKey) bool {
	if r == nil {
		return false
	}
	_, exists := r.membership[key]
	return exists
}

type RevisionReader struct {
	Transport           Transport
	Budgets             Budgets
	DIDDocumentID       string
	VerificationMethods []VerificationMethod
}

type latestCommit struct {
	CID string `json:"cid"`
	Rev string `json:"rev"`
}

func (r RevisionReader) Read(ctx context.Context, did string) (*Revision, error) {
	if r.Transport == nil {
		return nil, errors.New("revision transport is required")
	}
	if !validDID(did) || r.DIDDocumentID != did {
		return nil, fmt.Errorf("%w: requested DID and DID-document id must match", ErrKeyBinding)
	}
	budgets := r.Budgets
	if budgets == (Budgets{}) {
		budgets = DefaultBudgets()
	}
	if err := validateBudgets(budgets); err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 3; attempt++ {
		before, err := r.latest(ctx, did)
		if err != nil {
			return nil, err
		}
		carBytes, rootCID, err := r.car(ctx, did, budgets)
		if err != nil {
			return nil, err
		}
		commit, loaded, err := repo.LoadRepoFromCAR(ctx, bytes.NewReader(carBytes))
		if err != nil {
			return nil, fmt.Errorf("%w: CAR repository could not be loaded", ErrUntrustedCar)
		}
		if err := commit.VerifyStructure(); err != nil {
			return nil, fmt.Errorf("%w: malformed repository commit", ErrUntrustedCar)
		}
		if commit.DID != did || loaded.DID.String() != did || r.DIDDocumentID != commit.DID {
			return nil, fmt.Errorf("%w: requested DID, commit DID and DID-document id must match", ErrKeyBinding)
		}
		key, err := repositorySigningKey(r.VerificationMethods, did)
		if err != nil {
			return nil, err
		}
		if err := commit.VerifySignature(key); err != nil {
			return nil, fmt.Errorf("%w: commit signature is invalid", ErrSignature)
		}
		if loaded.MST.IsPartial() {
			return nil, fmt.Errorf("%w: MST is partial", ErrUnprovenMembership)
		}
		if depth := mstDepth(loaded.MST.Root); depth > budgets.MaxMSTDepth {
			return nil, untrustedBound("MaxMSTDepth", depth)
		}
		membership, records, err := verifiedMembership(ctx, loaded, budgets)
		if err != nil {
			return nil, err
		}
		commitCID := rootCID.String()
		after, err := r.latest(ctx, did)
		if err != nil {
			return nil, err
		}
		if before.CID == commitCID && commitCID == after.CID {
			return &Revision{did: did, commitCID: commitCID, rev: commit.Rev, membership: membership, records: records}, nil
		}
	}
	return nil, ErrRevisionMoving
}

func (r RevisionReader) IsCurrent(ctx context.Context, did string, cached *Revision) (bool, error) {
	if cached == nil || cached.did != did {
		return false, fmt.Errorf("%w: cached revision does not belong to the requested DID", ErrKeyBinding)
	}
	current, err := r.Read(ctx, did)
	if err != nil {
		return false, err
	}
	return current.commitCID == cached.commitCID, nil
}

func (r RevisionReader) latest(ctx context.Context, did string) (latestCommit, error) {
	status, body, err := r.Transport.Do(ctx, "GET", "com.atproto.sync.getLatestCommit", url.Values{"did": {did}}, nil, "")
	if err != nil {
		return latestCommit{}, fmt.Errorf("%w: getLatestCommit request failed", ErrAmbiguousTransport)
	}
	if status >= 500 {
		return latestCommit{}, fmt.Errorf("%w: getLatestCommit returned HTTP %d", ErrAmbiguousTransport, status)
	}
	if status < 200 || status >= 300 {
		return latestCommit{}, fmt.Errorf("getLatestCommit returned HTTP %d", status)
	}
	var current latestCommit
	if err := json.Unmarshal(body, &current); err != nil || current.CID == "" {
		return latestCommit{}, fmt.Errorf("%w: getLatestCommit response is malformed", ErrUntrustedCar)
	}
	parsed, err := cid.Parse(current.CID)
	if err != nil {
		return latestCommit{}, fmt.Errorf("%w: getLatestCommit CID is malformed", ErrUntrustedCar)
	}
	current.CID = parsed.String()
	return current, nil
}

func (r RevisionReader) car(ctx context.Context, did string, budgets Budgets) ([]byte, cid.Cid, error) {
	status, stream, err := r.Transport.OpenStream(ctx, "com.atproto.sync.getRepo", url.Values{"did": {did}})
	if err != nil {
		return nil, cid.Undef, fmt.Errorf("%w: getRepo request failed", ErrAmbiguousTransport)
	}
	if stream == nil {
		return nil, cid.Undef, fmt.Errorf("%w: getRepo returned no response body", ErrAmbiguousTransport)
	}
	defer stream.Close()
	if status >= 500 {
		return nil, cid.Undef, fmt.Errorf("%w: getRepo returned HTTP %d", ErrAmbiguousTransport, status)
	}
	if status < 200 || status >= 300 {
		return nil, cid.Undef, fmt.Errorf("getRepo returned HTTP %d", status)
	}
	limited := io.LimitReader(stream, budgets.MaxCarBytes+1)
	carBytes, err := io.ReadAll(limited)
	if int64(len(carBytes)) > budgets.MaxCarBytes {
		return nil, cid.Undef, untrustedBound("MaxCarBytes", len(carBytes))
	}
	if err != nil {
		return nil, cid.Undef, fmt.Errorf("%w: getRepo response stream failed", ErrAmbiguousTransport)
	}
	root, err := validateCARBudgets(carBytes, budgets)
	if err != nil {
		return nil, cid.Undef, err
	}
	return carBytes, root, nil
}

func validateBudgets(budgets Budgets) error {
	if budgets.MaxCarBytes <= 0 || budgets.MaxCarBytes == int64(^uint64(0)>>1) || budgets.MaxBlocks <= 0 || budgets.MaxBlockBytes <= 0 || budgets.MaxMembershipRecords <= 0 || budgets.MaxMSTDepth <= 0 {
		return fmt.Errorf("%w: invalid CAR budgets", ErrUntrustedCar)
	}
	return nil
}

func validateCARBudgets(carBytes []byte, budgets Budgets) (cid.Cid, error) {
	reader, err := car.NewCarReader(bytes.NewReader(carBytes))
	if err != nil {
		return cid.Undef, fmt.Errorf("%w: malformed CAR header", ErrUntrustedCar)
	}
	if len(reader.Header.Roots) != 1 {
		return cid.Undef, fmt.Errorf("%w: CAR must contain exactly one root", ErrUntrustedCar)
	}
	root := reader.Header.Roots[0]
	seen := make(map[string]struct{})
	blockCount := 0
	var cumulative int64
	for {
		block, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return cid.Undef, fmt.Errorf("%w: malformed CAR block", ErrUntrustedCar)
		}
		blockCount++
		if blockCount > budgets.MaxBlocks {
			return cid.Undef, untrustedBound("MaxBlocks", blockCount)
		}
		blockBytes := block.RawData()
		if int64(len(blockBytes)) > budgets.MaxBlockBytes {
			return cid.Undef, untrustedBound("MaxBlockBytes", len(blockBytes))
		}
		cumulative += int64(len(blockBytes))
		if cumulative > budgets.MaxCarBytes {
			return cid.Undef, untrustedBound("MaxCarBytes cumulative block bytes", cumulative)
		}
		key := block.Cid().KeyString()
		if _, exists := seen[key]; exists {
			return cid.Undef, fmt.Errorf("%w: duplicate CAR block CID %s", ErrUntrustedCar, block.Cid())
		}
		seen[key] = struct{}{}
		recomputed, err := block.Cid().Prefix().Sum(blockBytes)
		if err != nil || !recomputed.Equals(block.Cid()) {
			return cid.Undef, fmt.Errorf("%w: CAR block CID mismatch", ErrUntrustedCar)
		}
	}
	if _, exists := seen[root.KeyString()]; !exists {
		return cid.Undef, fmt.Errorf("%w: CAR root block is missing", ErrUntrustedCar)
	}
	return root, nil
}

func untrustedBound(name string, observed any) error {
	return fmt.Errorf("%w: %s exceeded; observed %v", ErrUntrustedCar, name, observed)
}

func repositorySigningKey(methods []VerificationMethod, did string) (atcrypto.PublicKey, error) {
	methodID := did + "#atproto"
	var selected *VerificationMethod
	for index := range methods {
		method := &methods[index]
		if method.ID != methodID && method.ID != "#atproto" {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("%w: multiple #atproto verification methods", ErrKeyBinding)
		}
		selected = method
	}
	if selected == nil || selected.Controller != did || selected.PublicKeyMultibase == "" {
		return nil, fmt.Errorf("%w: exactly one controller-bound #atproto method with publicKeyMultibase is required", ErrKeyBinding)
	}
	switch selected.Type {
	case "Multikey", "EcdsaSecp256r1VerificationKey2019", "EcdsaSecp256k1VerificationKey2019":
	default:
		return nil, fmt.Errorf("%w: %w", ErrKeyBinding, ErrWrongKeyPurpose)
	}
	key, err := atcrypto.ParsePublicMultibase(selected.PublicKeyMultibase)
	if err != nil {
		if strings.Contains(err.Error(), "unsupported atproto key type") {
			return nil, fmt.Errorf("%w: %w", ErrKeyBinding, ErrUnsupportedSigningAlgorithm)
		}
		return nil, fmt.Errorf("%w: %w", ErrKeyBinding, ErrMalformedPublicKey)
	}
	switch key.(type) {
	case *atcrypto.PublicKeyP256, *atcrypto.PublicKeyK256:
		return key, nil
	default:
		return nil, fmt.Errorf("%w: %w", ErrKeyBinding, ErrUnsupportedSigningAlgorithm)
	}
}

func mstDepth(root *mst.Node) int {
	if root == nil {
		return 0
	}
	type nodeDepth struct {
		node  *mst.Node
		depth int
	}
	stack := []nodeDepth{{node: root, depth: 1}}
	maximum := 0
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current.depth > maximum {
			maximum = current.depth
		}
		for _, entry := range current.node.Entries {
			if entry.Child != nil {
				stack = append(stack, nodeDepth{node: entry.Child, depth: current.depth + 1})
			}
		}
	}
	return maximum
}

func verifiedMembership(ctx context.Context, loaded *repo.Repo, budgets Budgets) (map[RecordKey]string, map[RecordKey]ProvenRecord, error) {
	membership := make(map[RecordKey]string)
	records := make(map[RecordKey]ProvenRecord)
	err := loaded.MST.Walk(func(path []byte, recordCID cid.Cid) error {
		if len(membership)+1 > budgets.MaxMembershipRecords {
			return untrustedBound("MaxMembershipRecords", len(membership)+1)
		}
		collection, rkey, err := syntax.ParseRepoPath(string(path))
		if err != nil {
			return fmt.Errorf("%w: invalid MST record key", ErrUntrustedCar)
		}
		key := RecordKey{Collection: collection.String(), RKey: rkey.String()}
		if _, exists := membership[key]; exists {
			return fmt.Errorf("%w: duplicate MST key %s/%s", ErrUntrustedCar, key.Collection, key.RKey)
		}
		data, actualCID, err := loaded.GetRecordBytes(ctx, collection, rkey)
		if err != nil || actualCID == nil {
			return fmt.Errorf("%w: record bytes are missing", ErrUnprovenMembership)
		}
		if !actualCID.Equals(recordCID) {
			return fmt.Errorf("%w: MST membership CID differs from the loaded record CID", ErrUnprovenMembership)
		}
		recomputed, err := recordCID.Prefix().Sum(data)
		if err != nil || !recomputed.Equals(recordCID) {
			return fmt.Errorf("%w: record bytes do not hash to the MST membership CID", ErrUnprovenMembership)
		}
		membership[key] = recordCID.String()
		records[key] = ProvenRecord{CID: recordCID.String(), Data: append([]byte(nil), data...)}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrUnprovenMembership) || errors.Is(err, ErrUntrustedCar) {
			return nil, nil, err
		}
		if errors.Is(err, mst.ErrPartialTree) {
			return nil, nil, fmt.Errorf("%w: partial MST during traversal", ErrUnprovenMembership)
		}
		return nil, nil, fmt.Errorf("%w: MST membership traversal failed", ErrUntrustedCar)
	}
	return membership, records, nil
}
