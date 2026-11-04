package atprototest

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/repo/mst"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/ipfs/go-cid"
	"github.com/ipld/go-car"
	"github.com/multiformats/go-multihash"
)

const RepositoryRevision = "2222222222222"

type Record struct {
	Collection string
	RKey       string
	Data       []byte
}

type Blob struct {
	Reference atdata.Blob
	CID       cid.Cid
	Data      []byte
}

type VerificationMethod struct {
	ID                 string
	Type               string
	Controller         string
	PublicKeyMultibase string
}

type SignedRevision struct {
	DID                string
	CAR                []byte
	CommitCID          cid.Cid
	VerificationMethod VerificationMethod
	Records            []Record
}

type block struct {
	cid  cid.Cid
	data []byte
}

func NewSigningKey() (*atcrypto.PrivateKeyP256, error) {
	return atcrypto.GeneratePrivateKeyP256()
}

type deterministicSigningKey struct {
	key *atcrypto.PrivateKeyP256
}

func (key deterministicSigningKey) Equal(other atcrypto.PrivateKey) bool {
	switch candidate := other.(type) {
	case deterministicSigningKey:
		return key.key.Equal(candidate.key)
	case *atcrypto.PrivateKeyP256:
		return key.key.Equal(candidate)
	default:
		return false
	}
}

func (key deterministicSigningKey) PublicKey() (atcrypto.PublicKey, error) {
	return key.key.PublicKey()
}

func (key deterministicSigningKey) HashAndSign(content []byte) ([]byte, error) {
	if key.key == nil {
		return nil, errors.New("repository signing key is required")
	}
	curve := elliptic.P256()
	order := curve.Params().N
	privateScalar := new(big.Int).SetBytes(key.key.Bytes())
	if privateScalar.Sign() <= 0 || privateScalar.Cmp(order) >= 0 {
		return nil, errors.New("repository signing key is invalid")
	}
	digest := sha256.Sum256(content)
	nonce := deterministicNonce(key.key.Bytes(), digest[:], order)
	x, _ := curve.ScalarBaseMult(nonce.Bytes())
	r := new(big.Int).Mod(x, order)
	if r.Sign() == 0 {
		return nil, errors.New("could not derive repository signature")
	}
	inverse := new(big.Int).ModInverse(nonce, order)
	if inverse == nil {
		return nil, errors.New("could not derive repository signature")
	}
	s := new(big.Int).Mul(r, privateScalar)
	s.Add(s, new(big.Int).SetBytes(digest[:]))
	s.Mul(s, inverse)
	s.Mod(s, order)
	if s.Sign() == 0 {
		return nil, errors.New("could not derive repository signature")
	}
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(order), 1)
	if s.Cmp(halfOrder) > 0 {
		s.Sub(order, s)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature, nil
}

func deterministicNonce(secret, digest []byte, order *big.Int) *big.Int {
	privateBytes := make([]byte, 32)
	new(big.Int).SetBytes(secret).FillBytes(privateBytes)
	hashValue := new(big.Int).SetBytes(digest)
	hashValue.Mod(hashValue, order)
	hashBytes := make([]byte, 32)
	hashValue.FillBytes(hashBytes)
	key := make([]byte, sha256.Size)
	value := bytes.Repeat([]byte{1}, sha256.Size)
	key = hmacSHA256(key, value, []byte{0}, privateBytes, hashBytes)
	value = hmacSHA256(key, value)
	key = hmacSHA256(key, value, []byte{1}, privateBytes, hashBytes)
	value = hmacSHA256(key, value)
	for {
		value = hmacSHA256(key, value)
		candidate := new(big.Int).SetBytes(value)
		if candidate.Sign() > 0 && candidate.Cmp(order) < 0 {
			return candidate
		}
		key = hmacSHA256(key, value, []byte{0})
		value = hmacSHA256(key, value)
	}
}

func hmacSHA256(key []byte, values ...[]byte) []byte {
	mac := hmac.New(sha256.New, key)
	for _, value := range values {
		_, _ = mac.Write(value)
	}
	return mac.Sum(nil)
}

func BuildRecord(collection, rkey string, fields map[string]any) (Record, error) {
	parsedCollection, err := syntax.ParseNSID(collection)
	if err != nil || parsedCollection.String() != collection {
		return Record{}, errors.New("invalid record collection")
	}
	parsedRKey, err := syntax.ParseRecordKey(rkey)
	if err != nil || parsedRKey.String() != rkey {
		return Record{}, errors.New("invalid record key")
	}
	if fields == nil {
		return Record{}, errors.New("record fields are required")
	}
	value := make(map[string]any, len(fields)+1)
	for key, field := range fields {
		if key == "$type" {
			name, ok := field.(string)
			if !ok || name != collection {
				return Record{}, errors.New("record type must match its collection")
			}
		}
		value[key] = field
	}
	if _, ok := value["$type"]; !ok {
		value["$type"] = collection
	}
	encoded, err := atdata.MarshalCBOR(value)
	if err != nil {
		return Record{}, fmt.Errorf("encode DAG-CBOR record: %w", err)
	}
	return Record{Collection: collection, RKey: rkey, Data: encoded}, nil
}

func BuildBlob(data []byte) (Blob, error) {
	prefix := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256)
	identifier, err := prefix.Sum(data)
	if err != nil {
		return Blob{}, fmt.Errorf("build raw blob CID: %w", err)
	}
	return Blob{
		Reference: atdata.Blob{Ref: atdata.CIDLink(identifier), MimeType: "application/octet-stream", Size: int64(len(data))},
		CID:       identifier,
		Data:      bytes.Clone(data),
	}, nil
}

func BuildSignedRevision(did string, signingKey *atcrypto.PrivateKeyP256, records []Record) (SignedRevision, error) {
	parsedDID, err := syntax.ParseDID(did)
	if err != nil || parsedDID.String() != did || signingKey == nil {
		return SignedRevision{}, errors.New("valid DID and repository signing key are required")
	}
	ordered := make([]Record, len(records))
	for index := range records {
		ordered[index] = Record{Collection: records[index].Collection, RKey: records[index].RKey, Data: bytes.Clone(records[index].Data)}
	}
	sort.Slice(ordered, func(i, j int) bool {
		left := ordered[i].Collection + "/" + ordered[i].RKey
		right := ordered[j].Collection + "/" + ordered[j].RKey
		return left < right
	})
	tree := mst.NewEmptyTree()
	blocks := make([]block, 0, len(ordered)+16)
	seenRecords := make(map[string]struct{}, len(ordered))
	seenBlocks := make(map[string][]byte, len(ordered)+16)
	for _, record := range ordered {
		collection, parseErr := syntax.ParseNSID(record.Collection)
		if parseErr != nil || collection.String() != record.Collection {
			return SignedRevision{}, errors.New("invalid repository record collection")
		}
		rkey, parseErr := syntax.ParseRecordKey(record.RKey)
		if parseErr != nil || rkey.String() != record.RKey || len(record.Data) == 0 {
			return SignedRevision{}, errors.New("invalid repository record")
		}
		key := record.Collection + "/" + record.RKey
		if _, duplicate := seenRecords[key]; duplicate {
			return SignedRevision{}, errors.New("duplicate repository record key")
		}
		seenRecords[key] = struct{}{}
		object, err := atdata.UnmarshalCBOR(record.Data)
		if err != nil || object["$type"] != record.Collection {
			return SignedRevision{}, errors.New("repository record bytes do not match their collection")
		}
		recordCID, err := dagCBORCID(record.Data)
		if err != nil {
			return SignedRevision{}, err
		}
		if _, err := tree.Insert([]byte(key), recordCID); err != nil {
			return SignedRevision{}, fmt.Errorf("insert repository record: %w", err)
		}
		if err := addBlock(&blocks, seenBlocks, recordCID, record.Data); err != nil {
			return SignedRevision{}, err
		}
	}
	rootCID, err := storeMST(tree.Root, &blocks, seenBlocks)
	if err != nil {
		return SignedRevision{}, err
	}
	commit := &repo.Commit{DID: did, Version: repo.ATPROTO_REPO_VERSION, Data: rootCID, Rev: RepositoryRevision}
	if err := commit.Sign(deterministicSigningKey{key: signingKey}); err != nil {
		return SignedRevision{}, fmt.Errorf("sign repository commit: %w", err)
	}
	var commitBytes bytes.Buffer
	if err := commit.MarshalCBOR(&commitBytes); err != nil {
		return SignedRevision{}, fmt.Errorf("encode repository commit: %w", err)
	}
	commitCID, err := dagCBORCID(commitBytes.Bytes())
	if err != nil {
		return SignedRevision{}, err
	}
	if err := addBlock(&blocks, seenBlocks, commitCID, commitBytes.Bytes()); err != nil {
		return SignedRevision{}, err
	}
	carBytes, err := encodeCAR(commitCID, blocks)
	if err != nil {
		return SignedRevision{}, err
	}
	publicKey, err := signingKey.PublicKey()
	if err != nil {
		return SignedRevision{}, fmt.Errorf("derive repository verification key: %w", err)
	}
	return SignedRevision{
		DID: did, CAR: carBytes, CommitCID: commitCID,
		VerificationMethod: VerificationMethod{
			ID: did + "#atproto", Type: "Multikey", Controller: did, PublicKeyMultibase: publicKey.Multibase(),
		},
		Records: ordered,
	}, nil
}

func dagCBORCID(data []byte) (cid.Cid, error) {
	prefix := cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256)
	identifier, err := prefix.Sum(data)
	if err != nil {
		return cid.Undef, fmt.Errorf("compute DAG-CBOR CID: %w", err)
	}
	return identifier, nil
}

func storeMST(node *mst.Node, blocks *[]block, seen map[string][]byte) (cid.Cid, error) {
	for index := range node.Entries {
		if node.Entries[index].Child == nil {
			continue
		}
		childCID, err := storeMST(node.Entries[index].Child, blocks, seen)
		if err != nil {
			return cid.Undef, err
		}
		node.Entries[index].ChildCID = &childCID
	}
	nodeData := node.NodeData()
	encoded, identifier, err := nodeData.Bytes()
	if err != nil {
		return cid.Undef, fmt.Errorf("encode MST node: %w", err)
	}
	if identifier == nil {
		return cid.Undef, errors.New("MST node has no CID")
	}
	node.CID = identifier
	node.Dirty = false
	if err := addBlock(blocks, seen, *identifier, encoded); err != nil {
		return cid.Undef, err
	}
	return *identifier, nil
}

func addBlock(blocks *[]block, seen map[string][]byte, identifier cid.Cid, data []byte) error {
	key := identifier.KeyString()
	if previous, exists := seen[key]; exists {
		if !bytes.Equal(previous, data) {
			return errors.New("repository block CID collision")
		}
		return nil
	}
	seen[key] = bytes.Clone(data)
	*blocks = append(*blocks, block{cid: identifier, data: bytes.Clone(data)})
	return nil
}

func encodeCAR(root cid.Cid, blocks []block) ([]byte, error) {
	var output bytes.Buffer
	if err := car.WriteHeader(&car.CarHeader{Roots: []cid.Cid{root}, Version: 1}, &output); err != nil {
		return nil, fmt.Errorf("encode CAR header: %w", err)
	}
	for _, item := range blocks {
		sectionLength := len(item.cid.Bytes()) + len(item.data)
		var length [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(length[:], uint64(sectionLength))
		output.Write(length[:n])
		output.Write(item.cid.Bytes())
		output.Write(item.data)
	}
	return output.Bytes(), nil
}
