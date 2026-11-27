package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/service"
)

const (
	publicationProposalFileVersion = 1
	publicationProposalFilePrefix  = "proposal-"
	publicationProposalFileSuffix  = ".json"
	publicationProposalFileLimit   = 2 * publication.MaxFileSetRecordBytes
)

var (
	errProposalRecordUnsafe    = errors.New("retained publication proposal is not an owned private regular file")
	errProposalRecordInvalid   = errors.New("retained publication proposal is unreadable or invalid")
	errProposalRecordDuplicate = errors.New("retained publication proposal already exists")
	errProposalRecordTooLarge  = errors.New("retained publication proposal exceeds the size bound")
)

type proposalBindingFile struct {
	AccountDID string `json:"account_did"`
	Backend    string `json:"backend"`
	Repository string `json:"repository"`
	Vault      string `json:"vault"`
}

type proposalRecordFile struct {
	Version            uint64              `json:"version"`
	Binding            proposalBindingFile `json:"binding"`
	DatabaseID         string              `json:"database_id"`
	Generation         uint64              `json:"generation"`
	FloorRevision      uint64              `json:"floor_revision"`
	CandidateRecordCID string              `json:"candidate_record_cid"`
	Form               string              `json:"form,omitempty"`
	Segments           string              `json:"segments"`
	PayloadsDigest     string              `json:"payloads_digest"`
	SelectionDigest    string              `json:"selection_digest"`
	SelectionRevision  uint64              `json:"selection_revision"`
	ApprovalDigest     string              `json:"approval_digest"`
	ApprovalRevision   uint64              `json:"approval_revision"`
	PublicationID      string              `json:"publication_id"`
	Lifecycle          string              `json:"lifecycle"`
	Consumed           bool                `json:"consumed"`
	Confirmation       string              `json:"confirmation"`
}

type publicationProposalStore struct {
	directory string
}

func newPublicationProposalStore(directory string) publicationProposalStore {
	return publicationProposalStore{directory: directory}
}

func encodeProposalRecord(record service.PublicationProposalRecord) ([]byte, error) {
	file := proposalRecordFile{
		Version: record.Version,
		Binding: proposalBindingFile{
			AccountDID: record.Binding.AccountDID, Backend: string(record.Binding.Backend),
			Repository: record.Binding.Repository, Vault: hex.EncodeToString(record.Binding.Vault[:]),
		},
		DatabaseID:         hex.EncodeToString(record.DatabaseID[:]),
		Generation:         record.Generation,
		FloorRevision:      record.FloorRevision,
		CandidateRecordCID: hex.EncodeToString(record.CandidateRecordCID),
		Form:               string(record.Form),
		Segments:           base64.StdEncoding.EncodeToString(record.Segments),
		PayloadsDigest:     hex.EncodeToString(record.PayloadsDigest[:]),
		SelectionDigest:    hex.EncodeToString(record.Review.SelectionDigest[:]),
		SelectionRevision:  record.Review.SelectionRevision,
		ApprovalDigest:     hex.EncodeToString(record.Review.ApprovalDigest[:]),
		ApprovalRevision:   record.Review.ApprovalRevision,
		PublicationID:      hex.EncodeToString(record.PublicationID[:]),
		Lifecycle:          string(record.Lifecycle),
		Consumed:           record.Consumed,
		Confirmation:       hex.EncodeToString(record.Confirmation[:]),
	}
	encoded, err := json.Marshal(file)
	if err != nil {
		return nil, errProposalRecordInvalid
	}
	return append(encoded, '\n'), nil
}

func encodeProposalFile(record service.PublicationProposalRecord) ([]byte, error) {
	encoded, err := encodeProposalRecord(record)
	if err != nil {
		return nil, err
	}
	if len(encoded) > publicationProposalFileLimit {
		return nil, errProposalRecordTooLarge
	}
	return encoded, nil
}

func decodeProposalRecord(encoded []byte) (service.PublicationProposalRecord, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var file proposalRecordFile
	if err := decoder.Decode(&file); err != nil {
		return service.PublicationProposalRecord{}, errProposalRecordInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return service.PublicationProposalRecord{}, errProposalRecordInvalid
	}
	vaultID, err := decodeFixedHex(file.Binding.Vault, 32)
	if err != nil {
		return service.PublicationProposalRecord{}, errProposalRecordInvalid
	}
	record := service.PublicationProposalRecord{
		Version: file.Version,
		Binding: publicationstate.Binding{
			AccountDID: file.Binding.AccountDID, Backend: publicationstate.Backend(file.Binding.Backend),
			Repository: file.Binding.Repository,
		},
		Generation:    file.Generation,
		FloorRevision: file.FloorRevision,
		Form:          publication.PayloadForm(file.Form),
		Review: publicationstate.LocalReviewContext{
			SelectionRevision: file.SelectionRevision, ApprovalRevision: file.ApprovalRevision,
		},
		Lifecycle: publicationstate.AttemptLifecycle(file.Lifecycle),
		Consumed:  file.Consumed,
	}
	copy(record.Binding.Vault[:], vaultID)
	for _, field := range []struct {
		encoded string
		length  int
		target  []byte
	}{
		{file.DatabaseID, 32, record.DatabaseID[:]},
		{file.PublicationID, 16, record.PublicationID[:]},
		{file.Confirmation, 32, record.Confirmation[:]},
		{file.SelectionDigest, 32, record.Review.SelectionDigest[:]},
		{file.ApprovalDigest, 32, record.Review.ApprovalDigest[:]},
	} {
		decoded, err := decodeFixedHex(field.encoded, field.length)
		if err != nil {
			return service.PublicationProposalRecord{}, errProposalRecordInvalid
		}
		copy(field.target, decoded)
	}
	if record.CandidateRecordCID, err = decodeHexField(file.CandidateRecordCID); err != nil {
		return service.PublicationProposalRecord{}, err
	}
	if record.Segments, err = decodeProposalSegments(file.Segments); err != nil {
		return service.PublicationProposalRecord{}, err
	}
	payloadsDigest, err := decodeFixedHex(file.PayloadsDigest, 32)
	if err != nil {
		return service.PublicationProposalRecord{}, errProposalRecordInvalid
	}
	copy(record.PayloadsDigest[:], payloadsDigest)
	if err := service.VerifyPublicationProposalRecord(record); err != nil {
		return service.PublicationProposalRecord{}, errProposalRecordInvalid
	}
	return record, nil
}

func decodeProposalSegments(value string) ([]byte, error) {
	for _, decode := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		hex.DecodeString,
	} {
		decoded, err := decode(value)
		if err != nil || len(decoded) == 0 {
			continue
		}
		if _, err := publicationstate.DecodeSegmentSummaries(decoded); err != nil {
			continue
		}
		return decoded, nil
	}
	return nil, errProposalRecordInvalid
}

func decodeHexField(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) == 0 {
		return nil, errProposalRecordInvalid
	}
	return decoded, nil
}

func proposalRecordName(publicationID [16]byte) string {
	return publicationProposalFilePrefix + hex.EncodeToString(publicationID[:]) + publicationProposalFileSuffix
}

func (store publicationProposalStore) path(publicationID [16]byte) string {
	return filepath.Join(store.directory, proposalRecordName(publicationID))
}

func (store publicationProposalStore) List(ctx context.Context) ([]service.PublicationProposalRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(store.directory)
	if err != nil {
		return nil, errProposalRecordInvalid
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), publicationProposalFilePrefix) &&
			strings.HasSuffix(entry.Name(), publicationProposalFileSuffix) {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	records := make([]service.PublicationProposalRecord, 0, len(names))
	for _, name := range names {
		record, err := store.read(filepath.Join(store.directory, name))
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (store publicationProposalStore) read(path string) (service.PublicationProposalRecord, error) {
	encoded, err := readProposalFile(path)
	if err != nil {
		return service.PublicationProposalRecord{}, err
	}
	defer clear(encoded)
	return decodeProposalRecord(encoded)
}

func readProposalFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 {
		return nil, errProposalRecordUnsafe
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errProposalRecordUnsafe
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) || info.Mode().Perm()&0o077 != 0 {
		return nil, errProposalRecordUnsafe
	}
	encoded, err := io.ReadAll(io.LimitReader(file, publicationProposalFileLimit+1))
	if err != nil || len(encoded) > publicationProposalFileLimit {
		clear(encoded)
		return nil, errProposalRecordInvalid
	}
	return encoded, nil
}

func (store publicationProposalStore) Issue(ctx context.Context, record service.PublicationProposalRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := service.VerifyPublicationProposalRecord(record); err != nil {
		return err
	}
	encoded, err := encodeProposalFile(record)
	if err != nil {
		return err
	}
	defer clear(encoded)
	file, err := os.OpenFile(store.path(record.PublicationID), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errProposalRecordDuplicate
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		_ = os.Remove(store.path(record.PublicationID))
		return errProposalRecordInvalid
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(store.path(record.PublicationID))
		return errProposalRecordInvalid
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(store.path(record.PublicationID))
		return errProposalRecordInvalid
	}
	return nil
}

func (store publicationProposalStore) Consume(ctx context.Context, publicationID [16]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	record, err := store.read(store.path(publicationID))
	if err != nil {
		return err
	}
	if record.Consumed {
		return nil
	}
	record.Consumed = true
	encoded, err := encodeProposalFile(record)
	if err != nil {
		return err
	}
	defer clear(encoded)
	path := store.path(publicationID)
	temporary, err := os.CreateTemp(store.directory, ".dottie-proposal-*")
	if err != nil {
		return errProposalRecordInvalid
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return errProposalRecordInvalid
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return errProposalRecordInvalid
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errProposalRecordInvalid
	}
	if err := temporary.Close(); err != nil {
		return errProposalRecordInvalid
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return errProposalRecordInvalid
	}
	return nil
}

func (store publicationProposalStore) Delete(ctx context.Context, publicationID [16]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Remove(store.path(publicationID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errProposalRecordInvalid
	}
	return nil
}
