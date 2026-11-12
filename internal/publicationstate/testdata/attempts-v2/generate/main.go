package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/vault"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

const (
	imageName                 = "pending-genesis"
	rowsName                  = "pending-genesis-rows.json"
	inputsName                = "pending-genesis-inputs.json"
	mixedImageName            = "mixed"
	mixedRowsName             = "mixed-rows.json"
	mixedInputsName           = "mixed-inputs.json"
	manifestName              = "manifest.json"
	manifestPendingName       = "manifest.pending"
	baselineCommit            = "f5387d6a5fd3a9f6902e6fa8cea271aec24fba26"
	baselineArchiveSHA256     = "c1fb2a175051fcc899149549ce15e1e35eaa59cd62d1ded2d46a0f71b4e8d4be"
	storageProfile            = "systems.lamb.dottie.vaultSnapshotV2+systems.lamb.dottie.vaultHeadV2;schemaVersion=2"
	baselinePinnedSourceFiles = 466
	maxTableRows              = int64(10000)
	maxCellBytes              = 16 << 20
	maxJSONBytes              = 32 << 20
	maxOutputBytes            = int64(64 << 20)
	sqliteApplicationID       = int64(0x44545032)
	payloadDirectoryName      = "payloads"
	payloadFileSuffix         = ".payload"
)

type columnSpec struct {
	Name string `json:"name"`
	Type string `json:"declaredType"`
}

type tableSpec struct {
	Name    string
	DDL     string
	Columns []columnSpec
	OrderBy string
}

type schemaObjectSpec struct {
	Name string
	Kind string
	SQL  string
}

var tableSpecs = []tableSpec{
	{Name: "store_meta", DDL: "CREATE TABLE store_meta (key TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL)", Columns: []columnSpec{{"key", "TEXT"}, {"value", "BLOB"}}, OrderBy: "key"},
	{Name: "cache_records", DDL: "CREATE TABLE cache_records (cid BLOB PRIMARY KEY NOT NULL, record_key TEXT NOT NULL, sequence INTEGER NOT NULL, raw BLOB NOT NULL, logical_bytes INTEGER NOT NULL)", Columns: []columnSpec{{"cid", "BLOB"}, {"record_key", "TEXT"}, {"sequence", "INTEGER"}, {"raw", "BLOB"}, {"logical_bytes", "INTEGER"}}, OrderBy: "cid"},
	{Name: "cache_observations", DDL: "CREATE TABLE cache_observations (observation_id BLOB PRIMARY KEY NOT NULL, metadata BLOB NOT NULL, logical_bytes INTEGER NOT NULL)", Columns: []columnSpec{{"observation_id", "BLOB"}, {"metadata", "BLOB"}, {"logical_bytes", "INTEGER"}}, OrderBy: "observation_id"},
	{Name: "accepted_records", DDL: "CREATE TABLE accepted_records (cid BLOB PRIMARY KEY NOT NULL, record_key TEXT NOT NULL, sequence INTEGER NOT NULL, raw BLOB NOT NULL, logical_bytes INTEGER NOT NULL)", Columns: []columnSpec{{"cid", "BLOB"}, {"record_key", "TEXT"}, {"sequence", "INTEGER"}, {"raw", "BLOB"}, {"logical_bytes", "INTEGER"}}, OrderBy: "cid"},
	{Name: "accepted_events", DDL: "CREATE TABLE accepted_events (revision INTEGER PRIMARY KEY NOT NULL, mode TEXT NOT NULL, reason TEXT NOT NULL, stop TEXT NOT NULL, old_floor BLOB, new_floor BLOB NOT NULL, body BLOB NOT NULL, digest BLOB NOT NULL, logical_bytes INTEGER NOT NULL)", Columns: []columnSpec{{"revision", "INTEGER"}, {"mode", "TEXT"}, {"reason", "TEXT"}, {"stop", "TEXT"}, {"old_floor", "BLOB"}, {"new_floor", "BLOB"}, {"body", "BLOB"}, {"digest", "BLOB"}, {"logical_bytes", "INTEGER"}}, OrderBy: "revision"},
	{Name: "active_floor", DDL: "CREATE TABLE active_floor (singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1), floor BLOB NOT NULL)", Columns: []columnSpec{{"singleton", "INTEGER"}, {"floor", "BLOB"}}, OrderBy: "singleton"},
	{Name: "publication_attempts", DDL: "CREATE TABLE publication_attempts (attempt_id BLOB PRIMARY KEY NOT NULL, core BLOB NOT NULL, lifecycle TEXT NOT NULL, outcome TEXT NOT NULL, blocked TEXT NOT NULL, state_digest BLOB NOT NULL, mutation_revision INTEGER NOT NULL, created_order INTEGER NOT NULL, logical_bytes INTEGER NOT NULL, terminal_evidence BLOB, retirement_evidence BLOB)", Columns: []columnSpec{{"attempt_id", "BLOB"}, {"core", "BLOB"}, {"lifecycle", "TEXT"}, {"outcome", "TEXT"}, {"blocked", "TEXT"}, {"state_digest", "BLOB"}, {"mutation_revision", "INTEGER"}, {"created_order", "INTEGER"}, {"logical_bytes", "INTEGER"}, {"terminal_evidence", "BLOB"}, {"retirement_evidence", "BLOB"}}, OrderBy: "created_order,attempt_id"},
	{Name: "active_publication_attempt", DDL: "CREATE TABLE active_publication_attempt (singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1), attempt_id BLOB NOT NULL REFERENCES publication_attempts(attempt_id))", Columns: []columnSpec{{"singleton", "INTEGER"}, {"attempt_id", "BLOB"}}, OrderBy: "singleton"},
	{Name: "pending_genesis", DDL: "CREATE TABLE pending_genesis (singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1), attempt_id BLOB NOT NULL UNIQUE REFERENCES publication_attempts(attempt_id), vault BLOB NOT NULL)", Columns: []columnSpec{{"singleton", "INTEGER"}, {"attempt_id", "BLOB"}, {"vault", "BLOB"}}, OrderBy: "singleton"},
	{Name: "attempt_events", DDL: "CREATE TABLE attempt_events (attempt_id BLOB NOT NULL REFERENCES publication_attempts(attempt_id), ordinal INTEGER NOT NULL, kind TEXT NOT NULL, body BLOB NOT NULL, digest BLOB NOT NULL, PRIMARY KEY(attempt_id, ordinal))", Columns: []columnSpec{{"attempt_id", "BLOB"}, {"ordinal", "INTEGER"}, {"kind", "TEXT"}, {"body", "BLOB"}, {"digest", "BLOB"}}, OrderBy: "attempt_id,ordinal"},
	{Name: "attempt_evidence", DDL: "CREATE TABLE attempt_evidence (attempt_id BLOB NOT NULL REFERENCES publication_attempts(attempt_id), role TEXT NOT NULL, body BLOB NOT NULL, digest BLOB NOT NULL, PRIMARY KEY(attempt_id, role))", Columns: []columnSpec{{"attempt_id", "BLOB"}, {"role", "TEXT"}, {"body", "BLOB"}, {"digest", "BLOB"}}, OrderBy: "attempt_id,role"},
	{Name: "payload_objects", DDL: "CREATE TABLE payload_objects (blob_cid BLOB PRIMARY KEY NOT NULL, size INTEGER NOT NULL, basename TEXT NOT NULL UNIQUE, logical_bytes INTEGER NOT NULL)", Columns: []columnSpec{{"blob_cid", "BLOB"}, {"size", "INTEGER"}, {"basename", "TEXT"}, {"logical_bytes", "INTEGER"}}, OrderBy: "blob_cid"},
	{Name: "attempt_payload_refs", DDL: "CREATE TABLE attempt_payload_refs (attempt_id BLOB PRIMARY KEY NOT NULL REFERENCES publication_attempts(attempt_id), blob_cid BLOB NOT NULL REFERENCES payload_objects(blob_cid))", Columns: []columnSpec{{"attempt_id", "BLOB"}, {"blob_cid", "BLOB"}}, OrderBy: "attempt_id"},
	{Name: "retained_publications", DDL: "CREATE TABLE retained_publications (record_cid BLOB PRIMARY KEY NOT NULL, attempt_id BLOB NOT NULL UNIQUE REFERENCES publication_attempts(attempt_id), sequence INTEGER NOT NULL, blob_cid BLOB NOT NULL REFERENCES payload_objects(blob_cid), size INTEGER NOT NULL, accepted_revision INTEGER NOT NULL)", Columns: []columnSpec{{"record_cid", "BLOB"}, {"attempt_id", "BLOB"}, {"sequence", "INTEGER"}, {"blob_cid", "BLOB"}, {"size", "INTEGER"}, {"accepted_revision", "INTEGER"}}, OrderBy: "record_cid"},
	{Name: "attempt_reservations", DDL: "CREATE TABLE attempt_reservations (attempt_id BLOB PRIMARY KEY NOT NULL REFERENCES publication_attempts(attempt_id), metadata_bytes INTEGER NOT NULL, accepted_bytes INTEGER NOT NULL, accepted_records INTEGER NOT NULL, accepted_events INTEGER NOT NULL, retained_points INTEGER NOT NULL)", Columns: []columnSpec{{"attempt_id", "BLOB"}, {"metadata_bytes", "INTEGER"}, {"accepted_bytes", "INTEGER"}, {"accepted_records", "INTEGER"}, {"accepted_events", "INTEGER"}, {"retained_points", "INTEGER"}}, OrderBy: "attempt_id"},
}

var indexSpecs = []schemaObjectSpec{
	{Name: "publication_attempts_order", Kind: "index", SQL: "CREATE INDEX publication_attempts_order ON publication_attempts(created_order, attempt_id)"},
	{Name: "payload_objects_basename", Kind: "index", SQL: "CREATE INDEX payload_objects_basename ON payload_objects(basename)"},
}

type rawCell struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type rawTable struct {
	Name     string       `json:"name"`
	DDL      string       `json:"ddl"`
	Columns  []columnSpec `json:"columns"`
	RowCount int64        `json:"rowCount"`
	Rows     [][]rawCell  `json:"rows"`
}

type schemaObject struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	SQL  string `json:"sql"`
}

type rowInventory struct {
	FormatVersion int            `json:"formatVersion"`
	Coverage      string         `json:"coverage"`
	ApplicationID int64          `json:"applicationId"`
	UserVersion   int64          `json:"userVersion"`
	MetadataKeys  []string       `json:"metadataKeys"`
	SchemaObjects []schemaObject `json:"schemaObjects"`
	Tables        []rawTable     `json:"tables"`
}

type byteValue struct {
	Length int    `json:"length"`
	Base64 string `json:"base64"`
	SHA256 string `json:"sha256"`
}

type bindingValue struct {
	AccountDID string    `json:"accountDID"`
	Backend    string    `json:"backend"`
	Repository string    `json:"repository"`
	Vault      byteValue `json:"vault"`
}

type policyValue struct {
	Revision  string    `json:"revision"`
	Identity  byteValue `json:"identity"`
	OwnerOnly bool      `json:"ownerOnly"`
}

type contextValue struct {
	RepositoryRevision string       `json:"repositoryRevision"`
	RepositoryDigest   byteValue    `json:"repositoryDigest"`
	Policy             *policyValue `json:"policy"`
}

type reviewValue struct {
	SelectionDigest   string `json:"selectionDigest"`
	SelectionRevision uint64 `json:"selectionRevision"`
	ApprovalDigest    string `json:"approvalDigest"`
	ApprovalRevision  uint64 `json:"approvalRevision"`
}

type inputOptions struct {
	PositionLimits       publicationstate.Limits        `json:"positionLimits"`
	AttemptLimits        publicationstate.AttemptLimits `json:"attemptLimits"`
	UpgradeFromPositions bool                           `json:"upgradeFromPositions"`
}

type snapshotValue struct {
	Key string    `json:"key"`
	Raw byteValue `json:"raw"`
}

type candidateValue struct {
	AttemptID      string    `json:"attemptID"`
	PublicationID  string    `json:"publicationID"`
	SnapshotKey    string    `json:"snapshotKey"`
	SnapshotCID    byteValue `json:"snapshotCID"`
	HeadCID        byteValue `json:"headCID"`
	BlobCID        byteValue `json:"blobCID"`
	BlobSize       uint64    `json:"blobSize"`
	SnapshotRecord byteValue `json:"snapshotRecord"`
	HeadRecord     byteValue `json:"headRecord"`
	Payload        byteValue `json:"payload"`
}

type emptyViewValue struct {
	Origin          bindingValue    `json:"origin"`
	Scope           string          `json:"scope"`
	SuppliedContext contextValue    `json:"suppliedContext"`
	Head            byteValue       `json:"head"`
	Snapshots       []snapshotValue `json:"snapshots"`
}

type replayInputs struct {
	FormatVersion int            `json:"formatVersion"`
	Coverage      string         `json:"coverage"`
	Binding       bindingValue   `json:"binding"`
	Options       inputOptions   `json:"options"`
	Candidate     candidateValue `json:"candidate"`
	EmptyView     emptyViewValue `json:"emptySuppliedView"`
	Review        reviewValue    `json:"localReview"`
	APISequence   []string       `json:"apiSequence"`
}

type fileEntry struct {
	Path   string `json:"path"`
	Role   string `json:"role"`
	Length int64  `json:"length"`
	SHA256 string `json:"sha256"`
}

type imageManifest struct {
	Name                    string               `json:"name"`
	SchemaVersion           int64                `json:"schemaVersion"`
	ApplicationID           int64                `json:"applicationId"`
	DatabaseID              string               `json:"databaseID"`
	Binding                 bindingValue         `json:"binding"`
	Options                 inputOptions         `json:"options"`
	Revision                uint64               `json:"revision"`
	Generation              uint64               `json:"generation"`
	AttemptMutationRevision uint64               `json:"attemptMutationRevision"`
	AcceptedFloor           bool                 `json:"acceptedFloorPresent"`
	Floor                   *mixedReplayFloor    `json:"floor"`
	AcceptedEvents          int64                `json:"acceptedEventCount"`
	ActiveAttemptID         string               `json:"activeAttemptID"`
	PendingGenesisAttemptID string               `json:"pendingGenesisAttemptID"`
	Attempts                []mixedReplayAttempt `json:"attempts"`
	Tables                  []tableCount         `json:"tables"`
	Payloads                []payloadManifest    `json:"payloads"`
	CacheObservationID      *byteValue           `json:"cacheObservationID"`
	RowsArtifact            string               `json:"rowsArtifact"`
	InputsArtifact          string               `json:"inputsArtifact"`
}

type outputArtifact struct {
	Name string
	Role string
	Data []byte
}

type payloadManifest struct {
	Role             string    `json:"role"`
	Path             string    `json:"path"`
	AttemptID        string    `json:"attemptID"`
	RecordCID        byteValue `json:"recordCID"`
	BlobCID          byteValue `json:"blobCID"`
	Length           uint64    `json:"length"`
	SHA256           string    `json:"sha256"`
	Owner            string    `json:"owner"`
	AcceptedRevision *uint64   `json:"acceptedRevision"`
}

type tableCount struct {
	Name     string `json:"name"`
	RowCount int64  `json:"rowCount"`
}

type manifest struct {
	FormatVersion int             `json:"formatVersion"`
	Coverage      string          `json:"coverage"`
	Baseline      baselineValue   `json:"baseline"`
	Images        []imageManifest `json:"images"`
	Files         []fileEntry     `json:"files"`
}

type baselineValue struct {
	ExpectedCommit        string `json:"expectedCommit"`
	PinnedSourceFiles     int    `json:"pinnedSourceFiles"`
	SourceArchiveSHA256   string `json:"sourceArchiveSHA256"`
	ProvenanceDisposition string `json:"provenanceDisposition"`
}

func main() {
	args := os.Args[1:]
	for _, arg := range args {
		if arg == "--image" || strings.HasPrefix(arg, "--image=") {
			printFailure(errors.New("image selection is unsupported"))
			os.Exit(2)
		}
	}
	if len(args) != 1 {
		printFailure(errors.New("one explicit output root is required"))
		os.Exit(2)
	}
	if err := run(args[0]); err != nil {
		printFailure(err)
		os.Exit(1)
	}
}

func printFailure(err error) {
	_, _ = io.WriteString(os.Stderr, "generator: "+err.Error()+"\n")
}

func run(outputRoot string) (resultErr error) {
	root, rootFD, parentFD, _, err := createOutputRoot(outputRoot)
	if err != nil {
		return err
	}
	publicationSucceeded := false
	var ownedStore *publicationstate.Store
	storeOwned := false
	defer func() {
		if storeOwned && ownedStore != nil {
			storeOwned = false
			store := ownedStore
			ownedStore = nil
			if store.Close() != nil {
				closeErr := errors.New("publication store cleanup close failed")
				if resultErr == nil {
					resultErr = closeErr
				} else {
					resultErr = errors.Join(resultErr, closeErr)
				}
			}
		}
		if closeErr := unix.Close(rootFD); closeErr != nil && !publicationSucceeded {
			rootCloseErr := errors.New("output root cleanup close failed")
			if resultErr == nil {
				resultErr = rootCloseErr
			} else {
				resultErr = errors.Join(resultErr, rootCloseErr)
			}
		}
	}()
	consumedParentFD := parentFD
	parentFD = -1
	if closeErr := unix.Close(consumedParentFD); closeErr != nil {
		return errors.New("output parent close failed")
	}
	closeStore := func() error {
		if !storeOwned || ownedStore == nil {
			return errors.New("publication store ownership is unavailable")
		}
		storeOwned = false
		store := ownedStore
		ownedStore = nil
		if store.Close() != nil {
			return errors.New("publication store close failed")
		}
		return nil
	}
	ctx := context.Background()

	if err := createPrivateChild(rootFD, imageName); err != nil {
		return err
	}
	pendingDirectory := filepath.Join(root, imageName)
	binding, pendingContext, pendingCandidate, pendingInput, pendingView, pendingReview, options, err := syntheticGenesis()
	if err != nil {
		return err
	}
	if err := validateCandidate(pendingInput, binding, pendingCandidate); err != nil {
		return err
	}
	pendingStore, err := publicationstate.OpenWithOptions(pendingDirectory, binding, options)
	if err != nil {
		return errors.New("could not open fresh pending publication store")
	}
	ownedStore = pendingStore
	storeOwned = true
	initialFloor, present, err := pendingStore.Load(ctx)
	if err != nil || present || !isZeroFloor(initialFloor) {
		return errors.New("fresh pending store did not begin without a floor")
	}
	attemptProposal, err := pendingStore.PrepareAttempt(ctx, pendingInput, pendingView, pendingReview)
	if err != nil || attemptProposal.Kind != publicationstate.AttemptGenesis || hex.EncodeToString(attemptProposal.AttemptID[:]) != pendingCandidate.PublicationID {
		return errors.New("genesis attempt preparation failed")
	}
	created, err := pendingStore.CreateAttempt(ctx, attemptProposal.StateToken, pendingInput, pendingView, pendingReview, attemptProposal.Confirmation)
	if err != nil || created.ID != attemptProposal.AttemptID || created.Kind != publicationstate.AttemptGenesis || created.Lifecycle != publicationstate.AttemptPrepared || created.Outcome != publicationstate.OutcomeNotSubmitted || created.Blocked != "" || created.Sequence != 0 || !bytes.Equal(created.SnapshotRecordCID, mustDecodeBytes(pendingCandidate.SnapshotCID)) || !bytes.Equal(created.HeadRecordCID, mustDecodeBytes(pendingCandidate.HeadCID)) || !bytes.Equal(created.BlobCID, mustDecodeBytes(pendingCandidate.BlobCID)) || created.BlobSize != uint64(len(pendingInput.Payload)) || created.CapturedFloor != nil || created.CapturedRevision != 0 || created.CapturedGeneration != 0 {
		return errors.New("genesis attempt creation did not return the expected prepared state")
	}
	if allZero(created.StateDigest[:]) {
		return errors.New("prepared attempt has an empty state digest")
	}
	pendingCandidate.AttemptID = hex.EncodeToString(created.ID[:])
	floor, present, err := pendingStore.Load(ctx)
	if err != nil || present || !isZeroFloor(floor) {
		return errors.New("pending genesis unexpectedly accepted a position")
	}
	positionHistory, err := pendingStore.History(ctx, 0, 10)
	if err != nil || len(positionHistory.Events) != 0 || len(positionHistory.Records) != 0 || positionHistory.HasMore {
		return errors.New("pending genesis has accepted position history")
	}
	active, activePresent, err := pendingStore.ActiveAttempt(ctx)
	if err != nil || !activePresent || active.ID != created.ID || active.Kind != publicationstate.AttemptGenesis || active.Lifecycle != publicationstate.AttemptPrepared || active.Outcome != publicationstate.OutcomeNotSubmitted || active.Blocked != "" {
		return errors.New("prepared genesis is not the active attempt")
	}
	loaded, err := pendingStore.LoadAttempt(ctx, created.ID)
	if err != nil || loaded.ID != created.ID || loaded.Kind != created.Kind || loaded.Lifecycle != publicationstate.AttemptPrepared || loaded.Outcome != publicationstate.OutcomeNotSubmitted || loaded.Blocked != "" || loaded.Sequence != created.Sequence || loaded.SnapshotKey != created.SnapshotKey || !bytes.Equal(loaded.SnapshotRecordCID, created.SnapshotRecordCID) || !bytes.Equal(loaded.HeadRecordCID, created.HeadRecordCID) || !bytes.Equal(loaded.BlobCID, created.BlobCID) || loaded.BlobSize != created.BlobSize || !bytes.Equal(loaded.StateDigest[:], created.StateDigest[:]) {
		return errors.New("prepared genesis readback differs")
	}
	attemptPage, err := pendingStore.AttemptHistory(ctx, [16]byte{}, 10)
	if err != nil || len(attemptPage.Attempts) != 1 || attemptPage.Attempts[0].ID != created.ID || attemptPage.Attempts[0].Kind != created.Kind || attemptPage.Attempts[0].Lifecycle != publicationstate.AttemptPrepared || attemptPage.Attempts[0].Outcome != publicationstate.OutcomeNotSubmitted || attemptPage.Attempts[0].Blocked != "" || attemptPage.Attempts[0].Sequence != created.Sequence || attemptPage.Attempts[0].SnapshotKey != created.SnapshotKey || !bytes.Equal(attemptPage.Attempts[0].SnapshotRecordCID, created.SnapshotRecordCID) || !bytes.Equal(attemptPage.Attempts[0].HeadRecordCID, created.HeadRecordCID) || !bytes.Equal(attemptPage.Attempts[0].BlobCID, created.BlobCID) || attemptPage.Attempts[0].BlobSize != created.BlobSize || attemptPage.Attempts[0].StateDigest != created.StateDigest || attemptPage.Attempts[0].Availability != publicationstate.AvailabilityUnchecked || len(attemptPage.Evidence) != 0 || attemptPage.HasMore {
		return errors.New("prepared genesis attempt history differs")
	}
	material, err := pendingStore.ReadCandidate(ctx, created.ID)
	if err != nil || material.AttemptID != created.ID || material.SnapshotKey != pendingCandidate.SnapshotKey || !bytes.Equal(material.SnapshotRecord, pendingInput.SnapshotRecord) || !bytes.Equal(material.HeadRecord, pendingInput.HeadRecord) || !bytes.Equal(material.Payload, pendingInput.Payload) || !bytes.Equal(material.Blob.CID, mustDecodeBytes(pendingCandidate.BlobCID)) || material.Blob.Size != uint64(len(pendingInput.Payload)) {
		return errors.New("prepared genesis candidate readback differs")
	}
	physicalPayloadName := payloadBasename(pendingInput.Payload)
	if err := closeStore(); err != nil {
		return err
	}
	pendingInventory, err := inspectDatabase(filepath.Join(pendingDirectory, "publication.db"))
	if err != nil {
		return err
	}
	pendingInventory.Coverage = "pending-genesis-only"
	if err := validatePendingRows(pendingInventory, binding, created.ID, created.StateDigest, pendingCandidate, pendingInput.Payload, physicalPayloadName); err != nil {
		return err
	}
	if pendingInputSize := uint64(len(pendingInput.Payload)); pendingInputSize == 0 || pendingInputSize > uint64(maxOutputBytes) {
		return errors.New("pending payload exceeds the caller-side physical bound")
	}
	pendingPayloadDirectory := filepath.Join(pendingDirectory, payloadDirectoryName)
	pendingPayloadPath := filepath.Join(pendingPayloadDirectory, physicalPayloadName)
	if verifyPrivateDirectory(pendingPayloadDirectory) != nil || verifyPrivateFile(pendingPayloadPath) != nil {
		return errors.New("pending physical payload path is not private")
	}
	pendingPayloadInfo, err := os.Lstat(pendingPayloadPath)
	if err != nil || pendingPayloadInfo.Size() <= 0 || uint64(pendingPayloadInfo.Size()) != uint64(len(pendingInput.Payload)) {
		return errors.New("pending physical payload size differs from checked candidate")
	}
	if err := validatePhysicalPayload(pendingDirectory, physicalPayloadName, pendingInput.Payload, publication.BlobReference{CID: mustDecodeBytes(pendingCandidate.BlobCID), Size: uint64(len(pendingInput.Payload))}); err != nil {
		return err
	}

	if err := createPrivateChild(rootFD, mixedImageName); err != nil {
		return err
	}
	mixedDirectory := filepath.Join(root, mixedImageName)
	mixedStore, err := publicationstate.OpenWithOptions(mixedDirectory, binding, options)
	if err != nil {
		return errors.New("could not open fresh mixed publication store")
	}
	ownedStore = mixedStore
	storeOwned = true
	mixedState, err := buildMixedLifecycle(ctx, mixedStore, binding)
	if err != nil {
		return err
	}
	if err := closeStore(); err != nil {
		return err
	}
	mixedInventory, err := inspectDatabase(filepath.Join(mixedDirectory, "publication.db"))
	if err != nil {
		return err
	}
	if err := validateMixedRows(mixedInventory, mixedState); err != nil {
		return err
	}
	mixedInventory.Coverage = "mixed-lifecycle"
	if err := validateCombinedCoverage(pendingInventory, mixedInventory); err != nil {
		return err
	}
	if err := validateMixedPhysicalPayloads(mixedDirectory, mixedInventory, mixedState); err != nil {
		return err
	}
	mixedExpectations, err := mixedPayloadExpectations(mixedInventory, mixedState)
	if err != nil {
		return err
	}
	mixedReplay, err := makeMixedReplayInputs(mixedState, options)
	if err != nil {
		return err
	}

	pendingDatabaseID, pendingRevision, pendingGeneration, pendingMutation, err := readImageMetadata(pendingInventory)
	if err != nil {
		return err
	}
	mixedDatabaseID, mixedRevision, mixedGeneration, mixedMutation, err := readImageMetadata(mixedInventory)
	if err != nil {
		return err
	}
	if pendingDatabaseID == mixedDatabaseID || pendingRevision != 0 || pendingGeneration != 0 || pendingMutation != 1 || mixedDatabaseID != mixedState.FinalFloor.DatabaseID || mixedDatabaseID != mixedState.Genesis.Floor.DatabaseID || mixedRevision != mixedState.FinalFloor.Revision || mixedGeneration != mixedState.FinalFloor.Generation || mixedRevision != 2 || mixedGeneration != 2 || mixedMutation != 17 {
		return errors.New("image metadata does not join independent lifecycle states")
	}

	pendingCatalog := tableByName(pendingInventory, "payload_objects").Rows
	if len(pendingCatalog) != 1 || len(pendingCatalog[0]) != 4 || pendingCatalog[0][0].Type != "blob-base64" || pendingCatalog[0][2].Type != "text-base64" {
		return errors.New("pending payload catalog row shape differs")
	}
	pendingCatalogCID, err := base64.StdEncoding.DecodeString(pendingCatalog[0][0].Value)
	if err != nil || !bytes.Equal(pendingCatalogCID, mustDecodeBytes(pendingCandidate.BlobCID)) {
		return errors.New("pending payload catalog CID differs from candidate")
	}
	pendingCatalogSize, err := strconv.ParseInt(pendingCatalog[0][1].Value, 10, 64)
	if pendingCatalog[0][1].Type != "integer" || err != nil || pendingCatalogSize <= 0 || uint64(pendingCatalogSize) != uint64(len(pendingInput.Payload)) {
		return errors.New("pending payload catalog size differs from candidate")
	}
	pendingCatalogNameBytes, err := base64.StdEncoding.DecodeString(pendingCatalog[0][2].Value)
	if err != nil {
		return errors.New("pending payload catalog basename is malformed")
	}
	pendingCatalogName := string(pendingCatalogNameBytes)
	pendingLogicalBytes, err := strconv.ParseInt(pendingCatalog[0][3].Value, 10, 64)
	if pendingCatalog[0][3].Type != "integer" || err != nil || pendingLogicalBytes != pendingCatalogSize || pendingCatalogName != physicalPayloadName {
		return errors.New("pending payload catalog metadata differs")
	}
	pendingReferences := tableByName(pendingInventory, "attempt_payload_refs").Rows
	if len(pendingReferences) != 1 || len(pendingReferences[0]) != 2 || !cellEqualsBlob(pendingReferences[0], 0, created.ID[:]) || !cellEqualsBlob(pendingReferences[0], 1, pendingCatalogCID) {
		return errors.New("pending payload attempt owner differs from observed rows")
	}
	pendingRecordCID, err := publication.RecordCID(pendingInput.SnapshotRecord)
	if err != nil {
		return errors.New("pending payload record CID is invalid")
	}
	pendingPayloadDigest := sha256.Sum256(pendingInput.Payload)
	pendingPayloads := []payloadManifest{{
		Role: "pending-genesis", Path: imageName + "/" + payloadDirectoryName + "/" + pendingCatalogName,
		AttemptID: hex.EncodeToString(created.ID[:]), RecordCID: encodeBytes(pendingRecordCID), BlobCID: encodeBytes(pendingCatalogCID),
		Length: uint64(pendingCatalogSize), SHA256: hex.EncodeToString(pendingPayloadDigest[:]), Owner: "attempt",
	}}
	mixedPayloads := make([]payloadManifest, 0, len(mixedExpectations))
	retainedRows := tableByName(mixedInventory, "retained_publications").Rows
	if len(retainedRows) != 1 || len(retainedRows[0]) != 6 {
		return errors.New("mixed retained payload owner row shape differs")
	}
	retainedRevision, err := strconv.ParseInt(retainedRows[0][5].Value, 10, 64)
	if retainedRows[0][5].Type != "integer" || err != nil || retainedRevision <= 0 {
		return errors.New("mixed retained payload revision is malformed")
	}
	for _, expected := range mixedExpectations {
		var recordRaw []byte
		switch expected.role {
		case "retained-genesis":
			recordRaw = mixedState.GenesisInput.SnapshotRecord
		case "abandoned-catalogued":
			recordRaw = mixedState.OwnSuccessorInput.SnapshotRecord
		case "active-unresolved":
			recordRaw = mixedState.ActiveSuccessorInput.SnapshotRecord
		default:
			return errors.New("mixed payload role is unexpected")
		}
		recordCID, err := publication.RecordCID(recordRaw)
		if err != nil || !bytes.Equal(recordCID, expected.recordCID) {
			return errors.New("mixed payload record identity differs from checked role")
		}
		owner := "none"
		var acceptedRevision *uint64
		if expected.role == "retained-genesis" {
			owner = "retained-publication"
			revision := uint64(retainedRevision)
			acceptedRevision = &revision
		} else if expected.role == "active-unresolved" {
			owner = "attempt"
		}
		payloadDigest := sha256.Sum256(expected.expected)
		mixedPayloads = append(mixedPayloads, payloadManifest{
			Role: expected.role, Path: mixedImageName + "/" + payloadDirectoryName + "/" + expected.basename,
			AttemptID: hex.EncodeToString(expected.attemptID[:]), RecordCID: encodeBytes(recordCID), BlobCID: encodeBytes(expected.blob.CID),
			Length: expected.blob.Size, SHA256: hex.EncodeToString(payloadDigest[:]), Owner: owner, AcceptedRevision: acceptedRevision,
		})
	}
	sort.Slice(mixedPayloads, func(i, j int) bool { return mixedPayloads[i].Path < mixedPayloads[j].Path })

	if len(attemptPage.Attempts) != 1 {
		return errors.New("pending manifest attempt page shape differs")
	}
	pendingAttempt := attemptPage.Attempts[0]
	if pendingAttempt.ID != created.ID || pendingAttempt.Kind != created.Kind || pendingAttempt.Lifecycle != loaded.Lifecycle || pendingAttempt.Outcome != loaded.Outcome || pendingAttempt.Blocked != loaded.Blocked || pendingAttempt.Sequence != created.Sequence || pendingAttempt.SnapshotKey != created.SnapshotKey || !bytes.Equal(pendingAttempt.SnapshotRecordCID, created.SnapshotRecordCID) || !bytes.Equal(pendingAttempt.HeadRecordCID, created.HeadRecordCID) || !bytes.Equal(pendingAttempt.BlobCID, created.BlobCID) || pendingAttempt.BlobSize != created.BlobSize || pendingAttempt.StateDigest != created.StateDigest || pendingAttempt.CapturedFloor != nil || pendingAttempt.Availability != publicationstate.AvailabilityUnchecked {
		return errors.New("pending manifest attempt page does not join to the created attempt")
	}
	pendingAttemptManifest := mixedReplayAttempt{
		ID: encodeBytes(pendingAttempt.ID[:]), Kind: string(pendingAttempt.Kind), Lifecycle: string(pendingAttempt.Lifecycle), Outcome: string(pendingAttempt.Outcome), Blocked: pendingAttempt.Blocked,
		Sequence: pendingAttempt.Sequence, SnapshotKey: pendingAttempt.SnapshotKey, SnapshotRecordCID: encodeBytes(pendingAttempt.SnapshotRecordCID), HeadRecordCID: encodeBytes(pendingAttempt.HeadRecordCID),
		BlobCID: encodeBytes(pendingAttempt.BlobCID), BlobSize: pendingAttempt.BlobSize, CapturedFloor: nil, CapturedRevision: pendingAttempt.CapturedRevision, CapturedGeneration: pendingAttempt.CapturedGeneration,
		MutationRevision: pendingAttempt.MutationRevision, StateDigest: encodeBytes(pendingAttempt.StateDigest[:]), Availability: string(pendingAttempt.Availability),
	}
	pendingCacheID := (*byteValue)(nil)
	pendingImage := imageManifest{
		Name: imageName, SchemaVersion: pendingInventory.UserVersion, ApplicationID: pendingInventory.ApplicationID, DatabaseID: hex.EncodeToString(pendingDatabaseID[:]),
		Binding: bindingValueFor(binding), Options: optionsFor(options), Revision: pendingRevision, Generation: pendingGeneration, AttemptMutationRevision: pendingMutation,
		AcceptedFloor: present, Floor: nil, AcceptedEvents: int64(len(positionHistory.Events)), ActiveAttemptID: hex.EncodeToString(active.ID[:]),
		PendingGenesisAttemptID: hex.EncodeToString(created.ID[:]), Attempts: []mixedReplayAttempt{pendingAttemptManifest}, Tables: tableCounts(pendingInventory), Payloads: pendingPayloads,
		CacheObservationID: pendingCacheID, RowsArtifact: rowsName, InputsArtifact: inputsName,
	}
	mixedFloorManifest := mixedReplay.Results.FinalFloor
	mixedCacheID := encodeBytes(mixedState.CacheID[:])
	mixedImage := imageManifest{
		Name: mixedImageName, SchemaVersion: mixedInventory.UserVersion, ApplicationID: mixedInventory.ApplicationID, DatabaseID: hex.EncodeToString(mixedDatabaseID[:]),
		Binding: bindingValueFor(mixedState.Binding), Options: optionsFor(options), Revision: mixedRevision, Generation: mixedGeneration, AttemptMutationRevision: mixedMutation,
		AcceptedFloor: true, Floor: &mixedFloorManifest, AcceptedEvents: int64(len(mixedState.FinalHistory.Events)), ActiveAttemptID: hex.EncodeToString(mixedState.AbsentResolution.Attempt.ID[:]),
		PendingGenesisAttemptID: "", Attempts: append([]mixedReplayAttempt(nil), mixedReplay.Results.FinalPage.Attempts...), Tables: tableCounts(mixedInventory), Payloads: mixedPayloads,
		CacheObservationID: &mixedCacheID, RowsArtifact: mixedRowsName, InputsArtifact: mixedInputsName,
	}
	pendingInputs := makeReplayInputs(binding, pendingContext, pendingCandidate, pendingView, pendingReview, options)
	pendingRowsJSON, err := marshalJSON(pendingInventory)
	if err != nil {
		return err
	}
	pendingInputsJSON, err := marshalJSON(pendingInputs)
	if err != nil {
		return err
	}
	mixedRowsJSON, err := marshalJSON(mixedInventory)
	if err != nil {
		return err
	}
	mixedInputsJSON, err := marshalJSON(mixedReplay)
	if err != nil {
		return err
	}
	artifacts := []outputArtifact{
		{Name: rowsName, Role: "raw-row-inventory", Data: pendingRowsJSON},
		{Name: mixedRowsName, Role: "raw-row-inventory", Data: mixedRowsJSON},
		{Name: inputsName, Role: "replay-inputs", Data: pendingInputsJSON},
		{Name: mixedInputsName, Role: "replay-inputs", Data: mixedInputsJSON},
	}
	prewriteTotal := int64(0)
	addPrewriteSize := func(size uint64) bool {
		if size > uint64(maxOutputBytes-prewriteTotal) {
			return false
		}
		prewriteTotal += int64(size)
		return true
	}
	for _, artifact := range artifacts {
		if len(artifact.Data) == 0 || len(artifact.Data) > maxJSONBytes || !addPrewriteSize(uint64(len(artifact.Data))) {
			return errors.New("combined companion artifact size exceeds its bound")
		}
	}
	for _, payload := range append(append([]payloadManifest(nil), pendingImage.Payloads...), mixedImage.Payloads...) {
		if payload.Length == 0 || payload.Length > uint64(maxOutputBytes) || !addPrewriteSize(payload.Length) {
			return errors.New("combined payload and artifact size exceeds its bound")
		}
	}
	for _, artifact := range artifacts {
		if err := writeRootFile(rootFD, artifact.Name, artifact.Data); err != nil {
			return err
		}
	}
	files, err := inventoryOutputFiles(root, []imageManifest{pendingImage, mixedImage}, artifacts)
	if err != nil {
		return err
	}
	outputManifest := manifest{
		FormatVersion: 1, Coverage: "two-image-schema-2",
		Baseline: baselineValue{
			ExpectedCommit: baselineCommit, PinnedSourceFiles: baselinePinnedSourceFiles, SourceArchiveSHA256: baselineArchiveSHA256,
			ProvenanceDisposition: "intended-baseline; linked-source provenance must be verified externally",
		},
		Images: []imageManifest{pendingImage, mixedImage}, Files: files,
	}
	manifestJSON, err := marshalJSON(outputManifest)
	if err != nil || len(manifestJSON) == 0 || len(manifestJSON) > maxJSONBytes {
		return errors.New("combined manifest size exceeds its bound")
	}
	fileTotal := int64(0)
	for _, file := range files {
		if file.Length < 0 || file.Length > maxOutputBytes-fileTotal {
			return errors.New("output inventory total exceeds its bound")
		}
		fileTotal += file.Length
	}
	if int64(len(manifestJSON)) > maxOutputBytes-fileTotal {
		return errors.New("final output tree including manifest exceeds its bound")
	}
	if err := writeRootFile(rootFD, manifestPendingName, manifestJSON); err != nil {
		return err
	}
	if err := unix.Fsync(rootFD); err != nil {
		return errors.New("output directory sync failed")
	}
	if err := unix.Renameat2(rootFD, manifestPendingName, rootFD, manifestName, unix.RENAME_NOREPLACE); err != nil {
		return errors.New("manifest publication failed without overwrite fallback")
	}
	publicationSucceeded = true
	return nil
}

func syntheticGenesis() (publicationstate.Binding, publicationstate.SuppliedContext, candidateValue, publicationstate.CandidateInput, publicationstate.SuppliedRepositoryView, publicationstate.LocalReviewContext, publicationstate.OpenOptions, error) {
	var binding publicationstate.Binding
	binding.AccountDID = "did:plc:abcdefghijklmnopqrstuvwx"
	binding.Backend = publicationstate.BackendPublicRepo
	binding.Repository = "at://" + binding.AccountDID
	binding.Vault[0] = 9
	contextValue := publicationstate.SuppliedContext{RepositoryRevision: "synthetic-genesis-revision", RepositoryDigest: []byte{0x31, 0x32, 0x33, 0x34}}
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{{
			ID:            "synthetic-files",
			Source:        model.SourceFiles,
			SourceVersion: model.SourceVersion,
			Root:          &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
		}},
		Entries: []model.Entry{{
			TargetID: "synthetic-files",
			File: &model.FileEntry{
				Path:    "init.lua",
				State:   model.FilePresent,
				Kind:    model.FileRegular,
				Content: []byte("pending genesis synthetic payload"),
				Mode:    0o600,
			},
		}},
	}
	packed, err := vault.Pack(snapshot)
	if err != nil {
		return binding, contextValue, candidateValue{}, publicationstate.CandidateInput{}, publicationstate.SuppliedRepositoryView{}, publicationstate.LocalReviewContext{}, publicationstate.OpenOptions{}, errors.New("synthetic payload packing failed")
	}
	blobCID, err := publication.RawPayloadCID(packed.Payload)
	if err != nil {
		return binding, contextValue, candidateValue{}, publicationstate.CandidateInput{}, publicationstate.SuppliedRepositoryView{}, publicationstate.LocalReviewContext{}, publicationstate.OpenOptions{}, errors.New("synthetic payload CID failed")
	}
	var publicationID [16]byte
	publicationID[0] = 0x42
	publicationID[15] = 0x17
	record, err := publication.EncodeSnapshot(publication.SnapshotRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          binding.Vault,
		PublicationID:  publicationID,
		PublicationSeq: 0,
		Parent:         []byte{},
		Blob: publication.BlobReference{
			CID:  blobCID,
			Size: uint64(len(packed.Payload)),
		},
	})
	if err != nil {
		return binding, contextValue, candidateValue{}, publicationstate.CandidateInput{}, publicationstate.SuppliedRepositoryView{}, publicationstate.LocalReviewContext{}, publicationstate.OpenOptions{}, errors.New("synthetic snapshot record encoding failed")
	}
	recordCID, err := publication.RecordCID(record)
	if err != nil {
		return binding, contextValue, candidateValue{}, publicationstate.CandidateInput{}, publicationstate.SuppliedRepositoryView{}, publicationstate.LocalReviewContext{}, publicationstate.OpenOptions{}, errors.New("synthetic snapshot record CID failed")
	}
	key, err := publication.SequenceKey(0)
	if err != nil {
		return binding, contextValue, candidateValue{}, publicationstate.CandidateInput{}, publicationstate.SuppliedRepositoryView{}, publicationstate.LocalReviewContext{}, publicationstate.OpenOptions{}, errors.New("synthetic sequence key failed")
	}
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          binding.Vault,
		PublicationSeq: 0,
		SnapshotCID:    recordCID,
		BlobCID:        blobCID,
	})
	if err != nil {
		return binding, contextValue, candidateValue{}, publicationstate.CandidateInput{}, publicationstate.SuppliedRepositoryView{}, publicationstate.LocalReviewContext{}, publicationstate.OpenOptions{}, errors.New("synthetic head encoding failed")
	}
	headCID, err := publication.RecordCID(head)
	if err != nil {
		return binding, contextValue, candidateValue{}, publicationstate.CandidateInput{}, publicationstate.SuppliedRepositoryView{}, publicationstate.LocalReviewContext{}, publicationstate.OpenOptions{}, errors.New("synthetic head CID failed")
	}
	candidate := publicationstate.CandidateInput{SnapshotKey: key, SnapshotRecord: bytes.Clone(record), HeadRecord: bytes.Clone(head), Payload: bytes.Clone(packed.Payload)}
	candidateMetadata := candidateValue{
		PublicationID:  hex.EncodeToString(publicationID[:]),
		SnapshotKey:    key,
		SnapshotCID:    encodeBytes(recordCID),
		HeadCID:        encodeBytes(headCID),
		BlobCID:        encodeBytes(blobCID),
		BlobSize:       uint64(len(packed.Payload)),
		SnapshotRecord: encodeBytes(record),
		HeadRecord:     encodeBytes(head),
		Payload:        encodeBytes(packed.Payload),
	}
	view := publicationstate.SuppliedRepositoryView{Origin: binding, Scope: publicationstate.ViewScopeWholeRepository, SuppliedContext: contextValue}
	var review publicationstate.LocalReviewContext
	review.SelectionDigest[0] = 0x51
	review.ApprovalDigest[0] = 0x52
	review.SelectionRevision = 1
	review.ApprovalRevision = 1
	options := publicationstate.DefaultOpenOptions()
	return binding, contextValue, candidateMetadata, candidate, view, review, options, nil
}

func validateCandidate(input publicationstate.CandidateInput, binding publicationstate.Binding, candidate candidateValue) error {
	snapshot, err := publication.DecodeSnapshot(input.SnapshotRecord)
	if err != nil || snapshot.SchemaVersion != publication.SchemaVersion || snapshot.Vault != binding.Vault || snapshot.PublicationSeq != 0 || snapshot.PublicationID == [16]byte{} || hex.EncodeToString(snapshot.PublicationID[:]) != candidate.PublicationID || !bytes.Equal(snapshot.Blob.CID, mustDecodeBytes(candidate.BlobCID)) || snapshot.Blob.Size != uint64(len(input.Payload)) {
		return errors.New("synthetic snapshot record validation failed")
	}
	recordCID, err := publication.RecordCID(input.SnapshotRecord)
	if err != nil || !bytes.Equal(recordCID, mustDecodeBytes(candidate.SnapshotCID)) {
		return errors.New("synthetic snapshot CID validation failed")
	}
	head, err := publication.DecodeHead(input.HeadRecord)
	if err != nil || head.SchemaVersion != publication.SchemaVersion || head.Vault != binding.Vault || head.PublicationSeq != 0 || !bytes.Equal(head.SnapshotCID, recordCID) || !bytes.Equal(head.BlobCID, snapshot.Blob.CID) {
		return errors.New("synthetic head binding validation failed")
	}
	if err := publication.VerifyHeadBinding(input.HeadRecord, input.SnapshotRecord, input.SnapshotKey); err != nil {
		return errors.New("synthetic head-to-record join failed")
	}
	headCID, err := publication.RecordCID(input.HeadRecord)
	if err != nil || !bytes.Equal(headCID, mustDecodeBytes(candidate.HeadCID)) {
		return errors.New("synthetic head CID validation failed")
	}
	if err := publication.VerifyPayload(input.Payload, snapshot.Blob); err != nil {
		return errors.New("synthetic payload reference validation failed")
	}
	if _, err := publication.DecodePayload(input.Payload, snapshot.Blob); err != nil {
		return errors.New("synthetic packed payload validation failed")
	}
	return nil
}

func finalizeGenesis(ctx context.Context, store *publicationstate.Store, binding publicationstate.Binding, candidateInput publicationstate.CandidateInput, candidate candidateValue, emptyView publicationstate.SuppliedRepositoryView, currentView publicationstate.SuppliedRepositoryView, review publicationstate.LocalReviewContext) (publicationstate.Finalization, error) {
	if ctx == nil || store == nil {
		return publicationstate.Finalization{}, errors.New("genesis finalization inputs are invalid")
	}
	if ctx.Err() != nil {
		return publicationstate.Finalization{}, errors.New("genesis finalization context is invalid")
	}
	if binding.Backend != publicationstate.BackendPublicRepo || candidate.AttemptID != "" || emptyView.Origin != binding || currentView.Origin != binding || emptyView.Scope != publicationstate.ViewScopeWholeRepository || currentView.Scope != publicationstate.ViewScopeWholeRepository || len(emptyView.Head) != 0 || len(emptyView.Snapshots) != 0 || len(currentView.Snapshots) != 1 || !reflect.DeepEqual(emptyView.SuppliedContext.Policy, currentView.SuppliedContext.Policy) {
		return publicationstate.Finalization{}, errors.New("genesis finalization views are invalid")
	}
	if err := validateCandidate(candidateInput, binding, candidate); err != nil {
		return publicationstate.Finalization{}, errors.New("genesis candidate is invalid")
	}
	if !reflect.DeepEqual(encodeBytes(candidateInput.SnapshotRecord), candidate.SnapshotRecord) || !reflect.DeepEqual(encodeBytes(candidateInput.HeadRecord), candidate.HeadRecord) || !reflect.DeepEqual(encodeBytes(candidateInput.Payload), candidate.Payload) || candidate.SnapshotKey != candidateInput.SnapshotKey || candidate.BlobSize != uint64(len(candidateInput.Payload)) {
		return publicationstate.Finalization{}, errors.New("genesis candidate metadata differs")
	}
	snapshotCID, err := publication.RecordCID(candidateInput.SnapshotRecord)
	if err != nil || !reflect.DeepEqual(encodeBytes(snapshotCID), candidate.SnapshotCID) {
		return publicationstate.Finalization{}, errors.New("genesis snapshot identifier differs")
	}
	headCID, err := publication.RecordCID(candidateInput.HeadRecord)
	if err != nil || !reflect.DeepEqual(encodeBytes(headCID), candidate.HeadCID) {
		return publicationstate.Finalization{}, errors.New("genesis head identifier differs")
	}
	blobCID, err := publication.RawPayloadCID(candidateInput.Payload)
	if err != nil || !reflect.DeepEqual(encodeBytes(blobCID), candidate.BlobCID) || candidate.BlobSize != uint64(len(candidateInput.Payload)) {
		return publicationstate.Finalization{}, errors.New("genesis payload identifier differs")
	}
	if currentView.Snapshots[0].Key != candidate.SnapshotKey || !bytes.Equal(currentView.Snapshots[0].Raw, candidateInput.SnapshotRecord) || !bytes.Equal(currentView.Head, candidateInput.HeadRecord) {
		return publicationstate.Finalization{}, errors.New("genesis current view differs")
	}
	currentHead, err := publication.DecodeHead(currentView.Head)
	if err != nil || currentHead.PublicationSeq != 0 || !bytes.Equal(currentHead.SnapshotCID, snapshotCID) || !bytes.Equal(currentHead.BlobCID, blobCID) || publication.VerifyHeadBinding(currentView.Head, candidateInput.SnapshotRecord, candidate.SnapshotKey) != nil {
		return publicationstate.Finalization{}, errors.New("genesis current head is invalid")
	}
	publicationID, err := hex.DecodeString(candidate.PublicationID)
	if err != nil || len(publicationID) != 16 || allZero(publicationID) {
		return publicationstate.Finalization{}, errors.New("genesis publication identifier is invalid")
	}
	var attemptID [16]byte
	copy(attemptID[:], publicationID)

	floor, present, err := store.Load(ctx)
	if err != nil || present || !isZeroFloor(floor) {
		return publicationstate.Finalization{}, errors.New("genesis store already has a position")
	}
	active, activePresent, err := store.ActiveAttempt(ctx)
	if err != nil || activePresent || active.ID != [16]byte{} {
		return publicationstate.Finalization{}, errors.New("genesis store already has an active attempt")
	}
	positionHistory, err := store.History(ctx, 0, 10)
	if err != nil || len(positionHistory.Events) != 0 || len(positionHistory.Records) != 0 || positionHistory.HasMore || positionHistory.NextRevision != 0 {
		return publicationstate.Finalization{}, errors.New("genesis store position history is not empty")
	}
	attemptHistory, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	if err != nil || len(attemptHistory.Attempts) != 0 || len(attemptHistory.Evidence) != 0 || attemptHistory.HasMore || attemptHistory.NextID != [16]byte{} {
		return publicationstate.Finalization{}, errors.New("genesis store attempt history is not empty")
	}
	observation := publicationstate.Observation{Origin: currentView.Origin, SuppliedContext: currentView.SuppliedContext, Head: currentView.Head, Snapshots: currentView.Snapshots}
	positionProposal, err := store.Prepare(ctx, publicationstate.ModeFirstUse, observation, candidateInput.Payload)
	if err != nil || positionProposal.Mode != publicationstate.ModeFirstUse || positionProposal.Stop != "first_use" || positionProposal.Reason != "" || len(positionProposal.Trace) != 1 || positionProposal.Trace[0].Key != candidate.SnapshotKey || !bytes.Equal(positionProposal.Trace[0].CID, snapshotCID) || positionProposal.Trace[0].Sequence != 0 || allZero(positionProposal.StateToken[:]) || allZero(positionProposal.Confirmation[:]) {
		return publicationstate.Finalization{}, errors.New("genesis current observation is invalid")
	}

	proposal, err := store.PrepareAttempt(ctx, candidateInput, emptyView, review)
	if err != nil || proposal.AttemptID != attemptID || proposal.Kind != publicationstate.AttemptGenesis || proposal.CapturedFloor != nil || proposal.CapturedGeneration != 0 || allZero(proposal.StateToken[:]) || allZero(proposal.CandidateDigest[:]) || allZero(proposal.Confirmation[:]) || !bytes.Equal(proposal.CandidateRecordCID, snapshotCID) || !bytes.Equal(proposal.CandidateBlobCID, blobCID) || proposal.CandidateBlobSize != uint64(len(candidateInput.Payload)) {
		return publicationstate.Finalization{}, errors.New("genesis attempt preparation differs")
	}
	created, err := store.CreateAttempt(ctx, proposal.StateToken, candidateInput, emptyView, review, proposal.Confirmation)
	if err != nil || created.ID != attemptID || created.Kind != publicationstate.AttemptGenesis || created.Lifecycle != publicationstate.AttemptPrepared || created.Outcome != publicationstate.OutcomeNotSubmitted || created.Blocked != "" || created.Sequence != 0 || !bytes.Equal(created.SnapshotRecordCID, snapshotCID) || !bytes.Equal(created.HeadRecordCID, headCID) || !bytes.Equal(created.BlobCID, blobCID) || created.BlobSize != uint64(len(candidateInput.Payload)) || created.CapturedFloor != nil || created.CapturedRevision != 0 || created.CapturedGeneration != 0 || allZero(created.StateDigest[:]) {
		return publicationstate.Finalization{}, errors.New("genesis attempt creation differs")
	}

	uploadProposal, err := store.PrepareDispatch(ctx, attemptID, publicationstate.DispatchUpload, emptyView, review)
	if err != nil || uploadProposal.AttemptID != attemptID || uploadProposal.Kind != publicationstate.DispatchUpload || allZero(uploadProposal.StateToken[:]) || allZero(uploadProposal.Confirmation[:]) {
		return publicationstate.Finalization{}, errors.New("genesis upload preparation differs")
	}
	upload, err := store.BeginUpload(ctx, attemptID, uploadProposal.StateToken, emptyView, review, uploadProposal.Confirmation)
	if err != nil || upload.AttemptID != attemptID || !bytes.Equal(upload.Payload, candidateInput.Payload) || !bytes.Equal(upload.Blob.CID, blobCID) || upload.Blob.Size != uint64(len(candidateInput.Payload)) {
		return publicationstate.Finalization{}, errors.New("genesis upload material differs")
	}
	uploadState, err := store.LoadAttempt(ctx, attemptID)
	if err != nil || uploadState.ID != attemptID || uploadState.Kind != publicationstate.AttemptGenesis || uploadState.Lifecycle != publicationstate.AttemptUploadStarted || uploadState.Outcome != publicationstate.OutcomeNotSubmitted || uploadState.Blocked != "" || uploadState.Sequence != 0 || uploadState.SnapshotKey != candidate.SnapshotKey || !bytes.Equal(uploadState.SnapshotRecordCID, snapshotCID) || !bytes.Equal(uploadState.HeadRecordCID, headCID) || !bytes.Equal(uploadState.BlobCID, blobCID) || uploadState.BlobSize != uint64(len(candidateInput.Payload)) || allZero(uploadState.StateDigest[:]) {
		return publicationstate.Finalization{}, errors.New("genesis upload state differs")
	}

	submissionProposal, err := store.PrepareDispatch(ctx, attemptID, publicationstate.DispatchSubmission, emptyView, review)
	if err != nil || submissionProposal.AttemptID != attemptID || submissionProposal.Kind != publicationstate.DispatchSubmission || allZero(submissionProposal.StateToken[:]) || allZero(submissionProposal.Confirmation[:]) {
		return publicationstate.Finalization{}, errors.New("genesis submission preparation differs")
	}
	submission, err := store.BeginSubmission(ctx, attemptID, submissionProposal.StateToken, emptyView, review, submissionProposal.Confirmation)
	if err != nil || submission.AttemptID != attemptID || submission.SnapshotCollection != publication.SnapshotNSID || submission.SnapshotKey != candidate.SnapshotKey || !bytes.Equal(submission.SnapshotRecord, candidateInput.SnapshotRecord) || !bytes.Equal(submission.ExpectedSnapshotCID, snapshotCID) || !submission.SnapshotCreateOnly || submission.HeadCollection != publication.HeadNSID || submission.HeadKey != "self" || !bytes.Equal(submission.HeadRecord, candidateInput.HeadRecord) || !submission.HeadCreate || submission.ExpectedPredecessor != nil || !reflect.DeepEqual(submission.ExpectedContext, emptyView.SuppliedContext) || !submission.RequiresAtomicBatch || !submission.RequiresCreateExclude || submission.RequiresPolicyCheck {
		return publicationstate.Finalization{}, errors.New("genesis submission material differs")
	}
	submittedState, err := store.LoadAttempt(ctx, attemptID)
	if err != nil || submittedState.ID != attemptID || submittedState.Kind != publicationstate.AttemptGenesis || submittedState.Lifecycle != publicationstate.AttemptMayHaveSubmitted || submittedState.Outcome != publicationstate.OutcomeUnresolved || submittedState.Blocked != "" || submittedState.Sequence != 0 || submittedState.SnapshotKey != candidate.SnapshotKey || !bytes.Equal(submittedState.SnapshotRecordCID, snapshotCID) || !bytes.Equal(submittedState.HeadRecordCID, headCID) || !bytes.Equal(submittedState.BlobCID, blobCID) || submittedState.BlobSize != uint64(len(candidateInput.Payload)) || allZero(submittedState.StateDigest[:]) {
		return publicationstate.Finalization{}, errors.New("genesis submitted state differs")
	}
	resolution, err := store.ResolveAttempt(ctx, attemptID, submittedState.StateDigest, currentView)
	if err != nil || resolution.Outcome != publicationstate.OutcomeCurrent || resolution.Attempt.ID != attemptID || resolution.Attempt.Kind != publicationstate.AttemptGenesis || resolution.Attempt.Lifecycle != publicationstate.AttemptMayHaveSubmitted || resolution.Attempt.Outcome != publicationstate.OutcomeCurrent || resolution.Attempt.Blocked != "" || resolution.Attempt.Sequence != 0 || resolution.Attempt.SnapshotKey != candidate.SnapshotKey || !bytes.Equal(resolution.Attempt.SnapshotRecordCID, snapshotCID) || !bytes.Equal(resolution.Attempt.HeadRecordCID, headCID) || !bytes.Equal(resolution.Attempt.BlobCID, blobCID) || resolution.Attempt.BlobSize != uint64(len(candidateInput.Payload)) || allZero(resolution.Attempt.StateDigest[:]) || len(resolution.Evidence) == 0 || allZero(resolution.ViewDigest[:]) {
		return publicationstate.Finalization{}, errors.New("genesis current resolution differs")
	}
	finalization, err := store.FinalizeAttempt(ctx, attemptID, resolution.Attempt.StateDigest, currentView)
	if err != nil {
		return publicationstate.Finalization{}, errors.New("genesis finalization failed")
	}
	finalFloor := finalization.Floor
	if finalization.Attempt.ID != attemptID || finalization.Attempt.Kind != publicationstate.AttemptGenesis || finalization.Attempt.Lifecycle != publicationstate.AttemptRetiredSuccess || finalization.Attempt.Outcome != publicationstate.OutcomeCurrent || finalization.Attempt.Blocked != "" || finalization.Attempt.Sequence != 0 || finalization.Attempt.SnapshotKey != candidate.SnapshotKey || !bytes.Equal(finalization.Attempt.SnapshotRecordCID, snapshotCID) || !bytes.Equal(finalization.Attempt.HeadRecordCID, headCID) || !bytes.Equal(finalization.Attempt.BlobCID, blobCID) || finalization.Attempt.BlobSize != uint64(len(candidateInput.Payload)) || allZero(finalization.Attempt.StateDigest[:]) || allZero(finalFloor.DatabaseID[:]) || finalFloor.Revision != 1 || finalFloor.Generation != 1 || finalFloor.Provenance != publicationstate.ProvenanceFirst || !bytes.Equal(finalFloor.AnchorCID, snapshotCID) || finalFloor.Binding != binding || !reflect.DeepEqual(finalFloor.SuppliedContext, currentView.SuppliedContext) || !bytes.Equal(finalFloor.Head, candidateInput.HeadRecord) || finalFloor.SnapshotKey != candidate.SnapshotKey || finalFloor.Sequence != 0 || finalFloor.PublicationID != attemptID || !bytes.Equal(finalFloor.RecordCID, snapshotCID) || !bytes.Equal(finalFloor.BlobCID, blobCID) || finalFloor.BlobSize != uint64(len(candidateInput.Payload)) || finalFloor.ObservationDigest != positionProposal.ObservationDigest || allZero(finalFloor.AcceptedEventDigest[:]) {
		return publicationstate.Finalization{}, errors.New("genesis finalization identity differs")
	}
	loadedFloor, present, err := store.Load(ctx)
	if err != nil || !present || !reflect.DeepEqual(loadedFloor, finalFloor) {
		return publicationstate.Finalization{}, errors.New("genesis accepted floor readback differs")
	}
	acceptedHistory, err := store.History(ctx, 0, 10)
	if err != nil || len(acceptedHistory.Events) != 1 || len(acceptedHistory.Records) != 1 || acceptedHistory.HasMore || acceptedHistory.NextRevision != 1 {
		return publicationstate.Finalization{}, errors.New("genesis accepted history shape differs")
	}
	event := acceptedHistory.Events[0]
	if event.Revision != 1 || event.Mode != publicationstate.ModeFirstUse || event.Reason != "" || event.Stop != "first_use" || event.OldFloor != nil || !reflect.DeepEqual(event.NewFloor, finalFloor) || event.EventDigest != finalFloor.AcceptedEventDigest || event.ObservationDigest != finalFloor.ObservationDigest || len(event.Trace) != 1 || event.Trace[0].Key != candidate.SnapshotKey || !bytes.Equal(event.Trace[0].CID, snapshotCID) || event.Trace[0].Sequence != 0 || acceptedHistory.Records[0].Reference.Key != candidate.SnapshotKey || !bytes.Equal(acceptedHistory.Records[0].Reference.CID, snapshotCID) || acceptedHistory.Records[0].Reference.Sequence != 0 || !bytes.Equal(acceptedHistory.Records[0].Raw, candidateInput.SnapshotRecord) {
		return publicationstate.Finalization{}, errors.New("genesis accepted history evidence differs")
	}
	loadedAttempt, err := store.LoadAttempt(ctx, attemptID)
	if err != nil || loadedAttempt.ID != attemptID || loadedAttempt.Kind != publicationstate.AttemptGenesis || loadedAttempt.Lifecycle != publicationstate.AttemptRetiredSuccess || loadedAttempt.Outcome != publicationstate.OutcomeCurrent || loadedAttempt.Blocked != "" || loadedAttempt.Sequence != 0 || loadedAttempt.SnapshotKey != candidate.SnapshotKey || !bytes.Equal(loadedAttempt.SnapshotRecordCID, snapshotCID) || !bytes.Equal(loadedAttempt.HeadRecordCID, headCID) || !bytes.Equal(loadedAttempt.BlobCID, blobCID) || loadedAttempt.BlobSize != uint64(len(candidateInput.Payload)) || loadedAttempt.StateDigest != finalization.Attempt.StateDigest {
		return publicationstate.Finalization{}, errors.New("genesis finalized attempt readback differs")
	}
	attemptHistory, err = store.AttemptHistory(ctx, [16]byte{}, 10)
	if err != nil || len(attemptHistory.Attempts) != 1 || attemptHistory.HasMore || attemptHistory.NextID != attemptID || attemptHistory.Attempts[0].ID != attemptID || attemptHistory.Attempts[0].Kind != publicationstate.AttemptGenesis || attemptHistory.Attempts[0].Lifecycle != publicationstate.AttemptRetiredSuccess || attemptHistory.Attempts[0].Outcome != publicationstate.OutcomeCurrent || attemptHistory.Attempts[0].Blocked != "" || attemptHistory.Attempts[0].Sequence != 0 || attemptHistory.Attempts[0].SnapshotKey != candidate.SnapshotKey || !bytes.Equal(attemptHistory.Attempts[0].SnapshotRecordCID, snapshotCID) || !bytes.Equal(attemptHistory.Attempts[0].HeadRecordCID, headCID) || !bytes.Equal(attemptHistory.Attempts[0].BlobCID, blobCID) || attemptHistory.Attempts[0].BlobSize != uint64(len(candidateInput.Payload)) || attemptHistory.Attempts[0].StateDigest != finalization.Attempt.StateDigest {
		return publicationstate.Finalization{}, errors.New("genesis finalized attempt history differs")
	}
	hasOutcomeEvidence := false
	hasSubmissionEvidence := false
	for _, evidence := range attemptHistory.Evidence {
		if evidence.AttemptID != attemptID || len(evidence.Evidence) == 0 {
			return publicationstate.Finalization{}, errors.New("genesis attempt evidence identity differs")
		}
		switch evidence.Role {
		case "outcome":
			if hasOutcomeEvidence || !bytes.Equal(evidence.Evidence, resolution.Evidence) {
				return publicationstate.Finalization{}, errors.New("genesis outcome evidence differs")
			}
			hasOutcomeEvidence = true
		case "submission":
			if hasSubmissionEvidence {
				return publicationstate.Finalization{}, errors.New("genesis submission evidence is duplicated")
			}
			hasSubmissionEvidence = true
		default:
			return publicationstate.Finalization{}, errors.New("genesis attempt evidence role is unexpected")
		}
	}
	if !hasOutcomeEvidence || !hasSubmissionEvidence {
		return publicationstate.Finalization{}, errors.New("genesis lifecycle evidence is incomplete")
	}
	active, activePresent, err = store.ActiveAttempt(ctx)
	if err != nil || activePresent || active.ID != [16]byte{} {
		return publicationstate.Finalization{}, errors.New("genesis active attempt remains")
	}
	candidateMaterial, err := store.ReadCandidate(ctx, attemptID)
	if err != nil || candidateMaterial.AttemptID != attemptID || candidateMaterial.SnapshotKey != candidate.SnapshotKey || !bytes.Equal(candidateMaterial.SnapshotRecord, candidateInput.SnapshotRecord) || !bytes.Equal(candidateMaterial.HeadRecord, candidateInput.HeadRecord) || !bytes.Equal(candidateMaterial.Payload, candidateInput.Payload) || !bytes.Equal(candidateMaterial.Blob.CID, blobCID) || candidateMaterial.Blob.Size != uint64(len(candidateInput.Payload)) {
		return publicationstate.Finalization{}, errors.New("genesis retained candidate readback differs")
	}
	acceptedMaterial, err := store.ReadAcceptedMaterial(ctx, binding, finalFloor)
	if err != nil || !reflect.DeepEqual(acceptedMaterial.Floor, finalFloor) || !bytes.Equal(acceptedMaterial.SnapshotRecord, candidateInput.SnapshotRecord) || !bytes.Equal(acceptedMaterial.Payload, candidateInput.Payload) {
		return publicationstate.Finalization{}, errors.New("genesis accepted material readback differs")
	}
	return finalization, nil
}

type attemptOutcomeReadback struct {
	Version           uint32                           `json:"version"`
	Role              string                           `json:"role"`
	ViewDigest        []byte                           `json:"viewDigest"`
	Head              []byte                           `json:"head"`
	AttemptedKey      string                           `json:"attemptedKey"`
	AttemptedRecord   []byte                           `json:"attemptedRecord"`
	PredecessorRecord []byte                           `json:"predecessorRecord"`
	Suffix            []publicationstate.SnapshotBlock `json:"suffix"`
	Outcome           string                           `json:"outcome"`
}

func submitSuccessorThenExtendLostFence(ctx context.Context, store *publicationstate.Store, binding publicationstate.Binding, genesis publicationstate.Finalization, genesisInput publicationstate.CandidateInput, genesisMetadata candidateValue, successorInput publicationstate.CandidateInput, successorMetadata candidateValue, predecessorView, firstConflictView, extendedView publicationstate.SuppliedRepositoryView, review publicationstate.LocalReviewContext) (publicationstate.AttemptResolution, publicationstate.FirstConflictEvidence, error) {
	if ctx == nil || store == nil {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor inputs are invalid")
	}
	if ctx.Err() != nil {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor context is invalid")
	}
	if binding.Backend != publicationstate.BackendPublicRepo || genesis.Attempt.CapturedFloor != nil || len(predecessorView.Snapshots) != 1 || len(firstConflictView.Snapshots) != 2 || len(extendedView.Snapshots) != 3 || len(predecessorView.Head) == 0 || len(firstConflictView.Head) == 0 || len(extendedView.Head) == 0 {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor view shape is invalid")
	}
	if predecessorView.Origin != binding || firstConflictView.Origin != binding || extendedView.Origin != binding || predecessorView.Scope != publicationstate.ViewScopeWholeRepository || firstConflictView.Scope != publicationstate.ViewScopeWholeRepository || extendedView.Scope != publicationstate.ViewScopeWholeRepository {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor view binding is invalid")
	}
	if review.SelectionRevision == 0 || review.ApprovalRevision == 0 || allZero(review.SelectionDigest[:]) || allZero(review.ApprovalDigest[:]) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor review is invalid")
	}
	contexts := []publicationstate.SuppliedContext{predecessorView.SuppliedContext, firstConflictView.SuppliedContext, extendedView.SuppliedContext}
	for _, supplied := range contexts {
		if len(supplied.RepositoryRevision) == 0 || len(supplied.RepositoryRevision) > 1024 || strings.ToValidUTF8(supplied.RepositoryRevision, "") != supplied.RepositoryRevision || len(supplied.RepositoryDigest) == 0 || len(supplied.RepositoryDigest) > 128 || supplied.Policy != nil {
			return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor repository context is invalid")
		}
	}
	if !reflect.DeepEqual(predecessorView.SuppliedContext, genesis.Floor.SuppliedContext) || predecessorView.SuppliedContext.RepositoryRevision == firstConflictView.SuppliedContext.RepositoryRevision || firstConflictView.SuppliedContext.RepositoryRevision == extendedView.SuppliedContext.RepositoryRevision || predecessorView.SuppliedContext.RepositoryRevision == extendedView.SuppliedContext.RepositoryRevision || bytes.Equal(predecessorView.SuppliedContext.RepositoryDigest, firstConflictView.SuppliedContext.RepositoryDigest) || bytes.Equal(firstConflictView.SuppliedContext.RepositoryDigest, extendedView.SuppliedContext.RepositoryDigest) || bytes.Equal(predecessorView.SuppliedContext.RepositoryDigest, extendedView.SuppliedContext.RepositoryDigest) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor repository contexts are not distinct")
	}
	if err := validateCandidate(genesisInput, binding, genesisMetadata); err != nil {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed genesis candidate is invalid")
	}
	genesisRecord, err := publication.DecodeSnapshot(genesisInput.SnapshotRecord)
	if err != nil || genesisRecord.PublicationSeq != 0 || len(genesisRecord.Parent) != 0 {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed genesis record is invalid")
	}
	genesisRecordCID, err := publication.RecordCID(genesisInput.SnapshotRecord)
	if err != nil || !reflect.DeepEqual(encodeBytes(genesisRecordCID), genesisMetadata.SnapshotCID) || !reflect.DeepEqual(encodeBytes(genesisInput.SnapshotRecord), genesisMetadata.SnapshotRecord) || !reflect.DeepEqual(encodeBytes(genesisInput.HeadRecord), genesisMetadata.HeadRecord) || !reflect.DeepEqual(encodeBytes(genesisInput.Payload), genesisMetadata.Payload) || genesisMetadata.SnapshotKey != genesisInput.SnapshotKey || genesisMetadata.BlobSize != uint64(len(genesisInput.Payload)) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed genesis metadata differs")
	}
	genesisHeadCID, err := publication.RecordCID(genesisInput.HeadRecord)
	if err != nil || !reflect.DeepEqual(encodeBytes(genesisHeadCID), genesisMetadata.HeadCID) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed genesis head identifier differs")
	}
	genesisBlobCID, err := publication.RawPayloadCID(genesisInput.Payload)
	if err != nil || !reflect.DeepEqual(encodeBytes(genesisBlobCID), genesisMetadata.BlobCID) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed genesis payload identifier differs")
	}
	genesisPublicationID, err := hex.DecodeString(genesisMetadata.PublicationID)
	if err != nil || len(genesisPublicationID) != 16 || allZero(genesisPublicationID) || !bytes.Equal(genesisPublicationID, genesisRecord.PublicationID[:]) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed genesis publication identifier differs")
	}
	var genesisAttemptID [16]byte
	copy(genesisAttemptID[:], genesisPublicationID)
	if (genesisMetadata.AttemptID != "" && genesisMetadata.AttemptID != hex.EncodeToString(genesisAttemptID[:])) || genesis.Attempt.ID != genesisAttemptID || genesis.Attempt.Kind != publicationstate.AttemptGenesis || genesis.Attempt.Lifecycle != publicationstate.AttemptRetiredSuccess || genesis.Attempt.Outcome != publicationstate.OutcomeCurrent || genesis.Attempt.Blocked != "" || genesis.Attempt.Sequence != 0 || genesis.Attempt.SnapshotKey != genesisInput.SnapshotKey || !bytes.Equal(genesis.Attempt.SnapshotRecordCID, genesisRecordCID) || !bytes.Equal(genesis.Attempt.HeadRecordCID, genesisHeadCID) || !bytes.Equal(genesis.Attempt.BlobCID, genesisBlobCID) || genesis.Attempt.BlobSize != uint64(len(genesisInput.Payload)) || allZero(genesis.Attempt.StateDigest[:]) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed finalized genesis identity differs")
	}
	genesisFloor := genesis.Floor
	if allZero(genesisFloor.DatabaseID[:]) || genesisFloor.Revision != 1 || genesisFloor.Generation != 1 || genesisFloor.Provenance != publicationstate.ProvenanceFirst || genesisFloor.Binding != binding || !bytes.Equal(genesisFloor.AnchorCID, genesisRecordCID) || !reflect.DeepEqual(genesisFloor.SuppliedContext, predecessorView.SuppliedContext) || !bytes.Equal(genesisFloor.Head, genesisInput.HeadRecord) || genesisFloor.SnapshotKey != genesisInput.SnapshotKey || genesisFloor.Sequence != 0 || genesisFloor.PublicationID != genesisAttemptID || !bytes.Equal(genesisFloor.RecordCID, genesisRecordCID) || !bytes.Equal(genesisFloor.BlobCID, genesisBlobCID) || genesisFloor.BlobSize != uint64(len(genesisInput.Payload)) || allZero(genesisFloor.ObservationDigest[:]) || allZero(genesisFloor.AcceptedEventDigest[:]) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed finalized genesis floor differs")
	}
	if successorMetadata.AttemptID != "" || successorMetadata.SnapshotKey != successorInput.SnapshotKey {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor metadata shape differs")
	}
	successorRecord, err := publication.DecodeSnapshot(successorInput.SnapshotRecord)
	if err != nil || successorRecord.Vault != binding.Vault || successorRecord.PublicationSeq != 1 || !bytes.Equal(successorRecord.Parent, genesisRecordCID) || allZero(successorRecord.PublicationID[:]) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor record is invalid")
	}
	successorKey, err := publication.SequenceKey(1)
	if err != nil || successorInput.SnapshotKey != successorKey || successorMetadata.SnapshotKey != successorKey || hex.EncodeToString(successorRecord.PublicationID[:]) != successorMetadata.PublicationID || bytes.Equal(successorRecord.PublicationID[:], genesisAttemptID[:]) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor identity differs")
	}
	successorAttemptID := successorRecord.PublicationID
	successorRecordCID, err := publication.RecordCID(successorInput.SnapshotRecord)
	if err != nil || !reflect.DeepEqual(encodeBytes(successorRecordCID), successorMetadata.SnapshotCID) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor record identifier differs")
	}
	successorHead, err := publication.DecodeHead(successorInput.HeadRecord)
	if err != nil || successorHead.Vault != binding.Vault || successorHead.PublicationSeq != 1 || !bytes.Equal(successorHead.SnapshotCID, successorRecordCID) || !bytes.Equal(successorHead.BlobCID, successorRecord.Blob.CID) || publication.VerifyHeadBinding(successorInput.HeadRecord, successorInput.SnapshotRecord, successorKey) != nil {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor head binding is invalid")
	}
	successorHeadCID, err := publication.RecordCID(successorInput.HeadRecord)
	if err != nil || !reflect.DeepEqual(encodeBytes(successorHeadCID), successorMetadata.HeadCID) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor head identifier differs")
	}
	successorBlobCID, err := publication.RawPayloadCID(successorInput.Payload)
	if err != nil || !bytes.Equal(successorBlobCID, successorRecord.Blob.CID) || successorRecord.Blob.Size != uint64(len(successorInput.Payload)) || !reflect.DeepEqual(encodeBytes(successorBlobCID), successorMetadata.BlobCID) || successorMetadata.BlobSize != uint64(len(successorInput.Payload)) || bytes.Equal(successorBlobCID, genesisBlobCID) || bytes.Equal(successorInput.Payload, genesisInput.Payload) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor payload is not distinct")
	}
	if err := publication.VerifyPayload(successorInput.Payload, successorRecord.Blob); err != nil {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor payload reference is invalid")
	}
	if _, err := publication.DecodePayload(successorInput.Payload, successorRecord.Blob); err != nil {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor payload is invalid")
	}
	if !reflect.DeepEqual(encodeBytes(successorInput.SnapshotRecord), successorMetadata.SnapshotRecord) || !reflect.DeepEqual(encodeBytes(successorInput.HeadRecord), successorMetadata.HeadRecord) || !reflect.DeepEqual(encodeBytes(successorInput.Payload), successorMetadata.Payload) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor metadata bytes differ")
	}

	views := []publicationstate.SuppliedRepositoryView{predecessorView, firstConflictView, extendedView}
	viewRecords := make([][]publication.SnapshotRecord, len(views))
	viewCIDs := make([][][]byte, len(views))
	for viewIndex, view := range views {
		if len(view.Head) > publication.MaxRecordBytes {
			return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor head exceeds its bound")
		}
		viewRecords[viewIndex] = make([]publication.SnapshotRecord, 0, len(view.Snapshots))
		viewCIDs[viewIndex] = make([][]byte, 0, len(view.Snapshots))
		for blockIndex, block := range view.Snapshots {
			if len(block.Raw) == 0 || len(block.Raw) > publication.MaxRecordBytes {
				return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor view record exceeds its bound")
			}
			sequence := uint64(blockIndex)
			key, err := publication.SequenceKey(sequence)
			if err != nil || block.Key != key {
				return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor view key differs")
			}
			record, err := publication.DecodeSnapshot(block.Raw)
			if err != nil || record.Vault != binding.Vault || record.PublicationSeq != sequence || allZero(record.PublicationID[:]) {
				return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor view record is invalid")
			}
			if blockIndex == 0 {
				if len(record.Parent) != 0 || !bytes.Equal(block.Raw, genesisInput.SnapshotRecord) {
					return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor view predecessor differs")
				}
			} else if err := publication.VerifySuccessor(view.Snapshots[blockIndex-1].Raw, block.Raw, block.Key); err != nil {
				return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor view lineage is invalid")
			}
			cid, err := publication.RecordCID(block.Raw)
			if err != nil {
				return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor view record identifier is invalid")
			}
			for _, previousCID := range viewCIDs[viewIndex] {
				if bytes.Equal(previousCID, cid) {
					return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor view repeats a record")
				}
			}
			viewRecords[viewIndex] = append(viewRecords[viewIndex], record)
			viewCIDs[viewIndex] = append(viewCIDs[viewIndex], cid)
		}
		last := len(view.Snapshots) - 1
		head, err := publication.DecodeHead(view.Head)
		if err != nil || head.Vault != binding.Vault || head.PublicationSeq != uint64(last) || !bytes.Equal(head.SnapshotCID, viewCIDs[viewIndex][last]) || !bytes.Equal(head.BlobCID, viewRecords[viewIndex][last].Blob.CID) || publication.VerifyHeadBinding(view.Head, view.Snapshots[last].Raw, view.Snapshots[last].Key) != nil {
			return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor view head binding is invalid")
		}
	}
	if !bytes.Equal(viewCIDs[0][0], genesisRecordCID) || !bytes.Equal(viewCIDs[1][0], genesisRecordCID) || !bytes.Equal(viewCIDs[2][0], genesisRecordCID) || !bytes.Equal(firstConflictView.Snapshots[0].Raw, extendedView.Snapshots[0].Raw) || !bytes.Equal(firstConflictView.Snapshots[1].Raw, extendedView.Snapshots[1].Raw) || firstConflictView.Snapshots[0].Key != extendedView.Snapshots[0].Key || firstConflictView.Snapshots[1].Key != extendedView.Snapshots[1].Key {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor suffix prefix differs")
	}
	conflictRecord := viewRecords[1][1]
	conflictCID := viewCIDs[1][1]
	if bytes.Equal(conflictCID, successorRecordCID) || bytes.Equal(firstConflictView.Snapshots[1].Raw, successorInput.SnapshotRecord) || bytes.Equal(conflictRecord.PublicationID[:], successorAttemptID[:]) || !bytes.Equal(conflictRecord.Parent, genesisRecordCID) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor conflict occupant is not distinct")
	}
	extendedRecord := viewRecords[2][2]
	if bytes.Equal(extendedRecord.PublicationID[:], successorAttemptID[:]) || bytes.Equal(extendedRecord.PublicationID[:], conflictRecord.PublicationID[:]) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor extension identity is not distinct")
	}
	firstHeadCID, err := publication.RecordCID(firstConflictView.Head)
	if err != nil {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed first conflict head identifier is invalid")
	}
	extendedHeadCID, err := publication.RecordCID(extendedView.Head)
	if err != nil || bytes.Equal(firstHeadCID, extendedHeadCID) || bytes.Equal(firstConflictView.Head, extendedView.Head) || !bytes.Equal(extendedRecord.Parent, conflictCID) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed latest view is not a distinct extension")
	}

	preFloor, floorPresent, err := store.Load(ctx)
	if err != nil || !floorPresent || !reflect.DeepEqual(preFloor, genesisFloor) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed store floor differs before successor")
	}
	finalizedState, err := store.LoadAttempt(ctx, genesisAttemptID)
	if err != nil || finalizedState.ID != genesisAttemptID || finalizedState.Kind != publicationstate.AttemptGenesis || finalizedState.Lifecycle != publicationstate.AttemptRetiredSuccess || finalizedState.Outcome != publicationstate.OutcomeCurrent || finalizedState.Blocked != "" || finalizedState.Sequence != 0 || finalizedState.SnapshotKey != genesisInput.SnapshotKey || !bytes.Equal(finalizedState.SnapshotRecordCID, genesisRecordCID) || !bytes.Equal(finalizedState.HeadRecordCID, genesisHeadCID) || !bytes.Equal(finalizedState.BlobCID, genesisBlobCID) || finalizedState.BlobSize != uint64(len(genesisInput.Payload)) || finalizedState.CapturedFloor != nil || finalizedState.CapturedRevision != 0 || finalizedState.CapturedGeneration != 0 || finalizedState.StateDigest != genesis.Attempt.StateDigest {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed finalized genesis state differs before successor")
	}
	preHistory, err := store.History(ctx, 0, 10)
	if err != nil || len(preHistory.Events) != 1 || len(preHistory.Records) != 1 || preHistory.HasMore || preHistory.NextRevision != 1 {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed accepted history shape differs before successor")
	}
	genesisEvent := preHistory.Events[0]
	if genesisEvent.Revision != 1 || genesisEvent.Mode != publicationstate.ModeFirstUse || genesisEvent.Reason != "" || genesisEvent.Stop != "first_use" || genesisEvent.OldFloor != nil || !reflect.DeepEqual(genesisEvent.NewFloor, genesisFloor) || genesisEvent.EventDigest != genesisFloor.AcceptedEventDigest || genesisEvent.ObservationDigest != genesisFloor.ObservationDigest || len(genesisEvent.Trace) != 1 || genesisEvent.Trace[0].Key != genesisInput.SnapshotKey || genesisEvent.Trace[0].Sequence != 0 || !bytes.Equal(genesisEvent.Trace[0].CID, genesisRecordCID) || preHistory.Records[0].Reference.Key != genesisInput.SnapshotKey || preHistory.Records[0].Reference.Sequence != 0 || !bytes.Equal(preHistory.Records[0].Reference.CID, genesisRecordCID) || !bytes.Equal(preHistory.Records[0].Raw, genesisInput.SnapshotRecord) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed accepted history differs before successor")
	}
	active, activePresent, err := store.ActiveAttempt(ctx)
	if err != nil || activePresent || active.ID != [16]byte{} {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed store already has an active attempt")
	}
	preAttempts, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	if err != nil || len(preAttempts.Attempts) != 1 || preAttempts.HasMore || preAttempts.NextID != genesisAttemptID || preAttempts.Attempts[0].ID != genesisAttemptID {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed finalized attempt history shape differs")
	}
	priorAttempt := preAttempts.Attempts[0]
	if priorAttempt.Kind != publicationstate.AttemptGenesis || priorAttempt.Lifecycle != publicationstate.AttemptRetiredSuccess || priorAttempt.Outcome != publicationstate.OutcomeCurrent || priorAttempt.Blocked != "" || priorAttempt.Sequence != 0 || priorAttempt.SnapshotKey != genesisInput.SnapshotKey || !bytes.Equal(priorAttempt.SnapshotRecordCID, genesisRecordCID) || !bytes.Equal(priorAttempt.HeadRecordCID, genesisHeadCID) || !bytes.Equal(priorAttempt.BlobCID, genesisBlobCID) || priorAttempt.BlobSize != uint64(len(genesisInput.Payload)) || priorAttempt.StateDigest != genesis.Attempt.StateDigest {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed finalized attempt history differs")
	}
	var genesisOutcomeEvidence []byte
	var genesisSubmissionEvidence []byte
	genesisOutcomeCount := 0
	genesisSubmissionCount := 0
	for _, evidence := range preAttempts.Evidence {
		if evidence.AttemptID != genesisAttemptID || len(evidence.Evidence) == 0 {
			return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed prior attempt evidence identity differs")
		}
		var projection attemptOutcomeReadback
		if json.Unmarshal(evidence.Evidence, &projection) != nil || projection.Version != 1 || len(projection.ViewDigest) != 32 {
			return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed prior attempt evidence is invalid")
		}
		switch evidence.Role {
		case "outcome":
			genesisOutcomeCount++
			if projection.Role != "outcome" || projection.Outcome != string(publicationstate.OutcomeCurrent) || projection.AttemptedKey != genesisInput.SnapshotKey || !bytes.Equal(projection.AttemptedRecord, genesisInput.SnapshotRecord) || len(projection.PredecessorRecord) != 0 || !bytes.Equal(projection.Head, genesisInput.HeadRecord) || len(projection.Suffix) != 1 || projection.Suffix[0].Key != genesisInput.SnapshotKey || !bytes.Equal(projection.Suffix[0].Raw, genesisInput.SnapshotRecord) {
				return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed prior outcome evidence differs")
			}
			genesisOutcomeEvidence = bytes.Clone(evidence.Evidence)
		case "submission":
			genesisSubmissionCount++
			if projection.Role != "submission" || projection.Outcome != string(publicationstate.OutcomeUnresolved) || projection.AttemptedKey != genesisInput.SnapshotKey || !bytes.Equal(projection.AttemptedRecord, genesisInput.SnapshotRecord) || len(projection.PredecessorRecord) != 0 || len(projection.Head) != 0 || len(projection.Suffix) != 0 {
				return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed prior submission evidence differs")
			}
			genesisSubmissionEvidence = bytes.Clone(evidence.Evidence)
		default:
			return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed prior attempt evidence role is unexpected")
		}
	}
	if genesisOutcomeCount != 1 || genesisSubmissionCount != 1 {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed prior attempt evidence roles are incomplete")
	}
	acceptedMaterial, err := store.ReadAcceptedMaterial(ctx, binding, genesisFloor)
	if err != nil || !reflect.DeepEqual(acceptedMaterial.Floor, genesisFloor) || !bytes.Equal(acceptedMaterial.SnapshotRecord, genesisInput.SnapshotRecord) || !bytes.Equal(acceptedMaterial.Payload, genesisInput.Payload) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed genesis accepted material differs before successor")
	}
	genesisMaterial, err := store.ReadCandidate(ctx, genesisAttemptID)
	if err != nil || genesisMaterial.AttemptID != genesisAttemptID || genesisMaterial.SnapshotKey != genesisInput.SnapshotKey || !bytes.Equal(genesisMaterial.SnapshotRecord, genesisInput.SnapshotRecord) || !bytes.Equal(genesisMaterial.HeadRecord, genesisInput.HeadRecord) || !bytes.Equal(genesisMaterial.Payload, genesisInput.Payload) || !bytes.Equal(genesisMaterial.Blob.CID, genesisBlobCID) || genesisMaterial.Blob.Size != uint64(len(genesisInput.Payload)) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed genesis retained candidate differs before successor")
	}

	proposal, err := store.PrepareAttempt(ctx, successorInput, predecessorView, review)
	if err != nil || proposal.AttemptID != successorAttemptID || proposal.Kind != publicationstate.AttemptSuccessor || proposal.CapturedFloor == nil || !reflect.DeepEqual(*proposal.CapturedFloor, genesisFloor) || proposal.CapturedGeneration != genesisFloor.Generation || !bytes.Equal(proposal.CandidateRecordCID, successorRecordCID) || !bytes.Equal(proposal.CandidateBlobCID, successorBlobCID) || proposal.CandidateBlobSize != uint64(len(successorInput.Payload)) || allZero(proposal.StateToken[:]) || allZero(proposal.CandidateDigest[:]) || allZero(proposal.Confirmation[:]) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor proposal differs")
	}
	created, err := store.CreateAttempt(ctx, proposal.StateToken, successorInput, predecessorView, review, proposal.Confirmation)
	if err != nil || created.ID != successorAttemptID || created.Kind != publicationstate.AttemptSuccessor || created.Lifecycle != publicationstate.AttemptPrepared || created.Outcome != publicationstate.OutcomeNotSubmitted || created.Blocked != "" || created.Sequence != 1 || created.SnapshotKey != successorKey || !bytes.Equal(created.SnapshotRecordCID, successorRecordCID) || !bytes.Equal(created.HeadRecordCID, successorHeadCID) || !bytes.Equal(created.BlobCID, successorBlobCID) || created.BlobSize != uint64(len(successorInput.Payload)) || created.CapturedFloor == nil || !reflect.DeepEqual(*created.CapturedFloor, genesisFloor) || created.CapturedRevision != genesisFloor.Revision || created.CapturedGeneration != genesisFloor.Generation || allZero(created.StateDigest[:]) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor creation differs")
	}

	uploadProposal, err := store.PrepareDispatch(ctx, successorAttemptID, publicationstate.DispatchUpload, predecessorView, review)
	if err != nil || uploadProposal.AttemptID != successorAttemptID || uploadProposal.Kind != publicationstate.DispatchUpload || allZero(uploadProposal.StateToken[:]) || allZero(uploadProposal.Confirmation[:]) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed upload proposal differs")
	}
	upload, err := store.BeginUpload(ctx, successorAttemptID, uploadProposal.StateToken, predecessorView, review, uploadProposal.Confirmation)
	if err != nil || upload.AttemptID != successorAttemptID || !bytes.Equal(upload.Payload, successorInput.Payload) || !bytes.Equal(upload.Blob.CID, successorBlobCID) || upload.Blob.Size != uint64(len(successorInput.Payload)) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed upload material differs")
	}
	uploadState, err := store.LoadAttempt(ctx, successorAttemptID)
	if err != nil || uploadState.ID != successorAttemptID || uploadState.Kind != publicationstate.AttemptSuccessor || uploadState.Lifecycle != publicationstate.AttemptUploadStarted || uploadState.Outcome != publicationstate.OutcomeNotSubmitted || uploadState.Blocked != "" || uploadState.Sequence != 1 || uploadState.SnapshotKey != successorKey || !bytes.Equal(uploadState.SnapshotRecordCID, successorRecordCID) || !bytes.Equal(uploadState.HeadRecordCID, successorHeadCID) || !bytes.Equal(uploadState.BlobCID, successorBlobCID) || uploadState.BlobSize != uint64(len(successorInput.Payload)) || allZero(uploadState.StateDigest[:]) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed upload state differs")
	}
	submissionProposal, err := store.PrepareDispatch(ctx, successorAttemptID, publicationstate.DispatchSubmission, predecessorView, review)
	if err != nil || submissionProposal.AttemptID != successorAttemptID || submissionProposal.Kind != publicationstate.DispatchSubmission || allZero(submissionProposal.StateToken[:]) || allZero(submissionProposal.Confirmation[:]) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed submission proposal differs")
	}
	submission, err := store.BeginSubmission(ctx, successorAttemptID, submissionProposal.StateToken, predecessorView, review, submissionProposal.Confirmation)
	if err != nil || submission.AttemptID != successorAttemptID || submission.SnapshotCollection != publication.SnapshotNSID || submission.SnapshotKey != successorKey || !bytes.Equal(submission.SnapshotRecord, successorInput.SnapshotRecord) || !bytes.Equal(submission.ExpectedSnapshotCID, successorRecordCID) || !submission.SnapshotCreateOnly || submission.HeadCollection != publication.HeadNSID || submission.HeadKey != "self" || !bytes.Equal(submission.HeadRecord, successorInput.HeadRecord) || submission.HeadCreate || !submission.RequiresAtomicBatch || !submission.RequiresCreateExclude || submission.RequiresPolicyCheck {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed submission material differs")
	}
	if submission.ExpectedPredecessor == nil || submission.ExpectedPredecessor.Key != genesisInput.SnapshotKey || !bytes.Equal(submission.ExpectedPredecessor.CID, genesisRecordCID) || submission.ExpectedPredecessor.Sequence != 0 || !reflect.DeepEqual(submission.ExpectedContext, predecessorView.SuppliedContext) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed submission predecessor differs")
	}
	submittedState, err := store.LoadAttempt(ctx, successorAttemptID)
	if err != nil || submittedState.ID != successorAttemptID || submittedState.Kind != publicationstate.AttemptSuccessor || submittedState.Lifecycle != publicationstate.AttemptMayHaveSubmitted || submittedState.Outcome != publicationstate.OutcomeUnresolved || submittedState.Blocked != "" || submittedState.Sequence != 1 || submittedState.SnapshotKey != successorKey || !bytes.Equal(submittedState.SnapshotRecordCID, successorRecordCID) || !bytes.Equal(submittedState.HeadRecordCID, successorHeadCID) || !bytes.Equal(submittedState.BlobCID, successorBlobCID) || submittedState.BlobSize != uint64(len(successorInput.Payload)) || submittedState.CapturedFloor == nil || !reflect.DeepEqual(*submittedState.CapturedFloor, genesisFloor) || allZero(submittedState.StateDigest[:]) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed submitted state differs")
	}
	firstResolution, err := store.ResolveAttempt(ctx, successorAttemptID, submittedState.StateDigest, firstConflictView)
	if err != nil || firstResolution.Outcome != publicationstate.OutcomeLostFence || firstResolution.Attempt.ID != successorAttemptID || firstResolution.Attempt.Kind != publicationstate.AttemptSuccessor || firstResolution.Attempt.Lifecycle != publicationstate.AttemptMayHaveSubmitted || firstResolution.Attempt.Outcome != publicationstate.OutcomeLostFence || firstResolution.Attempt.Blocked != "" || firstResolution.Attempt.Sequence != 1 || firstResolution.Attempt.SnapshotKey != successorKey || !bytes.Equal(firstResolution.Attempt.SnapshotRecordCID, successorRecordCID) || !bytes.Equal(firstResolution.Attempt.HeadRecordCID, successorHeadCID) || !bytes.Equal(firstResolution.Attempt.BlobCID, successorBlobCID) || firstResolution.Attempt.BlobSize != uint64(len(successorInput.Payload)) || allZero(firstResolution.Attempt.StateDigest[:]) || allZero(firstResolution.ViewDigest[:]) || len(firstResolution.Evidence) == 0 {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed first lost-fence resolution differs")
	}
	var firstOutcome attemptOutcomeReadback
	if json.Unmarshal(firstResolution.Evidence, &firstOutcome) != nil || firstOutcome.Version != 1 || firstOutcome.Role != "outcome" || firstOutcome.Outcome != string(publicationstate.OutcomeLostFence) || !bytes.Equal(firstOutcome.ViewDigest, firstResolution.ViewDigest[:]) || !bytes.Equal(firstOutcome.Head, firstConflictView.Head) || firstOutcome.AttemptedKey != successorKey || !bytes.Equal(firstOutcome.AttemptedRecord, firstConflictView.Snapshots[1].Raw) || !bytes.Equal(firstOutcome.PredecessorRecord, genesisInput.SnapshotRecord) || len(firstOutcome.Suffix) != 1 || firstOutcome.Suffix[0].Key != firstConflictView.Snapshots[1].Key || !bytes.Equal(firstOutcome.Suffix[0].Raw, firstConflictView.Snapshots[1].Raw) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed first outcome body differs")
	}
	firstConflict, firstConflictPresent, err := store.ReadFirstConflict(ctx, successorAttemptID)
	if err != nil || !firstConflictPresent || firstConflict.AttemptID != successorAttemptID || allZero(firstConflict.ID[:]) || len(firstConflict.Evidence) == 0 || !bytes.Equal(firstConflict.Head, firstConflictView.Head) || firstConflict.HeadKey != firstConflictView.Snapshots[1].Key || !bytes.Equal(firstConflict.HeadRecord, firstConflictView.Snapshots[1].Raw) || firstConflict.HeadSequence != 1 || bytes.Equal(firstConflict.Evidence, firstResolution.Evidence) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed first-conflict readback differs")
	}
	refreshedState, err := store.LoadAttempt(ctx, successorAttemptID)
	if err != nil || refreshedState.ID != successorAttemptID || refreshedState.Lifecycle != publicationstate.AttemptMayHaveSubmitted || refreshedState.Outcome != publicationstate.OutcomeLostFence || refreshedState.Blocked != "" || refreshedState.StateDigest != firstResolution.Attempt.StateDigest || allZero(refreshedState.StateDigest[:]) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed first-conflict state refresh differs")
	}
	latestResolution, err := store.ResolveAttempt(ctx, successorAttemptID, refreshedState.StateDigest, extendedView)
	if err != nil || latestResolution.Outcome != publicationstate.OutcomeLostFence || latestResolution.Attempt.ID != successorAttemptID || latestResolution.Attempt.Kind != publicationstate.AttemptSuccessor || latestResolution.Attempt.Lifecycle != publicationstate.AttemptMayHaveSubmitted || latestResolution.Attempt.Outcome != publicationstate.OutcomeLostFence || latestResolution.Attempt.Blocked != "" || latestResolution.Attempt.Sequence != 1 || latestResolution.Attempt.SnapshotKey != successorKey || !bytes.Equal(latestResolution.Attempt.SnapshotRecordCID, successorRecordCID) || !bytes.Equal(latestResolution.Attempt.HeadRecordCID, successorHeadCID) || !bytes.Equal(latestResolution.Attempt.BlobCID, successorBlobCID) || latestResolution.Attempt.BlobSize != uint64(len(successorInput.Payload)) || allZero(latestResolution.Attempt.StateDigest[:]) || allZero(latestResolution.ViewDigest[:]) || latestResolution.ViewDigest == firstResolution.ViewDigest || latestResolution.Attempt.StateDigest == firstResolution.Attempt.StateDigest || len(latestResolution.Evidence) == 0 || bytes.Equal(latestResolution.Evidence, firstResolution.Evidence) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed extended lost-fence resolution differs")
	}
	var latestOutcome attemptOutcomeReadback
	if json.Unmarshal(latestResolution.Evidence, &latestOutcome) != nil || latestOutcome.Version != 1 || latestOutcome.Role != "outcome" || latestOutcome.Outcome != string(publicationstate.OutcomeLostFence) || !bytes.Equal(latestOutcome.ViewDigest, latestResolution.ViewDigest[:]) || !bytes.Equal(latestOutcome.Head, extendedView.Head) || latestOutcome.AttemptedKey != successorKey || !bytes.Equal(latestOutcome.AttemptedRecord, firstConflictView.Snapshots[1].Raw) || !bytes.Equal(latestOutcome.PredecessorRecord, genesisInput.SnapshotRecord) || len(latestOutcome.Suffix) != 2 || latestOutcome.Suffix[0].Key != firstConflictView.Snapshots[1].Key || !bytes.Equal(latestOutcome.Suffix[0].Raw, firstConflictView.Snapshots[1].Raw) || latestOutcome.Suffix[1].Key != extendedView.Snapshots[2].Key || !bytes.Equal(latestOutcome.Suffix[1].Raw, extendedView.Snapshots[2].Raw) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed extended outcome body differs")
	}
	conflictAfter, conflictAfterPresent, err := store.ReadFirstConflict(ctx, successorAttemptID)
	if err != nil || !conflictAfterPresent || conflictAfter.AttemptID != firstConflict.AttemptID || conflictAfter.ID != firstConflict.ID || !bytes.Equal(conflictAfter.Evidence, firstConflict.Evidence) || !bytes.Equal(conflictAfter.Head, firstConflict.Head) || conflictAfter.HeadKey != firstConflict.HeadKey || !bytes.Equal(conflictAfter.HeadRecord, firstConflict.HeadRecord) || conflictAfter.HeadSequence != firstConflict.HeadSequence {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed first-conflict evidence changed after extension")
	}
	latestState, err := store.LoadAttempt(ctx, successorAttemptID)
	if err != nil || latestState.ID != successorAttemptID || latestState.Kind != publicationstate.AttemptSuccessor || latestState.Lifecycle != publicationstate.AttemptMayHaveSubmitted || latestState.Outcome != publicationstate.OutcomeLostFence || latestState.Blocked != "" || latestState.Sequence != 1 || latestState.SnapshotKey != successorKey || !bytes.Equal(latestState.SnapshotRecordCID, successorRecordCID) || !bytes.Equal(latestState.HeadRecordCID, successorHeadCID) || !bytes.Equal(latestState.BlobCID, successorBlobCID) || latestState.BlobSize != uint64(len(successorInput.Payload)) || latestState.StateDigest != latestResolution.Attempt.StateDigest {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed latest successor state differs")
	}
	latestActive, latestActivePresent, err := store.ActiveAttempt(ctx)
	if err != nil || !latestActivePresent || latestActive.ID != successorAttemptID || latestActive.Kind != publicationstate.AttemptSuccessor || latestActive.Lifecycle != publicationstate.AttemptMayHaveSubmitted || latestActive.Outcome != publicationstate.OutcomeLostFence || latestActive.Blocked != "" || latestActive.Sequence != 1 || latestActive.SnapshotKey != successorKey || !bytes.Equal(latestActive.SnapshotRecordCID, successorRecordCID) || !bytes.Equal(latestActive.BlobCID, successorBlobCID) || latestActive.StateDigest != latestState.StateDigest {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed submitted successor is not active")
	}
	latestAttempts, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	if err != nil || len(latestAttempts.Attempts) != 2 || latestAttempts.HasMore || latestAttempts.NextID != successorAttemptID || latestAttempts.Attempts[0].ID != genesisAttemptID || latestAttempts.Attempts[1].ID != successorAttemptID {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed attempt history page differs")
	}
	if latestAttempts.Attempts[0].Lifecycle != publicationstate.AttemptRetiredSuccess || latestAttempts.Attempts[0].Outcome != publicationstate.OutcomeCurrent || latestAttempts.Attempts[0].StateDigest != genesis.Attempt.StateDigest || latestAttempts.Attempts[1].Lifecycle != publicationstate.AttemptMayHaveSubmitted || latestAttempts.Attempts[1].Outcome != publicationstate.OutcomeLostFence || latestAttempts.Attempts[1].Blocked != "" || latestAttempts.Attempts[1].Sequence != 1 || latestAttempts.Attempts[1].SnapshotKey != successorKey || !bytes.Equal(latestAttempts.Attempts[1].SnapshotRecordCID, successorRecordCID) || !bytes.Equal(latestAttempts.Attempts[1].HeadRecordCID, successorHeadCID) || !bytes.Equal(latestAttempts.Attempts[1].BlobCID, successorBlobCID) || latestAttempts.Attempts[1].BlobSize != uint64(len(successorInput.Payload)) || latestAttempts.Attempts[1].StateDigest != latestState.StateDigest {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed attempt history entries differ")
	}
	genesisOutcomeAfterCount := 0
	genesisSubmissionAfterCount := 0
	successorConflictCount := 0
	successorOutcomeCount := 0
	successorSubmissionCount := 0
	for _, evidence := range latestAttempts.Evidence {
		if len(evidence.Evidence) == 0 {
			return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed attempt history evidence is empty")
		}
		var projection attemptOutcomeReadback
		if evidence.AttemptID == genesisAttemptID || (evidence.AttemptID == successorAttemptID && evidence.Role != "first-conflict") {
			if json.Unmarshal(evidence.Evidence, &projection) != nil || projection.Version != 1 || len(projection.ViewDigest) != 32 {
				return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed attempt history evidence is invalid")
			}
		}
		switch evidence.AttemptID {
		case genesisAttemptID:
			switch evidence.Role {
			case "outcome":
				genesisOutcomeAfterCount++
				if projection.Role != "outcome" || projection.Outcome != string(publicationstate.OutcomeCurrent) || !bytes.Equal(evidence.Evidence, genesisOutcomeEvidence) {
					return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed genesis outcome history changed")
				}
			case "submission":
				genesisSubmissionAfterCount++
				if projection.Role != "submission" || projection.Outcome != string(publicationstate.OutcomeUnresolved) || !bytes.Equal(evidence.Evidence, genesisSubmissionEvidence) {
					return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed genesis submission history changed")
				}
			default:
				return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed genesis history role is unexpected")
			}
		case successorAttemptID:
			switch evidence.Role {
			case "first-conflict":
				successorConflictCount++
				if evidence.AttemptID != firstConflict.AttemptID || !bytes.Equal(evidence.Evidence, firstConflict.Evidence) {
					return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed first-conflict history role differs")
				}
			case "outcome":
				successorOutcomeCount++
				if projection.Role != "outcome" || projection.Outcome != string(publicationstate.OutcomeLostFence) || !bytes.Equal(evidence.Evidence, latestResolution.Evidence) {
					return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed latest outcome history role differs")
				}
			case "submission":
				successorSubmissionCount++
				if projection.Role != "submission" || projection.Outcome != string(publicationstate.OutcomeUnresolved) || projection.AttemptedKey != successorKey || !bytes.Equal(projection.AttemptedRecord, successorInput.SnapshotRecord) || !bytes.Equal(projection.PredecessorRecord, genesisInput.SnapshotRecord) || !bytes.Equal(projection.Head, predecessorView.Head) || len(projection.Suffix) != 0 {
					return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor submission history differs")
				}
			default:
				return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed successor history role is unexpected")
			}
		default:
			return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed attempt history identity is unexpected")
		}
	}
	if genesisOutcomeAfterCount != 1 || genesisSubmissionAfterCount != 1 || successorConflictCount != 1 || successorOutcomeCount != 1 || successorSubmissionCount != 1 {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed attempt history roles are incomplete")
	}
	successorMaterial, err := store.ReadCandidate(ctx, successorAttemptID)
	if err != nil || successorMaterial.AttemptID != successorAttemptID || successorMaterial.SnapshotKey != successorKey || !bytes.Equal(successorMaterial.SnapshotRecord, successorInput.SnapshotRecord) || !bytes.Equal(successorMaterial.HeadRecord, successorInput.HeadRecord) || !bytes.Equal(successorMaterial.Payload, successorInput.Payload) || !bytes.Equal(successorMaterial.Blob.CID, successorBlobCID) || successorMaterial.Blob.Size != uint64(len(successorInput.Payload)) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed active successor candidate differs")
	}
	postFloor, postFloorPresent, err := store.Load(ctx)
	if err != nil || !postFloorPresent || !reflect.DeepEqual(postFloor, preFloor) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed accepted floor changed during successor lifecycle")
	}
	postHistory, err := store.History(ctx, 0, 10)
	if err != nil || len(postHistory.Events) != 1 || len(postHistory.Records) != 1 || postHistory.HasMore || postHistory.NextRevision != 1 || !reflect.DeepEqual(postHistory, preHistory) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed accepted history changed during successor lifecycle")
	}
	currentMaterial, err := store.ReadAcceptedMaterial(ctx, binding, preFloor)
	if err != nil || !reflect.DeepEqual(currentMaterial.Floor, preFloor) || !bytes.Equal(currentMaterial.SnapshotRecord, genesisInput.SnapshotRecord) || !bytes.Equal(currentMaterial.Payload, genesisInput.Payload) {
		return publicationstate.AttemptResolution{}, publicationstate.FirstConflictEvidence{}, errors.New("mixed current genesis material changed during successor lifecycle")
	}
	return latestResolution, firstConflict, nil
}

func replaceFloorThenRetireLostFence(ctx context.Context, store *publicationstate.Store, binding publicationstate.Binding, genesis publicationstate.Finalization, genesisInput publicationstate.CandidateInput, genesisMetadata candidateValue, priorLatest publicationstate.AttemptResolution, priorLatestView publicationstate.SuppliedRepositoryView, firstConflict publicationstate.FirstConflictEvidence, replacementInput publicationstate.CandidateInput, replacementMetadata candidateValue, replacementObservation publicationstate.Observation, retirementView publicationstate.SuppliedRepositoryView) (publicationstate.Floor, publicationstate.Attempt, publicationstate.FirstConflictEvidence, publicationstate.AttemptPage, error) {
	if ctx == nil || store == nil {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement inputs are invalid")
	}
	if ctx.Err() != nil {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement context is invalid")
	}
	if binding.Backend != publicationstate.BackendPublicRepo || genesis.Attempt.CapturedFloor != nil || len(priorLatestView.Snapshots) != 3 || len(replacementObservation.Snapshots) != 1 || len(retirementView.Snapshots) != 4 {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement shape is invalid")
	}
	if priorLatestView.Origin != binding || replacementObservation.Origin != binding || retirementView.Origin != binding || priorLatestView.Scope != publicationstate.ViewScopeWholeRepository || retirementView.Scope != publicationstate.ViewScopeWholeRepository || len(priorLatestView.Head) == 0 || len(replacementObservation.Head) == 0 || len(retirementView.Head) == 0 {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement binding is invalid")
	}
	if len(genesisInput.SnapshotRecord) == 0 || len(genesisInput.SnapshotRecord) > publication.MaxRecordBytes || len(genesisInput.HeadRecord) == 0 || len(genesisInput.HeadRecord) > publication.MaxRecordBytes || len(genesisInput.Payload) == 0 || uint64(len(genesisInput.Payload)) > publication.MaxBlobBytes || (genesisMetadata.AttemptID != "" && genesisMetadata.AttemptID != hex.EncodeToString(genesis.Attempt.ID[:])) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement genesis metadata differs")
	}
	if !reflect.DeepEqual(encodeBytes(genesisInput.SnapshotRecord), genesisMetadata.SnapshotRecord) || !reflect.DeepEqual(encodeBytes(genesisInput.HeadRecord), genesisMetadata.HeadRecord) || !reflect.DeepEqual(encodeBytes(genesisInput.Payload), genesisMetadata.Payload) || genesisMetadata.SnapshotKey != genesisInput.SnapshotKey || genesisMetadata.BlobSize != uint64(len(genesisInput.Payload)) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement genesis bytes differ")
	}
	if err := validateCandidate(genesisInput, binding, genesisMetadata); err != nil {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement genesis candidate is invalid")
	}
	genesisRecord, err := publication.DecodeSnapshot(genesisInput.SnapshotRecord)
	if err != nil || genesisRecord.PublicationSeq != 0 || len(genesisRecord.Parent) != 0 {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement genesis record is invalid")
	}
	genesisRecordCID, err := publication.RecordCID(genesisInput.SnapshotRecord)
	if err != nil || !reflect.DeepEqual(encodeBytes(genesisRecordCID), genesisMetadata.SnapshotCID) || !bytes.Equal(genesisRecordCID, genesis.Floor.RecordCID) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement genesis record identifier differs")
	}
	genesisHeadCID, err := publication.RecordCID(genesisInput.HeadRecord)
	if err != nil || !reflect.DeepEqual(encodeBytes(genesisHeadCID), genesisMetadata.HeadCID) || !bytes.Equal(genesisHeadCID, genesis.Attempt.HeadRecordCID) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement genesis head identifier differs")
	}
	genesisBlobCID, err := publication.RawPayloadCID(genesisInput.Payload)
	if err != nil || !reflect.DeepEqual(encodeBytes(genesisBlobCID), genesisMetadata.BlobCID) || !bytes.Equal(genesisBlobCID, genesis.Floor.BlobCID) || !bytes.Equal(genesisBlobCID, genesis.Attempt.BlobCID) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement genesis payload identifier differs")
	}
	genesisPublicationID, err := hex.DecodeString(genesisMetadata.PublicationID)
	if err != nil || len(genesisPublicationID) != 16 || allZero(genesisPublicationID) || !bytes.Equal(genesisPublicationID, genesisRecord.PublicationID[:]) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement genesis publication identifier differs")
	}
	var genesisAttemptID [16]byte
	copy(genesisAttemptID[:], genesisPublicationID)
	genesisFloor := genesis.Floor
	if genesis.Attempt.ID != genesisAttemptID || genesis.Attempt.Kind != publicationstate.AttemptGenesis || genesis.Attempt.Lifecycle != publicationstate.AttemptRetiredSuccess || genesis.Attempt.Outcome != publicationstate.OutcomeCurrent || genesis.Attempt.Blocked != "" || genesis.Attempt.Sequence != 0 || genesis.Attempt.CapturedRevision != 0 || genesis.Attempt.CapturedGeneration != 0 || genesis.Attempt.SnapshotKey != genesisInput.SnapshotKey || !bytes.Equal(genesis.Attempt.SnapshotRecordCID, genesisRecordCID) || !bytes.Equal(genesis.Attempt.HeadRecordCID, genesisHeadCID) || !bytes.Equal(genesis.Attempt.BlobCID, genesisBlobCID) || genesis.Attempt.BlobSize != uint64(len(genesisInput.Payload)) || allZero(genesis.Attempt.StateDigest[:]) || allZero(genesisFloor.DatabaseID[:]) || genesisFloor.Revision != 1 || genesisFloor.Generation != 1 || genesisFloor.Provenance != publicationstate.ProvenanceFirst || genesisFloor.Binding != binding || !bytes.Equal(genesisFloor.AnchorCID, genesisRecordCID) || !bytes.Equal(genesisFloor.Head, genesisInput.HeadRecord) || genesisFloor.SnapshotKey != genesisInput.SnapshotKey || genesisFloor.Sequence != 0 || genesisFloor.PublicationID != genesisAttemptID || !bytes.Equal(genesisFloor.RecordCID, genesisRecordCID) || !bytes.Equal(genesisFloor.BlobCID, genesisBlobCID) || genesisFloor.BlobSize != uint64(len(genesisInput.Payload)) || allZero(genesisFloor.ObservationDigest[:]) || allZero(genesisFloor.AcceptedEventDigest[:]) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement finalized genesis differs")
	}
	if len(replacementInput.SnapshotRecord) == 0 || len(replacementInput.SnapshotRecord) > publication.MaxRecordBytes || len(replacementInput.HeadRecord) == 0 || len(replacementInput.HeadRecord) > publication.MaxRecordBytes || len(replacementInput.Payload) == 0 || uint64(len(replacementInput.Payload)) > publication.MaxBlobBytes || replacementMetadata.AttemptID != "" || replacementMetadata.SnapshotKey != replacementInput.SnapshotKey || !reflect.DeepEqual(encodeBytes(replacementInput.SnapshotRecord), replacementMetadata.SnapshotRecord) || !reflect.DeepEqual(encodeBytes(replacementInput.HeadRecord), replacementMetadata.HeadRecord) || !reflect.DeepEqual(encodeBytes(replacementInput.Payload), replacementMetadata.Payload) || replacementMetadata.BlobSize != uint64(len(replacementInput.Payload)) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement fork metadata differs")
	}
	if err := validateCandidate(replacementInput, binding, replacementMetadata); err != nil {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement fork candidate is invalid")
	}
	forkRecord, err := publication.DecodeSnapshot(replacementInput.SnapshotRecord)
	if err != nil || forkRecord.Vault != binding.Vault || forkRecord.PublicationSeq != 0 || len(forkRecord.Parent) != 0 || allZero(forkRecord.PublicationID[:]) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement fork record is invalid")
	}
	forkRecordCID, err := publication.RecordCID(replacementInput.SnapshotRecord)
	if err != nil || !reflect.DeepEqual(encodeBytes(forkRecordCID), replacementMetadata.SnapshotCID) || bytes.Equal(forkRecordCID, genesisRecordCID) || bytes.Equal(forkRecord.PublicationID[:], genesisAttemptID[:]) || bytes.Equal(forkRecord.PublicationID[:], priorLatest.Attempt.ID[:]) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement fork is not a distinct same-position fork")
	}
	forkHeadCID, err := publication.RecordCID(replacementInput.HeadRecord)
	if err != nil || !reflect.DeepEqual(encodeBytes(forkHeadCID), replacementMetadata.HeadCID) || bytes.Equal(forkHeadCID, genesisHeadCID) || publication.VerifyHeadBinding(replacementInput.HeadRecord, replacementInput.SnapshotRecord, replacementInput.SnapshotKey) != nil {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement fork head is invalid")
	}
	forkBlobCID, err := publication.RawPayloadCID(replacementInput.Payload)
	if err != nil || !reflect.DeepEqual(encodeBytes(forkBlobCID), replacementMetadata.BlobCID) || bytes.Equal(forkBlobCID, genesisBlobCID) || bytes.Equal(replacementInput.Payload, genesisInput.Payload) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement fork payload is not distinct")
	}
	if replacementObservation.Head == nil || !bytes.Equal(replacementObservation.Head, replacementInput.HeadRecord) || replacementObservation.Snapshots[0].Key != replacementInput.SnapshotKey || !bytes.Equal(replacementObservation.Snapshots[0].Raw, replacementInput.SnapshotRecord) || replacementObservation.SuppliedContext.Policy != nil {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement observation differs from fork")
	}
	contexts := []publicationstate.SuppliedContext{genesisFloor.SuppliedContext, priorLatestView.SuppliedContext, replacementObservation.SuppliedContext, retirementView.SuppliedContext}
	for _, supplied := range contexts {
		if len(supplied.RepositoryRevision) == 0 || len(supplied.RepositoryRevision) > 1024 || strings.ToValidUTF8(supplied.RepositoryRevision, "") != supplied.RepositoryRevision || len(supplied.RepositoryDigest) == 0 || len(supplied.RepositoryDigest) > 128 || allZero(supplied.RepositoryDigest) || supplied.Policy != nil {
			return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement context is invalid")
		}
	}
	for left := range contexts {
		for right := left + 1; right < len(contexts); right++ {
			if contexts[left].RepositoryRevision == contexts[right].RepositoryRevision || bytes.Equal(contexts[left].RepositoryDigest, contexts[right].RepositoryDigest) {
				return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement contexts are not distinct")
			}
		}
	}
	successorKey, keyErr := publication.SequenceKey(1)
	if keyErr != nil || len(priorLatest.Evidence) == 0 || uint64(len(priorLatest.Evidence)) > publicationstate.DefaultAttemptLimits().EvidenceSlotBytes || len(firstConflict.Evidence) > int(publicationstate.DefaultAttemptLimits().EvidenceSlotBytes) || allZero(priorLatest.ViewDigest[:]) || priorLatest.Outcome != publicationstate.OutcomeLostFence || priorLatest.Attempt.Kind != publicationstate.AttemptSuccessor || priorLatest.Attempt.Lifecycle != publicationstate.AttemptMayHaveSubmitted || priorLatest.Attempt.Outcome != publicationstate.OutcomeLostFence || priorLatest.Attempt.Blocked != "" || priorLatest.Attempt.Sequence != 1 || priorLatest.Attempt.SnapshotKey != successorKey || priorLatest.Attempt.CapturedFloor == nil || !reflect.DeepEqual(*priorLatest.Attempt.CapturedFloor, genesisFloor) || priorLatest.Attempt.CapturedRevision != genesisFloor.Revision || priorLatest.Attempt.CapturedGeneration != genesisFloor.Generation || allZero(priorLatest.Attempt.StateDigest[:]) || priorLatest.Attempt.ID == genesisAttemptID || priorLatest.Attempt.SnapshotKey == genesisInput.SnapshotKey || !bytes.Equal(priorLatest.Attempt.CapturedFloor.RecordCID, genesisRecordCID) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement prior latest identity is invalid")
	}
	successorID := priorLatest.Attempt.ID
	if allZero(successorID[:]) || firstConflict.AttemptID != successorID || allZero(firstConflict.ID[:]) || len(firstConflict.Evidence) == 0 || len(firstConflict.Head) == 0 || len(firstConflict.Head) > publication.MaxRecordBytes || len(firstConflict.HeadRecord) == 0 || len(firstConflict.HeadRecord) > publication.MaxRecordBytes || firstConflict.HeadSequence != 1 {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement first-conflict input is invalid")
	}
	savedPriorLatestEvidence := bytes.Clone(priorLatest.Evidence)
	savedFirstConflict := firstConflict
	savedFirstConflict.Evidence = bytes.Clone(firstConflict.Evidence)
	savedFirstConflict.Head = bytes.Clone(firstConflict.Head)
	savedFirstConflict.HeadRecord = bytes.Clone(firstConflict.HeadRecord)
	if bytes.Equal(savedPriorLatestEvidence, savedFirstConflict.Evidence) || priorLatestView.Snapshots[0].Key != genesisInput.SnapshotKey || !bytes.Equal(priorLatestView.Snapshots[0].Raw, genesisInput.SnapshotRecord) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement chronology inputs are invalid")
	}
	priorRecords := make([]publication.SnapshotRecord, 0, len(priorLatestView.Snapshots))
	priorCIDs := make([][]byte, 0, len(priorLatestView.Snapshots))
	for index, block := range priorLatestView.Snapshots {
		if len(block.Raw) == 0 || len(block.Raw) > publication.MaxRecordBytes {
			return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement prior record exceeds its bound")
		}
		key, err := publication.SequenceKey(uint64(index))
		if err != nil || block.Key != key {
			return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement prior key differs")
		}
		record, err := publication.DecodeSnapshot(block.Raw)
		if err != nil || record.Vault != binding.Vault || record.PublicationSeq != uint64(index) || allZero(record.PublicationID[:]) {
			return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement prior record is invalid")
		}
		if index == 0 {
			if len(record.Parent) != 0 || !bytes.Equal(block.Raw, genesisInput.SnapshotRecord) {
				return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement prior genesis differs")
			}
		} else if err := publication.VerifySuccessor(priorLatestView.Snapshots[index-1].Raw, block.Raw, block.Key); err != nil {
			return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement prior lineage is invalid")
		}
		cid, err := publication.RecordCID(block.Raw)
		if err != nil {
			return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement prior record identifier is invalid")
		}
		priorRecords = append(priorRecords, record)
		priorCIDs = append(priorCIDs, cid)
	}
	if len(priorLatestView.Head) == 0 || len(priorLatestView.Head) > publication.MaxRecordBytes {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement prior head exceeds its bound")
	}
	priorHead, err := publication.DecodeHead(priorLatestView.Head)
	if err != nil || priorHead.Vault != binding.Vault || priorHead.PublicationSeq != 2 || !bytes.Equal(priorHead.SnapshotCID, priorCIDs[2]) || !bytes.Equal(priorHead.BlobCID, priorRecords[2].Blob.CID) || publication.VerifyHeadBinding(priorLatestView.Head, priorLatestView.Snapshots[2].Raw, priorLatestView.Snapshots[2].Key) != nil {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement prior head binding is invalid")
	}
	var priorContextProjection struct {
		Context *publicationstate.SuppliedContext `json:"context"`
	}
	if json.Unmarshal(savedPriorLatestEvidence, &priorContextProjection) != nil || priorContextProjection.Context == nil || !reflect.DeepEqual(*priorContextProjection.Context, priorLatestView.SuppliedContext) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement prior outcome context differs")
	}
	var priorOutcome attemptOutcomeReadback
	if json.Unmarshal(savedPriorLatestEvidence, &priorOutcome) != nil || priorOutcome.Version != 1 || priorOutcome.Role != "outcome" || priorOutcome.Outcome != string(publicationstate.OutcomeLostFence) || !bytes.Equal(priorOutcome.ViewDigest, priorLatest.ViewDigest[:]) || !bytes.Equal(priorOutcome.Head, priorLatestView.Head) || priorOutcome.AttemptedKey != priorLatestView.Snapshots[1].Key || !bytes.Equal(priorOutcome.AttemptedRecord, priorLatestView.Snapshots[1].Raw) || !bytes.Equal(priorOutcome.PredecessorRecord, genesisInput.SnapshotRecord) || len(priorOutcome.Suffix) != 2 || priorOutcome.Suffix[0].Key != priorLatestView.Snapshots[1].Key || !bytes.Equal(priorOutcome.Suffix[0].Raw, priorLatestView.Snapshots[1].Raw) || priorOutcome.Suffix[1].Key != priorLatestView.Snapshots[2].Key || !bytes.Equal(priorOutcome.Suffix[1].Raw, priorLatestView.Snapshots[2].Raw) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement prior outcome differs")
	}
	if !bytes.Equal(firstConflict.HeadRecord, priorLatestView.Snapshots[1].Raw) || firstConflict.HeadKey != priorLatestView.Snapshots[1].Key {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement first-conflict occupant differs")
	}
	firstHead, err := publication.DecodeHead(firstConflict.Head)
	if err != nil || firstHead.Vault != binding.Vault || firstHead.PublicationSeq != 1 || !bytes.Equal(firstHead.SnapshotCID, priorCIDs[1]) || !bytes.Equal(firstHead.BlobCID, priorRecords[1].Blob.CID) || publication.VerifyHeadBinding(firstConflict.Head, firstConflict.HeadRecord, firstConflict.HeadKey) != nil {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement first-conflict head is invalid")
	}
	retirementRecords := make([]publication.SnapshotRecord, 0, len(retirementView.Snapshots))
	retirementCIDs := make([][]byte, 0, len(retirementView.Snapshots))
	for index, block := range retirementView.Snapshots {
		if len(block.Raw) == 0 || len(block.Raw) > publication.MaxRecordBytes {
			return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement fresh record exceeds its bound")
		}
		key, err := publication.SequenceKey(uint64(index))
		if err != nil || block.Key != key {
			return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement fresh key differs")
		}
		record, err := publication.DecodeSnapshot(block.Raw)
		if err != nil || record.Vault != binding.Vault || record.PublicationSeq != uint64(index) || allZero(record.PublicationID[:]) {
			return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement fresh record is invalid")
		}
		if index == 0 {
			if len(record.Parent) != 0 || !bytes.Equal(block.Raw, genesisInput.SnapshotRecord) {
				return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement fresh genesis differs")
			}
		} else if err := publication.VerifySuccessor(retirementView.Snapshots[index-1].Raw, block.Raw, block.Key); err != nil {
			return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement fresh lineage is invalid")
		}
		cid, err := publication.RecordCID(block.Raw)
		if err != nil {
			return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement fresh record identifier is invalid")
		}
		retirementRecords = append(retirementRecords, record)
		retirementCIDs = append(retirementCIDs, cid)
	}
	if len(retirementView.Head) > publication.MaxRecordBytes {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement fresh head exceeds its bound")
	}
	for index := range priorLatestView.Snapshots {
		if priorLatestView.Snapshots[index].Key != retirementView.Snapshots[index].Key || !bytes.Equal(priorLatestView.Snapshots[index].Raw, retirementView.Snapshots[index].Raw) {
			return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement fresh suffix does not preserve prior bytes")
		}
	}
	retirementHead, err := publication.DecodeHead(retirementView.Head)
	if err != nil || retirementHead.Vault != binding.Vault || retirementHead.PublicationSeq != 3 || !bytes.Equal(retirementHead.SnapshotCID, retirementCIDs[3]) || !bytes.Equal(retirementHead.BlobCID, retirementRecords[3].Blob.CID) || publication.VerifyHeadBinding(retirementView.Head, retirementView.Snapshots[3].Raw, retirementView.Snapshots[3].Key) != nil || bytes.Equal(retirementView.Head, priorLatestView.Head) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement fresh head binding is invalid")
	}
	if bytes.Equal(retirementRecords[3].PublicationID[:], retirementRecords[1].PublicationID[:]) || bytes.Equal(retirementRecords[3].PublicationID[:], retirementRecords[2].PublicationID[:]) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement fresh successor identity is not distinct")
	}

	currentFloor, currentPresent, err := store.Load(ctx)
	if err != nil || !currentPresent || !reflect.DeepEqual(currentFloor, genesisFloor) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement current genesis floor differs")
	}
	positionHistory, err := store.History(ctx, 0, 10)
	if err != nil || len(positionHistory.Events) != 1 || len(positionHistory.Records) != 1 || positionHistory.HasMore || positionHistory.NextRevision != 1 {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement initial history shape differs")
	}
	initialEvent := positionHistory.Events[0]
	if initialEvent.Revision != 1 || initialEvent.Mode != publicationstate.ModeFirstUse || initialEvent.Reason != "" || initialEvent.Stop != "first_use" || initialEvent.OldFloor != nil || !reflect.DeepEqual(initialEvent.NewFloor, genesisFloor) || initialEvent.EventDigest != genesisFloor.AcceptedEventDigest || initialEvent.ObservationDigest != genesisFloor.ObservationDigest || len(initialEvent.Trace) != 1 || initialEvent.Trace[0].Key != genesisInput.SnapshotKey || initialEvent.Trace[0].Sequence != 0 || !bytes.Equal(initialEvent.Trace[0].CID, genesisRecordCID) || positionHistory.Records[0].Reference.Key != genesisInput.SnapshotKey || positionHistory.Records[0].Reference.Sequence != 0 || !bytes.Equal(positionHistory.Records[0].Reference.CID, genesisRecordCID) || !bytes.Equal(positionHistory.Records[0].Raw, genesisInput.SnapshotRecord) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement initial history evidence differs")
	}
	genesisState, err := store.LoadAttempt(ctx, genesisAttemptID)
	if err != nil || genesisState.ID != genesisAttemptID || genesisState.Kind != publicationstate.AttemptGenesis || genesisState.Lifecycle != publicationstate.AttemptRetiredSuccess || genesisState.Outcome != publicationstate.OutcomeCurrent || genesisState.Blocked != "" || genesisState.StateDigest != genesis.Attempt.StateDigest || !bytes.Equal(genesisState.SnapshotRecordCID, genesisRecordCID) || !bytes.Equal(genesisState.BlobCID, genesisBlobCID) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement finalized genesis state differs")
	}
	genesisMaterial, err := store.ReadCandidate(ctx, genesisAttemptID)
	if err != nil || genesisMaterial.AttemptID != genesisAttemptID || genesisMaterial.SnapshotKey != genesisInput.SnapshotKey || !bytes.Equal(genesisMaterial.SnapshotRecord, genesisInput.SnapshotRecord) || !bytes.Equal(genesisMaterial.HeadRecord, genesisInput.HeadRecord) || !bytes.Equal(genesisMaterial.Payload, genesisInput.Payload) || !bytes.Equal(genesisMaterial.Blob.CID, genesisBlobCID) || genesisMaterial.Blob.Size != uint64(len(genesisInput.Payload)) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement retained genesis material differs")
	}
	acceptedMaterial, err := store.ReadAcceptedMaterial(ctx, binding, genesisFloor)
	if err != nil || !reflect.DeepEqual(acceptedMaterial.Floor, genesisFloor) || !bytes.Equal(acceptedMaterial.SnapshotRecord, genesisInput.SnapshotRecord) || !bytes.Equal(acceptedMaterial.Payload, genesisInput.Payload) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement current genesis material differs")
	}
	priorState, err := store.LoadAttempt(ctx, successorID)
	if err != nil || priorState.ID != successorID || priorState.Kind != publicationstate.AttemptSuccessor || priorState.Lifecycle != publicationstate.AttemptMayHaveSubmitted || priorState.Outcome != publicationstate.OutcomeLostFence || priorState.Blocked != "" || priorState.Sequence != 1 || priorState.SnapshotKey != priorLatest.Attempt.SnapshotKey || priorState.StateDigest != priorLatest.Attempt.StateDigest || priorState.CapturedFloor == nil || !reflect.DeepEqual(*priorState.CapturedFloor, genesisFloor) || priorState.CapturedRevision != genesisFloor.Revision || priorState.CapturedGeneration != genesisFloor.Generation || !bytes.Equal(priorState.SnapshotRecordCID, priorLatest.Attempt.SnapshotRecordCID) || !bytes.Equal(priorState.HeadRecordCID, priorLatest.Attempt.HeadRecordCID) || !bytes.Equal(priorState.BlobCID, priorLatest.Attempt.BlobCID) || priorState.BlobSize == 0 || allZero(priorState.StateDigest[:]) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement submitted attempt state differs")
	}
	active, activePresent, err := store.ActiveAttempt(ctx)
	if err != nil || !activePresent || active.ID != successorID || active.Lifecycle != publicationstate.AttemptMayHaveSubmitted || active.Outcome != publicationstate.OutcomeLostFence || active.Blocked != "" || active.StateDigest != priorState.StateDigest {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement submitted attempt is not active")
	}
	attemptPage, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	if err != nil || len(attemptPage.Attempts) != 2 || attemptPage.HasMore || attemptPage.NextID != successorID || attemptPage.Attempts[0].ID != genesisAttemptID || attemptPage.Attempts[1].ID != successorID || attemptPage.Attempts[0].Lifecycle != publicationstate.AttemptRetiredSuccess || attemptPage.Attempts[0].Outcome != publicationstate.OutcomeCurrent || attemptPage.Attempts[0].StateDigest != genesis.Attempt.StateDigest || attemptPage.Attempts[1].Lifecycle != publicationstate.AttemptMayHaveSubmitted || attemptPage.Attempts[1].Outcome != publicationstate.OutcomeLostFence || attemptPage.Attempts[1].Blocked != "" || attemptPage.Attempts[1].SnapshotKey != priorState.SnapshotKey || !bytes.Equal(attemptPage.Attempts[1].SnapshotRecordCID, priorState.SnapshotRecordCID) || !bytes.Equal(attemptPage.Attempts[1].HeadRecordCID, priorState.HeadRecordCID) || !bytes.Equal(attemptPage.Attempts[1].BlobCID, priorState.BlobCID) || attemptPage.Attempts[1].BlobSize != priorState.BlobSize || attemptPage.Attempts[1].StateDigest != priorState.StateDigest {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement submitted attempt history differs")
	}
	firstReadback, firstPresent, err := store.ReadFirstConflict(ctx, successorID)
	if err != nil || !firstPresent || firstReadback.AttemptID != savedFirstConflict.AttemptID || firstReadback.ID != savedFirstConflict.ID || !bytes.Equal(firstReadback.Evidence, savedFirstConflict.Evidence) || !bytes.Equal(firstReadback.Head, savedFirstConflict.Head) || firstReadback.HeadKey != savedFirstConflict.HeadKey || !bytes.Equal(firstReadback.HeadRecord, savedFirstConflict.HeadRecord) || firstReadback.HeadSequence != savedFirstConflict.HeadSequence {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement first-conflict readback differs")
	}
	successorMaterial, err := store.ReadCandidate(ctx, successorID)
	if err != nil || successorMaterial.AttemptID != successorID || successorMaterial.SnapshotKey != priorState.SnapshotKey || len(successorMaterial.SnapshotRecord) == 0 || len(successorMaterial.SnapshotRecord) > publication.MaxRecordBytes || len(successorMaterial.HeadRecord) == 0 || len(successorMaterial.HeadRecord) > publication.MaxRecordBytes || len(successorMaterial.Payload) == 0 || uint64(len(successorMaterial.Payload)) > publication.MaxBlobBytes || !bytes.Equal(successorMaterial.Blob.CID, priorState.BlobCID) || successorMaterial.Blob.Size != priorState.BlobSize {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement submitted candidate readback differs")
	}
	successorRecord, err := publication.DecodeSnapshot(successorMaterial.SnapshotRecord)
	if err != nil || successorRecord.Vault != binding.Vault || successorRecord.PublicationSeq != 1 || allZero(successorRecord.PublicationID[:]) || successorRecord.PublicationID != successorID || !bytes.Equal(successorRecord.Parent, genesisRecordCID) || successorMaterial.SnapshotKey != priorState.SnapshotKey {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement submitted candidate record is invalid")
	}
	successorRecordCID, err := publication.RecordCID(successorMaterial.SnapshotRecord)
	if err != nil || bytes.Equal(successorRecordCID, genesisRecordCID) || bytes.Equal(successorRecordCID, forkRecordCID) || !bytes.Equal(successorRecordCID, priorState.SnapshotRecordCID) || !bytes.Equal(successorRecordCID, priorLatest.Attempt.SnapshotRecordCID) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement submitted candidate identifier differs")
	}
	successorHead, err := publication.DecodeHead(successorMaterial.HeadRecord)
	if err != nil || successorHead.Vault != binding.Vault || successorHead.PublicationSeq != 1 || !bytes.Equal(successorHead.SnapshotCID, successorRecordCID) || !bytes.Equal(successorHead.BlobCID, successorRecord.Blob.CID) || publication.VerifyHeadBinding(successorMaterial.HeadRecord, successorMaterial.SnapshotRecord, successorMaterial.SnapshotKey) != nil {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement submitted candidate head is invalid")
	}
	successorHeadCID, err := publication.RecordCID(successorMaterial.HeadRecord)
	if err != nil || bytes.Equal(successorHeadCID, genesisHeadCID) || bytes.Equal(successorHeadCID, forkHeadCID) || !bytes.Equal(successorHeadCID, priorState.HeadRecordCID) || !bytes.Equal(successorHeadCID, priorLatest.Attempt.HeadRecordCID) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement submitted candidate head identifier differs")
	}
	successorBlobCID, err := publication.RawPayloadCID(successorMaterial.Payload)
	if err != nil || !bytes.Equal(successorBlobCID, successorRecord.Blob.CID) || !bytes.Equal(successorBlobCID, priorState.BlobCID) || successorRecord.Blob.Size != uint64(len(successorMaterial.Payload)) || priorState.BlobSize != uint64(len(successorMaterial.Payload)) || bytes.Equal(successorMaterial.Payload, genesisInput.Payload) || bytes.Equal(successorBlobCID, genesisBlobCID) || bytes.Equal(successorMaterial.Payload, replacementInput.Payload) || bytes.Equal(successorBlobCID, forkBlobCID) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement submitted payload is not distinct")
	}
	if err := publication.VerifyPayload(successorMaterial.Payload, successorRecord.Blob); err != nil {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement submitted payload reference is invalid")
	}
	if _, err := publication.DecodePayload(successorMaterial.Payload, successorRecord.Blob); err != nil {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement submitted payload is invalid")
	}
	if !bytes.Equal(savedPriorLatestEvidence, priorLatest.Evidence) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement prior proof changed")
	}
	genesisOutcomeCount, genesisSubmissionCount := 0, 0
	successorConflictCount, successorOutcomeCount, successorSubmissionCount := 0, 0, 0
	var genesisOutcomeEvidence, genesisSubmissionEvidence, successorSubmissionEvidence []byte
	for _, evidence := range attemptPage.Evidence {
		if len(evidence.Evidence) == 0 {
			return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement prior evidence is empty")
		}
		switch evidence.AttemptID {
		case genesisAttemptID:
			var projection attemptOutcomeReadback
			if json.Unmarshal(evidence.Evidence, &projection) != nil || projection.Version != 1 || len(projection.ViewDigest) != 32 {
				return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement genesis evidence is invalid")
			}
			switch evidence.Role {
			case "outcome":
				genesisOutcomeCount++
				if projection.Role != "outcome" || projection.Outcome != string(publicationstate.OutcomeCurrent) || projection.AttemptedKey != genesisInput.SnapshotKey || !bytes.Equal(projection.AttemptedRecord, genesisInput.SnapshotRecord) || len(projection.PredecessorRecord) != 0 || !bytes.Equal(projection.Head, genesisInput.HeadRecord) || len(projection.Suffix) != 1 || projection.Suffix[0].Key != genesisInput.SnapshotKey || !bytes.Equal(projection.Suffix[0].Raw, genesisInput.SnapshotRecord) {
					return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement genesis outcome differs")
				}
				genesisOutcomeEvidence = bytes.Clone(evidence.Evidence)
			case "submission":
				genesisSubmissionCount++
				if projection.Role != "submission" || projection.Outcome != string(publicationstate.OutcomeUnresolved) || projection.AttemptedKey != genesisInput.SnapshotKey || !bytes.Equal(projection.AttemptedRecord, genesisInput.SnapshotRecord) || len(projection.PredecessorRecord) != 0 || len(projection.Head) != 0 || len(projection.Suffix) != 0 {
					return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement genesis submission differs")
				}
				genesisSubmissionEvidence = bytes.Clone(evidence.Evidence)
			default:
				return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement genesis role is unexpected")
			}
		case successorID:
			if evidence.Role == "first-conflict" {
				successorConflictCount++
				if !bytes.Equal(evidence.Evidence, savedFirstConflict.Evidence) {
					return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement first-conflict role differs")
				}
				continue
			}
			var projection attemptOutcomeReadback
			if json.Unmarshal(evidence.Evidence, &projection) != nil || projection.Version != 1 || len(projection.ViewDigest) != 32 {
				return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement successor evidence is invalid")
			}
			switch evidence.Role {
			case "outcome":
				successorOutcomeCount++
				if projection.Role != "outcome" || projection.Outcome != string(publicationstate.OutcomeLostFence) || !bytes.Equal(evidence.Evidence, savedPriorLatestEvidence) || !bytes.Equal(projection.Head, priorLatestView.Head) || len(projection.Suffix) != 2 {
					return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement prior outcome role differs")
				}
			case "submission":
				successorSubmissionCount++
				if projection.Role != "submission" || projection.Outcome != string(publicationstate.OutcomeUnresolved) || projection.AttemptedKey != successorMaterial.SnapshotKey || !bytes.Equal(projection.AttemptedRecord, successorMaterial.SnapshotRecord) || !bytes.Equal(projection.PredecessorRecord, genesisInput.SnapshotRecord) || !bytes.Equal(projection.Head, genesisInput.HeadRecord) || len(projection.Suffix) != 0 {
					return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement successor submission differs")
				}
				successorSubmissionEvidence = bytes.Clone(evidence.Evidence)
			default:
				return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement successor role is unexpected")
			}
		default:
			return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement evidence identity is unexpected")
		}
	}
	if genesisOutcomeCount != 1 || genesisSubmissionCount != 1 || successorConflictCount != 1 || successorOutcomeCount != 1 || successorSubmissionCount != 1 || len(genesisOutcomeEvidence) == 0 || len(genesisSubmissionEvidence) == 0 || len(successorSubmissionEvidence) == 0 {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement prior evidence roles are incomplete")
	}

	proposal, err := store.Prepare(ctx, publicationstate.ModeReplaceFloor, replacementObservation, replacementInput.Payload)
	if err != nil || proposal.Mode != publicationstate.ModeReplaceFloor || proposal.Stop != "fork" || proposal.Reason != publicationstate.ReasonFork || proposal.Warning != publicationstate.WarningReplacement || allZero(proposal.StateToken[:]) || allZero(proposal.Confirmation[:]) || allZero(proposal.ObservationDigest[:]) || len(proposal.Trace) != 1 || proposal.Trace[0].Key != replacementInput.SnapshotKey || proposal.Trace[0].Sequence != 0 || !bytes.Equal(proposal.Trace[0].CID, forkRecordCID) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement fork proposal differs")
	}
	replacementFloor, err := store.Accept(ctx, publicationstate.ModeReplaceFloor, proposal.StateToken, replacementObservation, replacementInput.Payload, proposal.Confirmation)
	if err != nil || replacementFloor.DatabaseID != genesisFloor.DatabaseID || replacementFloor.Binding != binding || replacementFloor.Revision != 2 || replacementFloor.Generation != 2 || replacementFloor.Provenance != publicationstate.ProvenanceReplace || !bytes.Equal(replacementFloor.AnchorCID, forkRecordCID) || !reflect.DeepEqual(replacementFloor.SuppliedContext, replacementObservation.SuppliedContext) || !bytes.Equal(replacementFloor.Head, replacementInput.HeadRecord) || replacementFloor.SnapshotKey != replacementInput.SnapshotKey || replacementFloor.Sequence != 0 || replacementFloor.PublicationID != forkRecord.PublicationID || !bytes.Equal(replacementFloor.RecordCID, forkRecordCID) || !bytes.Equal(replacementFloor.BlobCID, forkBlobCID) || replacementFloor.BlobSize != uint64(len(replacementInput.Payload)) || replacementFloor.ObservationDigest != proposal.ObservationDigest || allZero(replacementFloor.AcceptedEventDigest[:]) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement accepted floor differs")
	}
	acceptedFloor, floorPresent, err := store.Load(ctx)
	if err != nil || !floorPresent || !reflect.DeepEqual(acceptedFloor, replacementFloor) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement accepted floor readback differs")
	}
	replacementHistory, err := store.History(ctx, 0, 10)
	if err != nil || len(replacementHistory.Events) != 2 || len(replacementHistory.Records) != 2 || replacementHistory.HasMore || replacementHistory.NextRevision != 2 || !reflect.DeepEqual(replacementHistory.Events[0], positionHistory.Events[0]) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement accepted history shape differs")
	}
	replacementEvent := replacementHistory.Events[1]
	if replacementEvent.Revision != 2 || replacementEvent.Mode != publicationstate.ModeReplaceFloor || replacementEvent.Reason != publicationstate.ReasonFork || replacementEvent.Stop != "fork" || replacementEvent.OldFloor == nil || !reflect.DeepEqual(*replacementEvent.OldFloor, genesisFloor) || !reflect.DeepEqual(replacementEvent.NewFloor, replacementFloor) || replacementEvent.EventDigest != replacementFloor.AcceptedEventDigest || replacementEvent.ObservationDigest != proposal.ObservationDigest || len(replacementEvent.Trace) != 1 || replacementEvent.Trace[0].Key != replacementInput.SnapshotKey || replacementEvent.Trace[0].Sequence != 0 || !bytes.Equal(replacementEvent.Trace[0].CID, forkRecordCID) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement fork event differs")
	}
	foundGenesisRecord, foundForkRecord := false, false
	for _, record := range replacementHistory.Records {
		if record.Reference.Key != replacementInput.SnapshotKey || record.Reference.Sequence != 0 {
			return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement accepted record reference differs")
		}
		if bytes.Equal(record.Reference.CID, genesisRecordCID) && bytes.Equal(record.Raw, genesisInput.SnapshotRecord) {
			foundGenesisRecord = true
		}
		if bytes.Equal(record.Reference.CID, forkRecordCID) && bytes.Equal(record.Raw, replacementInput.SnapshotRecord) {
			foundForkRecord = true
		}
	}
	if !foundGenesisRecord || !foundForkRecord {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement accepted raw records differ")
	}
	postAcceptHistory := replacementHistory
	blockedState, err := store.LoadAttempt(ctx, successorID)
	if err != nil || blockedState.ID != successorID || blockedState.Kind != publicationstate.AttemptSuccessor || blockedState.Lifecycle != publicationstate.AttemptMayHaveSubmitted || blockedState.Outcome != publicationstate.OutcomeLostFence || blockedState.Blocked != "blocked-floor-replaced" || blockedState.Sequence != 1 || blockedState.SnapshotKey != priorState.SnapshotKey || blockedState.CapturedFloor == nil || !reflect.DeepEqual(*blockedState.CapturedFloor, genesisFloor) || blockedState.CapturedRevision != genesisFloor.Revision || blockedState.CapturedGeneration != genesisFloor.Generation || blockedState.StateDigest == priorState.StateDigest || allZero(blockedState.StateDigest[:]) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement block metadata differs")
	}
	blockedActive, blockedPresent, err := store.ActiveAttempt(ctx)
	if err != nil || !blockedPresent || blockedActive.ID != successorID || blockedActive.Lifecycle != publicationstate.AttemptMayHaveSubmitted || blockedActive.Outcome != publicationstate.OutcomeLostFence || blockedActive.Blocked != "blocked-floor-replaced" || blockedActive.StateDigest != blockedState.StateDigest {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement blocked attempt lost its active slot")
	}
	blockedPage, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	if err != nil || len(blockedPage.Attempts) != 2 || blockedPage.HasMore || blockedPage.NextID != successorID || blockedPage.Attempts[0].ID != genesisAttemptID || blockedPage.Attempts[1].ID != successorID || blockedPage.Attempts[1].Lifecycle != publicationstate.AttemptMayHaveSubmitted || blockedPage.Attempts[1].Outcome != publicationstate.OutcomeLostFence || blockedPage.Attempts[1].Blocked != "blocked-floor-replaced" || blockedPage.Attempts[1].StateDigest != blockedState.StateDigest || !reflect.DeepEqual(blockedPage.Evidence, attemptPage.Evidence) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement blocked attempt history differs")
	}
	blockedConflict, blockedConflictPresent, err := store.ReadFirstConflict(ctx, successorID)
	if err != nil || !blockedConflictPresent || blockedConflict.ID != savedFirstConflict.ID || !bytes.Equal(blockedConflict.Evidence, savedFirstConflict.Evidence) || !bytes.Equal(blockedConflict.Head, savedFirstConflict.Head) || blockedConflict.HeadKey != savedFirstConflict.HeadKey || !bytes.Equal(blockedConflict.HeadRecord, savedFirstConflict.HeadRecord) || blockedConflict.HeadSequence != savedFirstConflict.HeadSequence {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement first-conflict changed on blocking")
	}
	blockedMaterial, err := store.ReadCandidate(ctx, successorID)
	if err != nil || blockedMaterial.AttemptID != successorID || blockedMaterial.SnapshotKey != successorMaterial.SnapshotKey || !bytes.Equal(blockedMaterial.SnapshotRecord, successorMaterial.SnapshotRecord) || !bytes.Equal(blockedMaterial.HeadRecord, successorMaterial.HeadRecord) || !bytes.Equal(blockedMaterial.Payload, successorMaterial.Payload) || !bytes.Equal(blockedMaterial.Blob.CID, successorBlobCID) || blockedMaterial.Blob.Size != successorMaterial.Blob.Size {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement blocked candidate is not readable")
	}
	retirementProposal, err := store.PrepareAbandon(ctx, successorID, &retirementView)
	if err != nil || retirementProposal.AttemptID != successorID || allZero(retirementProposal.StateToken[:]) || allZero(retirementProposal.Confirmation[:]) || retirementProposal.Warning != publicationstate.AbandonWarning {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement abandonment proposal differs")
	}
	retiredAttempt, err := store.AbandonAttempt(ctx, successorID, retirementProposal.StateToken, &retirementView, retirementProposal.Confirmation)
	if err != nil || retiredAttempt.ID != successorID || retiredAttempt.Kind != publicationstate.AttemptSuccessor || retiredAttempt.Lifecycle != publicationstate.AttemptRetiredAbandoned || retiredAttempt.Outcome != publicationstate.OutcomeLostFence || retiredAttempt.Blocked != "blocked-floor-replaced" || retiredAttempt.Sequence != 1 || retiredAttempt.SnapshotKey != successorMaterial.SnapshotKey || !bytes.Equal(retiredAttempt.SnapshotRecordCID, successorRecordCID) || !bytes.Equal(retiredAttempt.HeadRecordCID, successorHeadCID) || !bytes.Equal(retiredAttempt.BlobCID, successorBlobCID) || retiredAttempt.BlobSize != uint64(len(successorMaterial.Payload)) || retiredAttempt.CapturedFloor == nil || !reflect.DeepEqual(*retiredAttempt.CapturedFloor, genesisFloor) || retiredAttempt.CapturedRevision != genesisFloor.Revision || retiredAttempt.CapturedGeneration != genesisFloor.Generation || allZero(retiredAttempt.StateDigest[:]) || retiredAttempt.StateDigest == blockedState.StateDigest {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement returned attempt differs")
	}
	retiredReadback, err := store.LoadAttempt(ctx, successorID)
	if err != nil || retiredReadback.ID != successorID || retiredReadback.Lifecycle != publicationstate.AttemptRetiredAbandoned || retiredReadback.Outcome != publicationstate.OutcomeLostFence || retiredReadback.Blocked != "blocked-floor-replaced" || retiredReadback.StateDigest != retiredAttempt.StateDigest || retiredReadback.CapturedFloor == nil || !reflect.DeepEqual(*retiredReadback.CapturedFloor, genesisFloor) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement attempt readback differs")
	}
	finalActive, finalActivePresent, err := store.ActiveAttempt(ctx)
	if err != nil || finalActivePresent || finalActive.ID != [16]byte{} {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement active slot remains")
	}
	finalPage, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	if err != nil || len(finalPage.Attempts) != 2 || finalPage.HasMore || finalPage.NextID != successorID || finalPage.Attempts[0].ID != genesisAttemptID || finalPage.Attempts[1].ID != successorID || finalPage.Attempts[0].Lifecycle != publicationstate.AttemptRetiredSuccess || finalPage.Attempts[0].Outcome != publicationstate.OutcomeCurrent || finalPage.Attempts[0].StateDigest != genesis.Attempt.StateDigest || finalPage.Attempts[1].Lifecycle != publicationstate.AttemptRetiredAbandoned || finalPage.Attempts[1].Outcome != publicationstate.OutcomeLostFence || finalPage.Attempts[1].Blocked != "blocked-floor-replaced" || finalPage.Attempts[1].Sequence != retiredAttempt.Sequence || finalPage.Attempts[1].SnapshotKey != retiredAttempt.SnapshotKey || !bytes.Equal(finalPage.Attempts[1].SnapshotRecordCID, retiredAttempt.SnapshotRecordCID) || !bytes.Equal(finalPage.Attempts[1].HeadRecordCID, retiredAttempt.HeadRecordCID) || !bytes.Equal(finalPage.Attempts[1].BlobCID, retiredAttempt.BlobCID) || finalPage.Attempts[1].BlobSize != retiredAttempt.BlobSize || finalPage.Attempts[1].StateDigest != retiredAttempt.StateDigest {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement final history shape differs")
	}
	if len(finalPage.Evidence) != 6 {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement final evidence count differs")
	}
	finalGenesisOutcomeCount, finalGenesisSubmissionCount := 0, 0
	finalConflictCount, finalOutcomeCount, finalRetirementCount, finalSubmissionCount := 0, 0, 0, 0
	var finalGenesisOutcome, finalGenesisSubmission []byte
	var finalConflictEvidence, finalOutcome, finalRetirement, finalSubmission []byte
	for _, evidence := range finalPage.Evidence {
		if len(evidence.Evidence) == 0 {
			return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement final evidence is empty")
		}
		switch evidence.AttemptID {
		case genesisAttemptID:
			switch evidence.Role {
			case "outcome":
				finalGenesisOutcomeCount++
				finalGenesisOutcome = bytes.Clone(evidence.Evidence)
			case "submission":
				finalGenesisSubmissionCount++
				finalGenesisSubmission = bytes.Clone(evidence.Evidence)
			default:
				return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement final genesis role is unexpected")
			}
		case successorID:
			switch evidence.Role {
			case "first-conflict":
				finalConflictCount++
				finalConflictEvidence = bytes.Clone(evidence.Evidence)
			case "outcome":
				finalOutcomeCount++
				finalOutcome = bytes.Clone(evidence.Evidence)
			case "retirement":
				finalRetirementCount++
				finalRetirement = bytes.Clone(evidence.Evidence)
			case "submission":
				finalSubmissionCount++
				finalSubmission = bytes.Clone(evidence.Evidence)
			default:
				return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement final successor role is unexpected")
			}
		default:
			return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement final evidence identity is unexpected")
		}
	}
	if finalGenesisOutcomeCount != 1 || finalGenesisSubmissionCount != 1 || finalConflictCount != 1 || finalOutcomeCount != 1 || finalRetirementCount != 1 || finalSubmissionCount != 1 || !bytes.Equal(finalGenesisOutcome, genesisOutcomeEvidence) || !bytes.Equal(finalGenesisSubmission, genesisSubmissionEvidence) || !bytes.Equal(finalConflictEvidence, savedFirstConflict.Evidence) || !bytes.Equal(finalSubmission, successorSubmissionEvidence) || !bytes.Equal(finalOutcome, finalRetirement) || bytes.Equal(finalOutcome, savedPriorLatestEvidence) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement final role evidence differs")
	}
	var retirementOutcome attemptOutcomeReadback
	if json.Unmarshal(finalOutcome, &retirementOutcome) != nil || retirementOutcome.Version != 1 || retirementOutcome.Role != "outcome" || retirementOutcome.Outcome != string(publicationstate.OutcomeLostFence) || len(retirementOutcome.ViewDigest) != 32 || !bytes.Equal(retirementOutcome.Head, retirementView.Head) || retirementOutcome.AttemptedKey != retirementView.Snapshots[1].Key || !bytes.Equal(retirementOutcome.AttemptedRecord, retirementView.Snapshots[1].Raw) || !bytes.Equal(retirementOutcome.PredecessorRecord, genesisInput.SnapshotRecord) || len(retirementOutcome.Suffix) != 3 {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement final outcome body differs")
	}
	for index := range retirementOutcome.Suffix {
		if retirementOutcome.Suffix[index].Key != retirementView.Snapshots[index+1].Key || !bytes.Equal(retirementOutcome.Suffix[index].Raw, retirementView.Snapshots[index+1].Raw) {
			return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement final suffix differs")
		}
	}
	if !bytes.Equal(priorOutcome.Head, priorLatestView.Head) || len(priorOutcome.Suffix) != 2 || len(retirementOutcome.ViewDigest) != 32 || allZero(retirementOutcome.ViewDigest) || bytes.Equal(priorOutcome.ViewDigest, retirementOutcome.ViewDigest) || bytes.Equal(priorOutcome.Head, retirementOutcome.Head) || bytes.Equal(savedPriorLatestEvidence, finalOutcome) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement chronology collapsed")
	}
	finalConflict, finalConflictPresent, err := store.ReadFirstConflict(ctx, successorID)
	if err != nil || !finalConflictPresent || finalConflict.AttemptID != savedFirstConflict.AttemptID || finalConflict.ID != savedFirstConflict.ID || !bytes.Equal(finalConflict.Evidence, savedFirstConflict.Evidence) || !bytes.Equal(finalConflict.Head, savedFirstConflict.Head) || finalConflict.HeadKey != savedFirstConflict.HeadKey || !bytes.Equal(finalConflict.HeadRecord, savedFirstConflict.HeadRecord) || finalConflict.HeadSequence != savedFirstConflict.HeadSequence {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement immutable first-conflict changed")
	}
	postRetirementFloor, postRetirementPresent, err := store.Load(ctx)
	if err != nil || !postRetirementPresent || !reflect.DeepEqual(postRetirementFloor, replacementFloor) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement position changed")
	}
	postRetirementHistory, err := store.History(ctx, 0, 10)
	if err != nil || !reflect.DeepEqual(postAcceptHistory, postRetirementHistory) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement accepted history changed")
	}
	retainedGenesis, err := store.ReadCandidate(ctx, genesisAttemptID)
	if err != nil || retainedGenesis.AttemptID != genesisAttemptID || retainedGenesis.SnapshotKey != genesisInput.SnapshotKey || !bytes.Equal(retainedGenesis.SnapshotRecord, genesisInput.SnapshotRecord) || !bytes.Equal(retainedGenesis.HeadRecord, genesisInput.HeadRecord) || !bytes.Equal(retainedGenesis.Payload, genesisInput.Payload) || !bytes.Equal(retainedGenesis.Blob.CID, genesisBlobCID) || retainedGenesis.Blob.Size != uint64(len(genesisInput.Payload)) {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement retained genesis readback differs")
	}
	abandonedMaterial, abandonedErr := store.ReadCandidate(ctx, successorID)
	var abandonedStateErr *publicationstate.Error
	if abandonedErr == nil || !reflect.DeepEqual(abandonedMaterial, publicationstate.CandidateMaterial{}) || !errors.As(abandonedErr, &abandonedStateErr) || abandonedStateErr == nil || abandonedStateErr.Class() != publicationstate.ErrStorage || abandonedStateErr.Stage() != publicationstate.StageCustody || abandonedStateErr.Reason() != publicationstate.ReasonCandidateMissing {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement abandoned candidate refusal differs")
	}
	unretainedMaterial, unretainedErr := store.ReadAcceptedMaterial(ctx, binding, replacementFloor)
	var unretainedStateErr *publicationstate.Error
	if unretainedErr == nil || !reflect.DeepEqual(unretainedMaterial, publicationstate.AcceptedMaterial{}) || !errors.As(unretainedErr, &unretainedStateErr) || unretainedStateErr == nil || unretainedStateErr.Class() != publicationstate.ErrStorage || unretainedStateErr.Stage() != publicationstate.StageReadAcceptedMaterial || unretainedStateErr.Reason() != publicationstate.ReasonMaterialNotRetained {
		return publicationstate.Floor{}, publicationstate.Attempt{}, publicationstate.FirstConflictEvidence{}, publicationstate.AttemptPage{}, errors.New("replacement retirement current material refusal differs")
	}
	return replacementFloor, retiredAttempt, finalConflict, finalPage, nil
}

func submitReplacementSuccessorAbsentAndCache(ctx context.Context, store *publicationstate.Store, binding publicationstate.Binding, genesis publicationstate.Finalization, genesisInput publicationstate.CandidateInput, genesisMetadata candidateValue, replacementFloor publicationstate.Floor, replacementInput publicationstate.CandidateInput, replacementMetadata candidateValue, retiredAttempt publicationstate.Attempt, abandonedMetadata candidateValue, firstConflict publicationstate.FirstConflictEvidence, priorPage publicationstate.AttemptPage, successorInput publicationstate.CandidateInput, successorMetadata candidateValue, absentView publicationstate.SuppliedRepositoryView, cacheObservation publicationstate.Observation, review publicationstate.LocalReviewContext) (publicationstate.Floor, publicationstate.AttemptResolution, [32]byte, publicationstate.CandidateMaterial, publicationstate.AttemptPage, publicationstate.HistoryPage, publicationstate.FirstConflictEvidence, error) {
	if ctx == nil || store == nil {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor inputs are invalid")
	}
	if ctx.Err() != nil {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor context is invalid")
	}
	if binding.Backend != publicationstate.BackendPublicRepo || genesis.Attempt.CapturedFloor != nil || len(priorPage.Attempts) != 2 || len(priorPage.Evidence) != 6 || priorPage.HasMore || priorPage.NextID != retiredAttempt.ID || len(absentView.Snapshots) != 1 || len(cacheObservation.Snapshots) != 1 {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor shape is invalid")
	}
	genesisAttemptID := genesis.Attempt.ID
	abandonedAttemptID := retiredAttempt.ID
	if allZero(genesisAttemptID[:]) || allZero(abandonedAttemptID[:]) || genesisAttemptID == abandonedAttemptID || allZero(firstConflict.ID[:]) || len(firstConflict.Evidence) == 0 || firstConflict.AttemptID != abandonedAttemptID {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor prior identities are invalid")
	}
	if priorPage.Attempts[0].ID != genesisAttemptID || priorPage.Attempts[1].ID != abandonedAttemptID || priorPage.Attempts[0].Kind != publicationstate.AttemptGenesis || priorPage.Attempts[0].Lifecycle != publicationstate.AttemptRetiredSuccess || priorPage.Attempts[0].Outcome != publicationstate.OutcomeCurrent || priorPage.Attempts[1].Kind != publicationstate.AttemptSuccessor || priorPage.Attempts[1].Lifecycle != publicationstate.AttemptRetiredAbandoned || priorPage.Attempts[1].Outcome != publicationstate.OutcomeLostFence || priorPage.Attempts[1].Blocked != "blocked-floor-replaced" {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor prior attempt page differs")
	}
	if retiredAttempt.Kind != publicationstate.AttemptSuccessor || retiredAttempt.Lifecycle != publicationstate.AttemptRetiredAbandoned || retiredAttempt.Outcome != publicationstate.OutcomeLostFence || retiredAttempt.Blocked != "blocked-floor-replaced" || retiredAttempt.Sequence != 1 || retiredAttempt.CapturedFloor == nil || !reflect.DeepEqual(*retiredAttempt.CapturedFloor, genesis.Floor) || retiredAttempt.CapturedRevision != genesis.Floor.Revision || retiredAttempt.CapturedGeneration != genesis.Floor.Generation || allZero(retiredAttempt.StateDigest[:]) || priorPage.Attempts[1].StateDigest != retiredAttempt.StateDigest || priorPage.Attempts[1].BlobSize != retiredAttempt.BlobSize || !bytes.Equal(priorPage.Attempts[1].SnapshotRecordCID, retiredAttempt.SnapshotRecordCID) || !bytes.Equal(priorPage.Attempts[1].HeadRecordCID, retiredAttempt.HeadRecordCID) || !bytes.Equal(priorPage.Attempts[1].BlobCID, retiredAttempt.BlobCID) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor retired identity differs")
	}
	if genesis.Attempt.Kind != publicationstate.AttemptGenesis || genesis.Attempt.Lifecycle != publicationstate.AttemptRetiredSuccess || genesis.Attempt.Outcome != publicationstate.OutcomeCurrent || genesis.Attempt.Blocked != "" || genesis.Attempt.Sequence != 0 || allZero(genesis.Attempt.StateDigest[:]) || genesis.Floor.Revision != 1 || genesis.Floor.Generation != 1 || genesis.Floor.Provenance != publicationstate.ProvenanceFirst || genesis.Floor.Binding != binding || allZero(genesis.Floor.DatabaseID[:]) || allZero(genesis.Floor.AcceptedEventDigest[:]) || allZero(genesis.Floor.ObservationDigest[:]) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor genesis floor is invalid")
	}
	if genesisMetadata.AttemptID != "" && genesisMetadata.AttemptID != hex.EncodeToString(genesisAttemptID[:]) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor genesis attempt metadata differs")
	}
	if err := validateCandidate(genesisInput, binding, genesisMetadata); err != nil || !reflect.DeepEqual(encodeBytes(genesisInput.SnapshotRecord), genesisMetadata.SnapshotRecord) || !reflect.DeepEqual(encodeBytes(genesisInput.HeadRecord), genesisMetadata.HeadRecord) || !reflect.DeepEqual(encodeBytes(genesisInput.Payload), genesisMetadata.Payload) || genesisMetadata.SnapshotKey != genesisInput.SnapshotKey || genesisMetadata.BlobSize != uint64(len(genesisInput.Payload)) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor genesis candidate metadata differs")
	}
	genesisRecord, err := publication.DecodeSnapshot(genesisInput.SnapshotRecord)
	if err != nil || genesisRecord.PublicationSeq != 0 || len(genesisRecord.Parent) != 0 || genesisRecord.PublicationID != genesisAttemptID || genesisRecord.Vault != binding.Vault {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor genesis record differs")
	}
	genesisRecordCID, err := publication.RecordCID(genesisInput.SnapshotRecord)
	if err != nil || !reflect.DeepEqual(encodeBytes(genesisRecordCID), genesisMetadata.SnapshotCID) || !bytes.Equal(genesisRecordCID, genesis.Floor.RecordCID) || !bytes.Equal(genesisRecordCID, genesis.Floor.AnchorCID) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor genesis record identifier differs")
	}
	genesisHeadCID, err := publication.RecordCID(genesisInput.HeadRecord)
	if err != nil || !reflect.DeepEqual(encodeBytes(genesisHeadCID), genesisMetadata.HeadCID) || !bytes.Equal(genesisHeadCID, genesis.Attempt.HeadRecordCID) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor genesis head identifier differs")
	}
	genesisBlobCID, err := publication.RawPayloadCID(genesisInput.Payload)
	if err != nil || !reflect.DeepEqual(encodeBytes(genesisBlobCID), genesisMetadata.BlobCID) || !bytes.Equal(genesisBlobCID, genesis.Floor.BlobCID) || genesis.Floor.BlobSize != uint64(len(genesisInput.Payload)) || genesis.Attempt.BlobSize != uint64(len(genesisInput.Payload)) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor genesis payload identifier differs")
	}
	if genesis.Attempt.ID != genesisAttemptID || genesis.Attempt.SnapshotKey != genesisInput.SnapshotKey || !bytes.Equal(genesis.Attempt.SnapshotRecordCID, genesisRecordCID) || !bytes.Equal(genesis.Attempt.BlobCID, genesisBlobCID) || !bytes.Equal(genesis.Floor.Head, genesisInput.HeadRecord) || genesis.Floor.SnapshotKey != genesisInput.SnapshotKey || genesis.Floor.Sequence != 0 || genesis.Floor.PublicationID != genesisAttemptID || !bytes.Equal(genesis.Floor.RecordCID, genesisRecordCID) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor genesis identity differs")
	}
	if replacementMetadata.AttemptID != "" || replacementMetadata.SnapshotKey != replacementInput.SnapshotKey || !reflect.DeepEqual(encodeBytes(replacementInput.SnapshotRecord), replacementMetadata.SnapshotRecord) || !reflect.DeepEqual(encodeBytes(replacementInput.HeadRecord), replacementMetadata.HeadRecord) || !reflect.DeepEqual(encodeBytes(replacementInput.Payload), replacementMetadata.Payload) || replacementMetadata.BlobSize != uint64(len(replacementInput.Payload)) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor floor metadata differs")
	}
	if err := validateCandidate(replacementInput, binding, replacementMetadata); err != nil {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor floor candidate is invalid")
	}
	replacementRecord, err := publication.DecodeSnapshot(replacementInput.SnapshotRecord)
	if err != nil || replacementRecord.PublicationSeq != 0 || len(replacementRecord.Parent) != 0 || replacementRecord.Vault != binding.Vault || allZero(replacementRecord.PublicationID[:]) || replacementRecord.PublicationID == genesisAttemptID {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor fork record is invalid")
	}
	replacementRecordCID, err := publication.RecordCID(replacementInput.SnapshotRecord)
	if err != nil || bytes.Equal(replacementRecordCID, genesisRecordCID) || !reflect.DeepEqual(encodeBytes(replacementRecordCID), replacementMetadata.SnapshotCID) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor fork record identifier differs")
	}
	replacementHead, err := publication.DecodeHead(replacementInput.HeadRecord)
	if err != nil || replacementHead.Vault != binding.Vault || replacementHead.PublicationSeq != 0 || !bytes.Equal(replacementHead.SnapshotCID, replacementRecordCID) || !bytes.Equal(replacementHead.BlobCID, replacementRecord.Blob.CID) || publication.VerifyHeadBinding(replacementInput.HeadRecord, replacementInput.SnapshotRecord, replacementInput.SnapshotKey) != nil {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor fork head is invalid")
	}
	replacementHeadCID, err := publication.RecordCID(replacementInput.HeadRecord)
	if err != nil || !reflect.DeepEqual(encodeBytes(replacementHeadCID), replacementMetadata.HeadCID) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor fork head identifier differs")
	}
	replacementBlobCID, err := publication.RawPayloadCID(replacementInput.Payload)
	if err != nil || !bytes.Equal(replacementBlobCID, replacementRecord.Blob.CID) || replacementRecord.Blob.Size != uint64(len(replacementInput.Payload)) || replacementMetadata.BlobSize != uint64(len(replacementInput.Payload)) || !reflect.DeepEqual(encodeBytes(replacementBlobCID), replacementMetadata.BlobCID) || bytes.Equal(replacementInput.Payload, genesisInput.Payload) || bytes.Equal(replacementBlobCID, genesisBlobCID) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor fork payload is not distinct")
	}
	if err := publication.VerifyPayload(replacementInput.Payload, replacementRecord.Blob); err != nil {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor fork payload reference is invalid")
	}
	if _, err := publication.DecodePayload(replacementInput.Payload, replacementRecord.Blob); err != nil {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor fork payload is invalid")
	}
	if allZero(replacementFloor.DatabaseID[:]) || replacementFloor.DatabaseID != genesis.Floor.DatabaseID || replacementFloor.Revision != 2 || replacementFloor.Generation != 2 || replacementFloor.Provenance != publicationstate.ProvenanceReplace || replacementFloor.Binding != binding || !bytes.Equal(replacementFloor.AnchorCID, replacementRecordCID) || !bytes.Equal(replacementFloor.Head, replacementInput.HeadRecord) || replacementFloor.SnapshotKey != replacementInput.SnapshotKey || replacementFloor.Sequence != 0 || replacementFloor.PublicationID != replacementRecord.PublicationID || !bytes.Equal(replacementFloor.RecordCID, replacementRecordCID) || !bytes.Equal(replacementFloor.BlobCID, replacementBlobCID) || replacementFloor.BlobSize != uint64(len(replacementInput.Payload)) || allZero(replacementFloor.ObservationDigest[:]) || allZero(replacementFloor.AcceptedEventDigest[:]) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor current floor differs")
	}
	if genesis.Attempt.SnapshotKey != genesisInput.SnapshotKey || !bytes.Equal(genesis.Attempt.HeadRecordCID, genesisHeadCID) || !bytes.Equal(genesis.Attempt.SnapshotRecordCID, genesisRecordCID) || !bytes.Equal(genesis.Attempt.BlobCID, genesisBlobCID) || genesis.Attempt.BlobSize != uint64(len(genesisInput.Payload)) || genesis.Floor.Binding != binding || genesis.Floor.SnapshotKey != genesisInput.SnapshotKey || genesis.Floor.Sequence != 0 || genesis.Floor.PublicationID != genesisAttemptID || !bytes.Equal(genesis.Floor.RecordCID, genesisRecordCID) || !bytes.Equal(genesis.Floor.BlobCID, genesisBlobCID) || genesis.Floor.BlobSize != uint64(len(genesisInput.Payload)) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor genesis ownership differs")
	}

	abandonedRecordRaw, err := base64.StdEncoding.DecodeString(abandonedMetadata.SnapshotRecord.Base64)
	if err != nil || !reflect.DeepEqual(encodeBytes(abandonedRecordRaw), abandonedMetadata.SnapshotRecord) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor abandoned record metadata is invalid")
	}
	abandonedHeadRaw, err := base64.StdEncoding.DecodeString(abandonedMetadata.HeadRecord.Base64)
	if err != nil || !reflect.DeepEqual(encodeBytes(abandonedHeadRaw), abandonedMetadata.HeadRecord) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor abandoned head metadata is invalid")
	}
	abandonedPayload, err := base64.StdEncoding.DecodeString(abandonedMetadata.Payload.Base64)
	if err != nil || !reflect.DeepEqual(encodeBytes(abandonedPayload), abandonedMetadata.Payload) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor abandoned payload metadata is invalid")
	}
	if abandonedMetadata.AttemptID != "" || abandonedMetadata.PublicationID != hex.EncodeToString(abandonedAttemptID[:]) || abandonedMetadata.SnapshotKey != retiredAttempt.SnapshotKey || abandonedMetadata.BlobSize != uint64(len(abandonedPayload)) || len(abandonedRecordRaw) == 0 || len(abandonedRecordRaw) > publication.MaxRecordBytes || len(abandonedHeadRaw) == 0 || len(abandonedHeadRaw) > publication.MaxRecordBytes || len(abandonedPayload) == 0 || uint64(len(abandonedPayload)) > publication.MaxBlobBytes {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor abandoned candidate shape differs")
	}
	abandonedRecord, err := publication.DecodeSnapshot(abandonedRecordRaw)
	if err != nil || abandonedRecord.Vault != binding.Vault || abandonedRecord.PublicationSeq != 1 || abandonedRecord.PublicationID != abandonedAttemptID || !bytes.Equal(abandonedRecord.Parent, genesisRecordCID) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor abandoned record differs")
	}
	abandonedKey, err := publication.SequenceKey(1)
	if err != nil || abandonedKey != abandonedMetadata.SnapshotKey || publication.VerifySuccessor(genesisInput.SnapshotRecord, abandonedRecordRaw, abandonedKey) != nil {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor abandoned key or predecessor differs")
	}
	abandonedRecordCID, err := publication.RecordCID(abandonedRecordRaw)
	if err != nil || !reflect.DeepEqual(encodeBytes(abandonedRecordCID), abandonedMetadata.SnapshotCID) || !bytes.Equal(abandonedRecordCID, retiredAttempt.SnapshotRecordCID) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor abandoned record identifier differs")
	}
	abandonedHead, err := publication.DecodeHead(abandonedHeadRaw)
	if err != nil || abandonedHead.Vault != binding.Vault || abandonedHead.PublicationSeq != 1 || !bytes.Equal(abandonedHead.SnapshotCID, abandonedRecordCID) || !bytes.Equal(abandonedHead.BlobCID, abandonedRecord.Blob.CID) || publication.VerifyHeadBinding(abandonedHeadRaw, abandonedRecordRaw, abandonedKey) != nil {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor abandoned head is invalid")
	}
	abandonedHeadCID, err := publication.RecordCID(abandonedHeadRaw)
	if err != nil || !reflect.DeepEqual(encodeBytes(abandonedHeadCID), abandonedMetadata.HeadCID) || !bytes.Equal(abandonedHeadCID, retiredAttempt.HeadRecordCID) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor abandoned head identifier differs")
	}
	abandonedBlobCID, err := publication.RawPayloadCID(abandonedPayload)
	if err != nil || !bytes.Equal(abandonedBlobCID, abandonedRecord.Blob.CID) || abandonedRecord.Blob.Size != uint64(len(abandonedPayload)) || !reflect.DeepEqual(encodeBytes(abandonedBlobCID), abandonedMetadata.BlobCID) || !bytes.Equal(abandonedBlobCID, retiredAttempt.BlobCID) || retiredAttempt.BlobSize != uint64(len(abandonedPayload)) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor abandoned payload identifier differs")
	}
	if err := publication.VerifyPayload(abandonedPayload, abandonedRecord.Blob); err != nil {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor abandoned payload reference is invalid")
	}
	if _, err := publication.DecodePayload(abandonedPayload, abandonedRecord.Blob); err != nil {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor abandoned payload is invalid")
	}

	if len(successorInput.SnapshotRecord) == 0 || len(successorInput.SnapshotRecord) > publication.MaxRecordBytes || len(successorInput.HeadRecord) == 0 || len(successorInput.HeadRecord) > publication.MaxRecordBytes || len(successorInput.Payload) == 0 || uint64(len(successorInput.Payload)) > publication.MaxBlobBytes || successorMetadata.AttemptID != "" || successorMetadata.SnapshotKey != successorInput.SnapshotKey || !reflect.DeepEqual(encodeBytes(successorInput.SnapshotRecord), successorMetadata.SnapshotRecord) || !reflect.DeepEqual(encodeBytes(successorInput.HeadRecord), successorMetadata.HeadRecord) || !reflect.DeepEqual(encodeBytes(successorInput.Payload), successorMetadata.Payload) || successorMetadata.BlobSize != uint64(len(successorInput.Payload)) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor candidate metadata differs")
	}
	successorRecord, err := publication.DecodeSnapshot(successorInput.SnapshotRecord)
	if err != nil || successorRecord.Vault != binding.Vault || successorRecord.PublicationSeq != 1 || allZero(successorRecord.PublicationID[:]) || !bytes.Equal(successorRecord.Parent, replacementRecordCID) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor candidate record is invalid")
	}
	successorKey, err := publication.SequenceKey(1)
	if err != nil || successorInput.SnapshotKey != successorKey || successorMetadata.SnapshotKey != successorKey || successorMetadata.PublicationID != hex.EncodeToString(successorRecord.PublicationID[:]) || successorRecord.PublicationID == genesisAttemptID || successorRecord.PublicationID == abandonedAttemptID || successorRecord.PublicationID == replacementRecord.PublicationID {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor candidate identity differs")
	}
	successorRecordCID, err := publication.RecordCID(successorInput.SnapshotRecord)
	if err != nil || bytes.Equal(successorRecordCID, genesisRecordCID) || bytes.Equal(successorRecordCID, replacementRecordCID) || bytes.Equal(successorRecordCID, abandonedRecordCID) || !reflect.DeepEqual(encodeBytes(successorRecordCID), successorMetadata.SnapshotCID) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor candidate record identifier differs")
	}
	successorHead, err := publication.DecodeHead(successorInput.HeadRecord)
	if err != nil || successorHead.Vault != binding.Vault || successorHead.PublicationSeq != 1 || !bytes.Equal(successorHead.SnapshotCID, successorRecordCID) || !bytes.Equal(successorHead.BlobCID, successorRecord.Blob.CID) || publication.VerifyHeadBinding(successorInput.HeadRecord, successorInput.SnapshotRecord, successorKey) != nil {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor candidate head is invalid")
	}
	if err := publication.VerifySuccessor(replacementInput.SnapshotRecord, successorInput.SnapshotRecord, successorKey); err != nil {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor parent join is invalid")
	}
	successorHeadCID, err := publication.RecordCID(successorInput.HeadRecord)
	if err != nil || !reflect.DeepEqual(encodeBytes(successorHeadCID), successorMetadata.HeadCID) || bytes.Equal(successorHeadCID, genesisHeadCID) || bytes.Equal(successorHeadCID, replacementHeadCID) || bytes.Equal(successorHeadCID, abandonedHeadCID) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor candidate head identifier differs")
	}
	successorBlobCID, err := publication.RawPayloadCID(successorInput.Payload)
	if err != nil || !bytes.Equal(successorBlobCID, successorRecord.Blob.CID) || successorRecord.Blob.Size != uint64(len(successorInput.Payload)) || successorMetadata.BlobSize != uint64(len(successorInput.Payload)) || !reflect.DeepEqual(encodeBytes(successorBlobCID), successorMetadata.BlobCID) || bytes.Equal(successorBlobCID, genesisBlobCID) || bytes.Equal(successorBlobCID, replacementBlobCID) || bytes.Equal(successorBlobCID, abandonedBlobCID) || bytes.Equal(successorInput.Payload, genesisInput.Payload) || bytes.Equal(successorInput.Payload, replacementInput.Payload) || bytes.Equal(successorInput.Payload, abandonedPayload) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor candidate payload is not distinct")
	}
	if err := publication.VerifyPayload(successorInput.Payload, successorRecord.Blob); err != nil {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor candidate payload reference is invalid")
	}
	if _, err := publication.DecodePayload(successorInput.Payload, successorRecord.Blob); err != nil {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor candidate payload is invalid")
	}
	if successorRecord.PublicationID == genesis.Attempt.ID || successorRecord.PublicationID == retiredAttempt.ID || successorRecord.PublicationID == replacementFloor.PublicationID || !bytes.Equal(successorRecord.Parent, replacementFloor.RecordCID) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor candidate lineage is not distinct")
	}

	contexts := []publicationstate.SuppliedContext{replacementFloor.SuppliedContext, absentView.SuppliedContext, cacheObservation.SuppliedContext}
	for index, supplied := range contexts {
		if len(supplied.RepositoryRevision) == 0 || len(supplied.RepositoryRevision) > 1024 || strings.ToValidUTF8(supplied.RepositoryRevision, "") != supplied.RepositoryRevision || len(supplied.RepositoryDigest) == 0 || len(supplied.RepositoryDigest) > 128 || supplied.Policy != nil {
			return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor context is invalid")
		}
		for prior := 0; prior < index; prior++ {
			if supplied.RepositoryRevision == contexts[prior].RepositoryRevision || bytes.Equal(supplied.RepositoryDigest, contexts[prior].RepositoryDigest) {
				return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor contexts are not distinct")
			}
		}
	}
	if absentView.Origin != binding || absentView.Scope != publicationstate.ViewScopeWholeRepository || len(absentView.Head) == 0 || !bytes.Equal(absentView.Head, replacementInput.HeadRecord) || absentView.Snapshots[0].Key != replacementInput.SnapshotKey || !bytes.Equal(absentView.Snapshots[0].Raw, replacementInput.SnapshotRecord) || cacheObservation.Origin != binding || len(cacheObservation.Head) == 0 || !bytes.Equal(cacheObservation.Head, replacementInput.HeadRecord) || cacheObservation.Snapshots[0].Key != replacementInput.SnapshotKey || !bytes.Equal(cacheObservation.Snapshots[0].Raw, replacementInput.SnapshotRecord) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor predecessor views differ")
	}
	if review.SelectionRevision == 0 || review.ApprovalRevision == 0 || allZero(review.SelectionDigest[:]) || allZero(review.ApprovalDigest[:]) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor local review is invalid")
	}
	predecessorView := publicationstate.SuppliedRepositoryView{
		Origin:          binding,
		Scope:           publicationstate.ViewScopeWholeRepository,
		SuppliedContext: publicationstate.SuppliedContext{RepositoryRevision: replacementFloor.SuppliedContext.RepositoryRevision, RepositoryDigest: bytes.Clone(replacementFloor.SuppliedContext.RepositoryDigest)},
		Head:            bytes.Clone(replacementInput.HeadRecord),
		Snapshots:       []publicationstate.SnapshotBlock{{Key: replacementInput.SnapshotKey, Raw: bytes.Clone(replacementInput.SnapshotRecord)}},
	}

	currentFloor, floorPresent, err := store.Load(ctx)
	if err != nil || !floorPresent || !reflect.DeepEqual(currentFloor, replacementFloor) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor current floor readback differs")
	}
	positionHistory, err := store.History(ctx, 0, 10)
	if err != nil || len(positionHistory.Events) != 2 || len(positionHistory.Records) != 2 || positionHistory.HasMore || positionHistory.NextRevision != 2 {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor accepted history shape differs")
	}
	genesisEvent := positionHistory.Events[0]
	if genesisEvent.Revision != 1 || genesisEvent.Mode != publicationstate.ModeFirstUse || genesisEvent.Reason != "" || genesisEvent.Stop != "first_use" || genesisEvent.OldFloor != nil || !reflect.DeepEqual(genesisEvent.NewFloor, genesis.Floor) || genesisEvent.EventDigest != genesis.Floor.AcceptedEventDigest || genesisEvent.ObservationDigest != genesis.Floor.ObservationDigest || len(genesisEvent.Trace) != 1 || genesisEvent.Trace[0].Key != genesisInput.SnapshotKey || genesisEvent.Trace[0].Sequence != 0 || !bytes.Equal(genesisEvent.Trace[0].CID, genesisRecordCID) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor genesis history differs")
	}
	replacementEvent := positionHistory.Events[1]
	if replacementEvent.Revision != 2 || replacementEvent.Mode != publicationstate.ModeReplaceFloor || replacementEvent.Reason != publicationstate.ReasonFork || replacementEvent.Stop != "fork" || replacementEvent.OldFloor == nil || !reflect.DeepEqual(*replacementEvent.OldFloor, genesis.Floor) || !reflect.DeepEqual(replacementEvent.NewFloor, replacementFloor) || replacementEvent.EventDigest != replacementFloor.AcceptedEventDigest || replacementEvent.ObservationDigest != replacementFloor.ObservationDigest || len(replacementEvent.Trace) != 1 || replacementEvent.Trace[0].Key != replacementInput.SnapshotKey || replacementEvent.Trace[0].Sequence != 0 || !bytes.Equal(replacementEvent.Trace[0].CID, replacementRecordCID) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor fork history differs")
	}
	foundGenesisRecord, foundReplacementRecord := false, false
	for _, record := range positionHistory.Records {
		if record.Reference.Key != replacementInput.SnapshotKey || record.Reference.Sequence != 0 {
			return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor accepted record reference differs")
		}
		if bytes.Equal(record.Reference.CID, genesisRecordCID) && bytes.Equal(record.Raw, genesisInput.SnapshotRecord) {
			foundGenesisRecord = true
		}
		if bytes.Equal(record.Reference.CID, replacementRecordCID) && bytes.Equal(record.Raw, replacementInput.SnapshotRecord) {
			foundReplacementRecord = true
		}
	}
	if !foundGenesisRecord || !foundReplacementRecord {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor accepted raw records differ")
	}
	currentPage, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	if err != nil || !reflect.DeepEqual(currentPage, priorPage) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor prior attempt history changed")
	}
	loadedGenesis, err := store.LoadAttempt(ctx, genesisAttemptID)
	if err != nil || loadedGenesis.ID != genesisAttemptID || loadedGenesis.Kind != publicationstate.AttemptGenesis || loadedGenesis.Lifecycle != publicationstate.AttemptRetiredSuccess || loadedGenesis.Outcome != publicationstate.OutcomeCurrent || loadedGenesis.Blocked != "" || loadedGenesis.StateDigest != genesis.Attempt.StateDigest || !bytes.Equal(loadedGenesis.SnapshotRecordCID, genesisRecordCID) || !bytes.Equal(loadedGenesis.HeadRecordCID, genesisHeadCID) || !bytes.Equal(loadedGenesis.BlobCID, genesisBlobCID) || loadedGenesis.BlobSize != uint64(len(genesisInput.Payload)) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor finalized genesis state differs")
	}
	loadedRetired, err := store.LoadAttempt(ctx, abandonedAttemptID)
	if err != nil || loadedRetired.ID != retiredAttempt.ID || loadedRetired.Kind != retiredAttempt.Kind || loadedRetired.Lifecycle != retiredAttempt.Lifecycle || loadedRetired.Outcome != retiredAttempt.Outcome || loadedRetired.Blocked != retiredAttempt.Blocked || loadedRetired.Sequence != retiredAttempt.Sequence || loadedRetired.SnapshotKey != retiredAttempt.SnapshotKey || !bytes.Equal(loadedRetired.SnapshotRecordCID, retiredAttempt.SnapshotRecordCID) || !bytes.Equal(loadedRetired.HeadRecordCID, retiredAttempt.HeadRecordCID) || !bytes.Equal(loadedRetired.BlobCID, retiredAttempt.BlobCID) || loadedRetired.BlobSize != retiredAttempt.BlobSize || loadedRetired.StateDigest != retiredAttempt.StateDigest || loadedRetired.CapturedFloor == nil || retiredAttempt.CapturedFloor == nil || !reflect.DeepEqual(*loadedRetired.CapturedFloor, *retiredAttempt.CapturedFloor) || loadedRetired.CapturedRevision != retiredAttempt.CapturedRevision || loadedRetired.CapturedGeneration != retiredAttempt.CapturedGeneration {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor retired attempt readback differs")
	}
	activeBefore, activeBeforePresent, err := store.ActiveAttempt(ctx)
	if err != nil || activeBeforePresent || activeBefore.ID != [16]byte{} {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor active slot is not empty")
	}
	storedConflict, storedConflictPresent, err := store.ReadFirstConflict(ctx, abandonedAttemptID)
	if err != nil || !storedConflictPresent || storedConflict.AttemptID != firstConflict.AttemptID || storedConflict.ID != firstConflict.ID || !bytes.Equal(storedConflict.Evidence, firstConflict.Evidence) || !bytes.Equal(storedConflict.Head, firstConflict.Head) || storedConflict.HeadKey != firstConflict.HeadKey || !bytes.Equal(storedConflict.HeadRecord, firstConflict.HeadRecord) || storedConflict.HeadSequence != firstConflict.HeadSequence {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor first-conflict readback differs")
	}
	genesisMaterial, err := store.ReadCandidate(ctx, genesisAttemptID)
	if err != nil || genesisMaterial.AttemptID != genesisAttemptID || genesisMaterial.SnapshotKey != genesisInput.SnapshotKey || !bytes.Equal(genesisMaterial.SnapshotRecord, genesisInput.SnapshotRecord) || !bytes.Equal(genesisMaterial.HeadRecord, genesisInput.HeadRecord) || !bytes.Equal(genesisMaterial.Payload, genesisInput.Payload) || !bytes.Equal(genesisMaterial.Blob.CID, genesisBlobCID) || genesisMaterial.Blob.Size != uint64(len(genesisInput.Payload)) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor retained genesis material differs")
	}
	abandonedRead, abandonedReadErr := store.ReadCandidate(ctx, abandonedAttemptID)
	var abandonedReadStateErr *publicationstate.Error
	if abandonedReadErr == nil || !reflect.DeepEqual(abandonedRead, publicationstate.CandidateMaterial{}) || !errors.As(abandonedReadErr, &abandonedReadStateErr) || abandonedReadStateErr == nil || abandonedReadStateErr.Class() != publicationstate.ErrStorage || abandonedReadStateErr.Stage() != publicationstate.StageCustody || abandonedReadStateErr.Reason() != publicationstate.ReasonCandidateMissing {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor abandoned candidate refusal differs")
	}
	unretainedBefore, unretainedBeforeErr := store.ReadAcceptedMaterial(ctx, binding, replacementFloor)
	var unretainedBeforeStateErr *publicationstate.Error
	if unretainedBeforeErr == nil || !reflect.DeepEqual(unretainedBefore, publicationstate.AcceptedMaterial{}) || !errors.As(unretainedBeforeErr, &unretainedBeforeStateErr) || unretainedBeforeStateErr == nil || unretainedBeforeStateErr.Class() != publicationstate.ErrStorage || unretainedBeforeStateErr.Stage() != publicationstate.StageReadAcceptedMaterial || unretainedBeforeStateErr.Reason() != publicationstate.ReasonMaterialNotRetained {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor position-only refusal differs")
	}

	priorEvidence := make(map[[16]byte]map[string][]byte, 2)
	priorEvidence[genesisAttemptID] = make(map[string][]byte, 2)
	priorEvidence[abandonedAttemptID] = make(map[string][]byte, 4)
	for _, evidence := range currentPage.Evidence {
		if len(evidence.Evidence) == 0 || (evidence.AttemptID != genesisAttemptID && evidence.AttemptID != abandonedAttemptID) {
			return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor prior evidence identity differs")
		}
		if _, exists := priorEvidence[evidence.AttemptID][evidence.Role]; exists {
			return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor prior evidence role is duplicated")
		}
		priorEvidence[evidence.AttemptID][evidence.Role] = bytes.Clone(evidence.Evidence)
	}
	if len(priorEvidence[genesisAttemptID]) != 2 || len(priorEvidence[abandonedAttemptID]) != 4 || len(priorEvidence[genesisAttemptID]["outcome"]) == 0 || len(priorEvidence[genesisAttemptID]["submission"]) == 0 || len(priorEvidence[abandonedAttemptID]["first-conflict"]) == 0 || len(priorEvidence[abandonedAttemptID]["outcome"]) == 0 || len(priorEvidence[abandonedAttemptID]["retirement"]) == 0 || len(priorEvidence[abandonedAttemptID]["submission"]) == 0 || !bytes.Equal(priorEvidence[abandonedAttemptID]["first-conflict"], firstConflict.Evidence) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor prior evidence roles are incomplete")
	}
	if !bytes.Equal(priorEvidence[abandonedAttemptID]["outcome"], priorEvidence[abandonedAttemptID]["retirement"]) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor retirement roles differ")
	}
	var retirementOutcome attemptOutcomeReadback
	if json.Unmarshal(priorEvidence[abandonedAttemptID]["outcome"], &retirementOutcome) != nil || retirementOutcome.Version != 1 || retirementOutcome.Role != "outcome" || retirementOutcome.Outcome != string(publicationstate.OutcomeLostFence) || len(retirementOutcome.ViewDigest) != 32 || allZero(retirementOutcome.ViewDigest) || retirementOutcome.AttemptedKey != abandonedMetadata.SnapshotKey || len(retirementOutcome.AttemptedRecord) == 0 || len(retirementOutcome.AttemptedRecord) > publication.MaxRecordBytes || len(firstConflict.HeadRecord) == 0 || len(firstConflict.HeadRecord) > publication.MaxRecordBytes || !bytes.Equal(retirementOutcome.AttemptedRecord, firstConflict.HeadRecord) || bytes.Equal(retirementOutcome.AttemptedRecord, abandonedRecordRaw) || len(retirementOutcome.PredecessorRecord) == 0 || len(retirementOutcome.PredecessorRecord) > publication.MaxRecordBytes || !bytes.Equal(retirementOutcome.PredecessorRecord, genesisInput.SnapshotRecord) || len(retirementOutcome.Head) == 0 || len(retirementOutcome.Head) > publication.MaxRecordBytes || len(firstConflict.Head) == 0 || len(firstConflict.Head) > publication.MaxRecordBytes || len(retirementOutcome.Suffix) != 3 || firstConflict.HeadSequence != 1 || firstConflict.HeadKey != abandonedMetadata.SnapshotKey {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor retirement proof shape differs")
	}
	retirementRecords := make([]publication.SnapshotRecord, 0, 3)
	retirementCIDs := make([][]byte, 0, 3)
	for index, block := range retirementOutcome.Suffix {
		sequence := uint64(index + 1)
		key, err := publication.SequenceKey(sequence)
		if err != nil || block.Key != key || len(block.Raw) == 0 || len(block.Raw) > publication.MaxRecordBytes {
			return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor retirement suffix shape differs")
		}
		record, err := publication.DecodeSnapshot(block.Raw)
		if err != nil || record.Vault != binding.Vault || record.PublicationSeq != sequence || allZero(record.PublicationID[:]) {
			return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor retirement suffix record differs")
		}
		if index == 0 {
			if !bytes.Equal(block.Raw, firstConflict.HeadRecord) || record.PublicationID == abandonedAttemptID || !bytes.Equal(record.Parent, genesisRecordCID) || publication.VerifySuccessor(genesisInput.SnapshotRecord, block.Raw, block.Key) != nil {
				return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor retirement occupant is not the first conflict")
			}
		} else if publication.VerifySuccessor(retirementOutcome.Suffix[index-1].Raw, block.Raw, block.Key) != nil {
			return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor retirement suffix lineage differs")
		}
		cid, err := publication.RecordCID(block.Raw)
		if err != nil {
			return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor retirement suffix CID is invalid")
		}
		retirementRecords = append(retirementRecords, record)
		retirementCIDs = append(retirementCIDs, cid)
	}
	firstConflictHead, err := publication.DecodeHead(firstConflict.Head)
	if err != nil || firstConflictHead.Vault != binding.Vault || firstConflictHead.PublicationSeq != 1 || !bytes.Equal(firstConflictHead.SnapshotCID, retirementCIDs[0]) || !bytes.Equal(firstConflictHead.BlobCID, retirementRecords[0].Blob.CID) || publication.VerifyHeadBinding(firstConflict.Head, firstConflict.HeadRecord, firstConflict.HeadKey) != nil {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor first-conflict head binding differs")
	}
	retirementHead, err := publication.DecodeHead(retirementOutcome.Head)
	if err != nil || retirementHead.Vault != binding.Vault || retirementHead.PublicationSeq != 3 || !bytes.Equal(retirementHead.SnapshotCID, retirementCIDs[2]) || !bytes.Equal(retirementHead.BlobCID, retirementRecords[2].Blob.CID) || publication.VerifyHeadBinding(retirementOutcome.Head, retirementOutcome.Suffix[2].Raw, retirementOutcome.Suffix[2].Key) != nil || bytes.Equal(retirementOutcome.Head, firstConflict.Head) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor retirement head binding differs")
	}
	var abandonedSubmission attemptOutcomeReadback
	if json.Unmarshal(priorEvidence[abandonedAttemptID]["submission"], &abandonedSubmission) != nil || abandonedSubmission.Version != 1 || abandonedSubmission.Role != "submission" || abandonedSubmission.Outcome != string(publicationstate.OutcomeUnresolved) || len(abandonedSubmission.ViewDigest) != 32 || abandonedSubmission.AttemptedKey != abandonedMetadata.SnapshotKey || !bytes.Equal(abandonedSubmission.AttemptedRecord, abandonedRecordRaw) || !bytes.Equal(abandonedSubmission.PredecessorRecord, genesisInput.SnapshotRecord) || !bytes.Equal(abandonedSubmission.Head, genesisInput.HeadRecord) || len(abandonedSubmission.Suffix) != 0 {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor abandoned submission evidence differs")
	}

	proposal, err := store.PrepareAttempt(ctx, successorInput, predecessorView, review)
	if err != nil || proposal.AttemptID != successorRecord.PublicationID || proposal.Kind != publicationstate.AttemptSuccessor || proposal.CapturedFloor == nil || !reflect.DeepEqual(*proposal.CapturedFloor, replacementFloor) || proposal.CapturedGeneration != replacementFloor.Generation || !bytes.Equal(proposal.CandidateRecordCID, successorRecordCID) || !bytes.Equal(proposal.CandidateBlobCID, successorBlobCID) || proposal.CandidateBlobSize != uint64(len(successorInput.Payload)) || allZero(proposal.StateToken[:]) || allZero(proposal.CandidateDigest[:]) || allZero(proposal.Confirmation[:]) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor proposal differs")
	}
	created, err := store.CreateAttempt(ctx, proposal.StateToken, successorInput, predecessorView, review, proposal.Confirmation)
	if err != nil || created.ID != proposal.AttemptID || created.Kind != publicationstate.AttemptSuccessor || created.Lifecycle != publicationstate.AttemptPrepared || created.Outcome != publicationstate.OutcomeNotSubmitted || created.Blocked != "" || created.Sequence != 1 || created.SnapshotKey != successorKey || !bytes.Equal(created.SnapshotRecordCID, successorRecordCID) || !bytes.Equal(created.HeadRecordCID, successorHeadCID) || !bytes.Equal(created.BlobCID, successorBlobCID) || created.BlobSize != uint64(len(successorInput.Payload)) || created.CapturedFloor == nil || !reflect.DeepEqual(*created.CapturedFloor, replacementFloor) || created.CapturedRevision != replacementFloor.Revision || created.CapturedGeneration != replacementFloor.Generation || allZero(created.StateDigest[:]) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor creation differs")
	}
	uploadProposal, err := store.PrepareDispatch(ctx, created.ID, publicationstate.DispatchUpload, predecessorView, review)
	if err != nil || uploadProposal.AttemptID != created.ID || uploadProposal.Kind != publicationstate.DispatchUpload || allZero(uploadProposal.StateToken[:]) || allZero(uploadProposal.Confirmation[:]) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor upload proposal differs")
	}
	upload, err := store.BeginUpload(ctx, created.ID, uploadProposal.StateToken, predecessorView, review, uploadProposal.Confirmation)
	if err != nil || upload.AttemptID != created.ID || !bytes.Equal(upload.Payload, successorInput.Payload) || !bytes.Equal(upload.Blob.CID, successorBlobCID) || upload.Blob.Size != uint64(len(successorInput.Payload)) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor upload material differs")
	}
	uploadState, err := store.LoadAttempt(ctx, created.ID)
	if err != nil || uploadState.ID != created.ID || uploadState.Kind != publicationstate.AttemptSuccessor || uploadState.Lifecycle != publicationstate.AttemptUploadStarted || uploadState.Outcome != publicationstate.OutcomeNotSubmitted || uploadState.Blocked != "" || uploadState.Sequence != 1 || uploadState.SnapshotKey != successorKey || !bytes.Equal(uploadState.SnapshotRecordCID, successorRecordCID) || !bytes.Equal(uploadState.HeadRecordCID, successorHeadCID) || !bytes.Equal(uploadState.BlobCID, successorBlobCID) || uploadState.BlobSize != uint64(len(successorInput.Payload)) || uploadState.CapturedFloor == nil || !reflect.DeepEqual(*uploadState.CapturedFloor, replacementFloor) || uploadState.CapturedRevision != replacementFloor.Revision || uploadState.CapturedGeneration != replacementFloor.Generation || allZero(uploadState.StateDigest[:]) || uploadState.StateDigest == created.StateDigest {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor upload state differs")
	}
	submissionProposal, err := store.PrepareDispatch(ctx, created.ID, publicationstate.DispatchSubmission, predecessorView, review)
	if err != nil || submissionProposal.AttemptID != created.ID || submissionProposal.Kind != publicationstate.DispatchSubmission || allZero(submissionProposal.StateToken[:]) || allZero(submissionProposal.Confirmation[:]) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor submission proposal differs")
	}
	submission, err := store.BeginSubmission(ctx, created.ID, submissionProposal.StateToken, predecessorView, review, submissionProposal.Confirmation)
	if err != nil || submission.AttemptID != created.ID || submission.SnapshotCollection != publication.SnapshotNSID || submission.SnapshotKey != successorKey || !bytes.Equal(submission.SnapshotRecord, successorInput.SnapshotRecord) || !bytes.Equal(submission.ExpectedSnapshotCID, successorRecordCID) || !submission.SnapshotCreateOnly || submission.HeadCollection != publication.HeadNSID || submission.HeadKey != "self" || !bytes.Equal(submission.HeadRecord, successorInput.HeadRecord) || submission.HeadCreate || !submission.RequiresAtomicBatch || !submission.RequiresCreateExclude || submission.RequiresPolicyCheck {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor submission material differs")
	}
	if submission.ExpectedPredecessor == nil || submission.ExpectedPredecessor.Key != replacementInput.SnapshotKey || !bytes.Equal(submission.ExpectedPredecessor.CID, replacementRecordCID) || submission.ExpectedPredecessor.Sequence != replacementFloor.Sequence || !reflect.DeepEqual(submission.ExpectedContext, predecessorView.SuppliedContext) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor submission predecessor differs")
	}
	submittedState, err := store.LoadAttempt(ctx, created.ID)
	if err != nil || submittedState.ID != created.ID || submittedState.Kind != publicationstate.AttemptSuccessor || submittedState.Lifecycle != publicationstate.AttemptMayHaveSubmitted || submittedState.Outcome != publicationstate.OutcomeUnresolved || submittedState.Blocked != "" || submittedState.Sequence != 1 || submittedState.SnapshotKey != successorKey || !bytes.Equal(submittedState.SnapshotRecordCID, successorRecordCID) || !bytes.Equal(submittedState.HeadRecordCID, successorHeadCID) || !bytes.Equal(submittedState.BlobCID, successorBlobCID) || submittedState.BlobSize != uint64(len(successorInput.Payload)) || submittedState.CapturedFloor == nil || !reflect.DeepEqual(*submittedState.CapturedFloor, replacementFloor) || submittedState.CapturedRevision != replacementFloor.Revision || submittedState.CapturedGeneration != replacementFloor.Generation || allZero(submittedState.StateDigest[:]) || submittedState.StateDigest == uploadState.StateDigest {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor submitted state differs")
	}
	submittedPage, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	if err != nil || len(submittedPage.Attempts) != 3 || len(submittedPage.Evidence) != 7 || submittedPage.HasMore || submittedPage.NextID != created.ID || !reflect.DeepEqual(submittedPage.Attempts[0], priorPage.Attempts[0]) || !reflect.DeepEqual(submittedPage.Attempts[1], priorPage.Attempts[1]) || submittedPage.Attempts[2].ID != created.ID || submittedPage.Attempts[2].StateDigest != submittedState.StateDigest {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor submitted history shape differs")
	}
	for _, evidence := range priorPage.Evidence {
		found := false
		for _, current := range submittedPage.Evidence {
			if current.AttemptID == evidence.AttemptID && current.Role == evidence.Role && bytes.Equal(current.Evidence, evidence.Evidence) {
				found = true
				break
			}
		}
		if !found {
			return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor changed prior evidence before resolution")
		}
	}
	var submittedEvidence []byte
	for _, evidence := range submittedPage.Evidence {
		if evidence.AttemptID != created.ID {
			continue
		}
		if evidence.Role != "submission" || len(evidence.Evidence) == 0 || len(submittedEvidence) != 0 {
			return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor submission evidence roles differ")
		}
		submittedEvidence = bytes.Clone(evidence.Evidence)
	}
	var submittedProjection attemptOutcomeReadback
	var submittedContextProjection struct {
		Context *publicationstate.SuppliedContext `json:"context"`
	}
	if len(submittedEvidence) == 0 || json.Unmarshal(submittedEvidence, &submittedProjection) != nil || json.Unmarshal(submittedEvidence, &submittedContextProjection) != nil || submittedProjection.Version != 1 || submittedProjection.Role != "submission" || submittedProjection.Outcome != string(publicationstate.OutcomeUnresolved) || len(submittedProjection.ViewDigest) != 32 || submittedProjection.AttemptedKey != successorKey || !bytes.Equal(submittedProjection.AttemptedRecord, successorInput.SnapshotRecord) || !bytes.Equal(submittedProjection.PredecessorRecord, replacementInput.SnapshotRecord) || !bytes.Equal(submittedProjection.Head, predecessorView.Head) || len(submittedProjection.Suffix) != 0 || submittedContextProjection.Context == nil || !reflect.DeepEqual(*submittedContextProjection.Context, submission.ExpectedContext) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor submission evidence differs")
	}

	resolution, err := store.ResolveAttempt(ctx, created.ID, submittedState.StateDigest, absentView)
	if err != nil || resolution.Outcome != publicationstate.OutcomeAbsentUnresolved || resolution.Attempt.ID != created.ID || resolution.Attempt.Kind != publicationstate.AttemptSuccessor || resolution.Attempt.Lifecycle != publicationstate.AttemptMayHaveSubmitted || resolution.Attempt.Outcome != publicationstate.OutcomeAbsentUnresolved || resolution.Attempt.Blocked != "" || resolution.Attempt.Sequence != 1 || resolution.Attempt.SnapshotKey != successorKey || !bytes.Equal(resolution.Attempt.SnapshotRecordCID, successorRecordCID) || !bytes.Equal(resolution.Attempt.HeadRecordCID, successorHeadCID) || !bytes.Equal(resolution.Attempt.BlobCID, successorBlobCID) || resolution.Attempt.BlobSize != uint64(len(successorInput.Payload)) || resolution.Attempt.CapturedFloor == nil || !reflect.DeepEqual(*resolution.Attempt.CapturedFloor, replacementFloor) || resolution.Attempt.CapturedRevision != replacementFloor.Revision || resolution.Attempt.CapturedGeneration != replacementFloor.Generation || allZero(resolution.Attempt.StateDigest[:]) || resolution.Attempt.StateDigest == submittedState.StateDigest || resolution.ViewDigest == [32]byte{} || len(resolution.Evidence) == 0 {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor absent resolution differs")
	}
	var absentProjection attemptOutcomeReadback
	var absentContextProjection struct {
		Context *publicationstate.SuppliedContext `json:"context"`
	}
	if json.Unmarshal(resolution.Evidence, &absentProjection) != nil || json.Unmarshal(resolution.Evidence, &absentContextProjection) != nil || absentProjection.Version != 1 || absentProjection.Role != "outcome" || absentProjection.Outcome != string(publicationstate.OutcomeAbsentUnresolved) || !bytes.Equal(absentProjection.ViewDigest, resolution.ViewDigest[:]) || absentProjection.AttemptedKey != successorKey || len(absentProjection.AttemptedRecord) != 0 || len(absentProjection.Suffix) != 0 || !bytes.Equal(absentProjection.PredecessorRecord, replacementInput.SnapshotRecord) || !bytes.Equal(absentProjection.Head, absentView.Head) || absentContextProjection.Context == nil || !reflect.DeepEqual(*absentContextProjection.Context, absentView.SuppliedContext) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor absent evidence differs")
	}
	resolvedState, err := store.LoadAttempt(ctx, created.ID)
	if err != nil || resolvedState.ID != created.ID || resolvedState.Lifecycle != publicationstate.AttemptMayHaveSubmitted || resolvedState.Outcome != publicationstate.OutcomeAbsentUnresolved || resolvedState.Blocked != "" || resolvedState.StateDigest != resolution.Attempt.StateDigest || !reflect.DeepEqual(resolvedState.CapturedFloor, resolution.Attempt.CapturedFloor) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor absent state readback differs")
	}
	activeAfterResolve, activeAfterResolvePresent, err := store.ActiveAttempt(ctx)
	if err != nil || !activeAfterResolvePresent || activeAfterResolve.ID != created.ID || activeAfterResolve.Lifecycle != publicationstate.AttemptMayHaveSubmitted || activeAfterResolve.Outcome != publicationstate.OutcomeAbsentUnresolved || activeAfterResolve.Blocked != "" || activeAfterResolve.StateDigest != resolution.Attempt.StateDigest || !reflect.DeepEqual(activeAfterResolve.CapturedFloor, resolution.Attempt.CapturedFloor) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor absent attempt is not active")
	}
	candidateMaterial, err := store.ReadCandidate(ctx, created.ID)
	if err != nil || candidateMaterial.AttemptID != created.ID || candidateMaterial.SnapshotKey != successorKey || !bytes.Equal(candidateMaterial.SnapshotRecord, successorInput.SnapshotRecord) || !bytes.Equal(candidateMaterial.HeadRecord, successorInput.HeadRecord) || !bytes.Equal(candidateMaterial.Payload, successorInput.Payload) || !bytes.Equal(candidateMaterial.Blob.CID, successorBlobCID) || candidateMaterial.Blob.Size != uint64(len(successorInput.Payload)) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor absent candidate material differs")
	}
	finalPage, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	if err != nil || len(finalPage.Attempts) != 3 || len(finalPage.Evidence) != 8 || finalPage.HasMore || finalPage.NextID != created.ID || !reflect.DeepEqual(finalPage.Attempts[0], priorPage.Attempts[0]) || !reflect.DeepEqual(finalPage.Attempts[1], priorPage.Attempts[1]) || finalPage.Attempts[2].ID != created.ID || finalPage.Attempts[2].Kind != publicationstate.AttemptSuccessor || finalPage.Attempts[2].Lifecycle != publicationstate.AttemptMayHaveSubmitted || finalPage.Attempts[2].Outcome != publicationstate.OutcomeAbsentUnresolved || finalPage.Attempts[2].Blocked != "" || finalPage.Attempts[2].StateDigest != resolution.Attempt.StateDigest || finalPage.Attempts[2].CapturedFloor == nil || !reflect.DeepEqual(*finalPage.Attempts[2].CapturedFloor, replacementFloor) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor final attempt history shape differs")
	}
	finalEvidence := make(map[[16]byte]map[string][]byte, 3)
	finalEvidence[genesisAttemptID] = make(map[string][]byte, 2)
	finalEvidence[abandonedAttemptID] = make(map[string][]byte, 4)
	finalEvidence[created.ID] = make(map[string][]byte, 2)
	for _, evidence := range finalPage.Evidence {
		if len(evidence.Evidence) == 0 {
			return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor final evidence is empty")
		}
		roles, ok := finalEvidence[evidence.AttemptID]
		if !ok {
			return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor final evidence identity differs")
		}
		if _, exists := roles[evidence.Role]; exists {
			return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor final evidence role is duplicated")
		}
		roles[evidence.Role] = bytes.Clone(evidence.Evidence)
	}
	if len(finalEvidence[genesisAttemptID]) != 2 || len(finalEvidence[abandonedAttemptID]) != 4 || len(finalEvidence[created.ID]) != 2 || !bytes.Equal(finalEvidence[genesisAttemptID]["outcome"], priorEvidence[genesisAttemptID]["outcome"]) || !bytes.Equal(finalEvidence[genesisAttemptID]["submission"], priorEvidence[genesisAttemptID]["submission"]) || !bytes.Equal(finalEvidence[abandonedAttemptID]["first-conflict"], priorEvidence[abandonedAttemptID]["first-conflict"]) || !bytes.Equal(finalEvidence[abandonedAttemptID]["outcome"], priorEvidence[abandonedAttemptID]["outcome"]) || !bytes.Equal(finalEvidence[abandonedAttemptID]["retirement"], priorEvidence[abandonedAttemptID]["retirement"]) || !bytes.Equal(finalEvidence[abandonedAttemptID]["submission"], priorEvidence[abandonedAttemptID]["submission"]) || !bytes.Equal(finalEvidence[created.ID]["outcome"], resolution.Evidence) || !bytes.Equal(finalEvidence[created.ID]["submission"], submittedEvidence) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor final evidence roles differ")
	}
	finalConflict, finalConflictPresent, err := store.ReadFirstConflict(ctx, abandonedAttemptID)
	if err != nil || !finalConflictPresent || finalConflict.AttemptID != firstConflict.AttemptID || finalConflict.ID != firstConflict.ID || !bytes.Equal(finalConflict.Evidence, firstConflict.Evidence) || !bytes.Equal(finalConflict.Head, firstConflict.Head) || finalConflict.HeadKey != firstConflict.HeadKey || !bytes.Equal(finalConflict.HeadRecord, firstConflict.HeadRecord) || finalConflict.HeadSequence != firstConflict.HeadSequence {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor immutable first-conflict differs")
	}
	finalFloor, finalFloorPresent, err := store.Load(ctx)
	if err != nil || !finalFloorPresent || !reflect.DeepEqual(finalFloor, replacementFloor) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor accepted floor changed")
	}
	finalHistory, err := store.History(ctx, 0, 10)
	if err != nil || !reflect.DeepEqual(finalHistory, positionHistory) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor accepted history changed")
	}
	genesisBeforeCache, err := store.ReadCandidate(ctx, genesisAttemptID)
	if err != nil || genesisBeforeCache.AttemptID != genesisAttemptID || genesisBeforeCache.SnapshotKey != genesisInput.SnapshotKey || !bytes.Equal(genesisBeforeCache.SnapshotRecord, genesisInput.SnapshotRecord) || !bytes.Equal(genesisBeforeCache.HeadRecord, genesisInput.HeadRecord) || !bytes.Equal(genesisBeforeCache.Payload, genesisInput.Payload) || !bytes.Equal(genesisBeforeCache.Blob.CID, genesisBlobCID) || genesisBeforeCache.Blob.Size != uint64(len(genesisInput.Payload)) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor pre-cache genesis material differs")
	}
	abandonedBeforeCache, abandonedBeforeCacheErr := store.ReadCandidate(ctx, abandonedAttemptID)
	var abandonedBeforeCacheStateErr *publicationstate.Error
	if abandonedBeforeCacheErr == nil || !reflect.DeepEqual(abandonedBeforeCache, publicationstate.CandidateMaterial{}) || !errors.As(abandonedBeforeCacheErr, &abandonedBeforeCacheStateErr) || abandonedBeforeCacheStateErr == nil || abandonedBeforeCacheStateErr.Class() != publicationstate.ErrStorage || abandonedBeforeCacheStateErr.Stage() != publicationstate.StageCustody || abandonedBeforeCacheStateErr.Reason() != publicationstate.ReasonCandidateMissing {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor pre-cache abandoned refusal differs")
	}
	positionBeforeCache, positionBeforeCacheErr := store.ReadAcceptedMaterial(ctx, binding, finalFloor)
	var positionBeforeCacheStateErr *publicationstate.Error
	if positionBeforeCacheErr == nil || !reflect.DeepEqual(positionBeforeCache, publicationstate.AcceptedMaterial{}) || !errors.As(positionBeforeCacheErr, &positionBeforeCacheStateErr) || positionBeforeCacheStateErr == nil || positionBeforeCacheStateErr.Class() != publicationstate.ErrStorage || positionBeforeCacheStateErr.Stage() != publicationstate.StageReadAcceptedMaterial || positionBeforeCacheStateErr.Reason() != publicationstate.ReasonMaterialNotRetained {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor pre-cache position-only refusal differs")
	}

	cacheID, err := store.RecordObservation(ctx, cacheObservation)
	if err != nil || allZero(cacheID[:]) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor cache observation failed")
	}
	cacheFloorAfterFirst, cacheFloorAfterFirstPresent, err := store.Load(ctx)
	if err != nil || !cacheFloorAfterFirstPresent || !reflect.DeepEqual(cacheFloorAfterFirst, finalFloor) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor cache changed floor")
	}
	cacheHistoryAfterFirst, err := store.History(ctx, 0, 10)
	if err != nil || !reflect.DeepEqual(cacheHistoryAfterFirst, finalHistory) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor cache changed accepted history")
	}
	cachePageAfterFirst, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	if err != nil || !reflect.DeepEqual(cachePageAfterFirst, finalPage) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor cache changed attempt evidence")
	}
	cacheActiveAfterFirst, cacheActiveAfterFirstPresent, err := store.ActiveAttempt(ctx)
	if err != nil || !cacheActiveAfterFirstPresent || cacheActiveAfterFirst.ID != created.ID || cacheActiveAfterFirst.Lifecycle != publicationstate.AttemptMayHaveSubmitted || cacheActiveAfterFirst.Outcome != publicationstate.OutcomeAbsentUnresolved || cacheActiveAfterFirst.Blocked != "" || cacheActiveAfterFirst.StateDigest != resolution.Attempt.StateDigest || cacheActiveAfterFirst.CapturedFloor == nil || !reflect.DeepEqual(*cacheActiveAfterFirst.CapturedFloor, replacementFloor) || cacheActiveAfterFirst.CapturedRevision != replacementFloor.Revision || cacheActiveAfterFirst.CapturedGeneration != replacementFloor.Generation {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor cache changed active attempt")
	}
	cacheMaterialAfterFirst, err := store.ReadCandidate(ctx, created.ID)
	if err != nil || !reflect.DeepEqual(cacheMaterialAfterFirst, candidateMaterial) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor cache changed candidate material")
	}
	cacheConflictAfterFirst, cacheConflictAfterFirstPresent, err := store.ReadFirstConflict(ctx, abandonedAttemptID)
	if err != nil || !cacheConflictAfterFirstPresent || cacheConflictAfterFirst.AttemptID != finalConflict.AttemptID || cacheConflictAfterFirst.ID != finalConflict.ID || !bytes.Equal(cacheConflictAfterFirst.Evidence, finalConflict.Evidence) || !bytes.Equal(cacheConflictAfterFirst.Head, finalConflict.Head) || cacheConflictAfterFirst.HeadKey != finalConflict.HeadKey || !bytes.Equal(cacheConflictAfterFirst.HeadRecord, finalConflict.HeadRecord) || cacheConflictAfterFirst.HeadSequence != finalConflict.HeadSequence {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor cache changed first-conflict")
	}
	secondCacheID, err := store.RecordObservation(ctx, cacheObservation)
	if err != nil || secondCacheID != cacheID {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor cache idempotency differs")
	}
	cacheFloorAfterSecond, cacheFloorAfterSecondPresent, err := store.Load(ctx)
	if err != nil || !cacheFloorAfterSecondPresent || !reflect.DeepEqual(cacheFloorAfterSecond, finalFloor) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor repeated cache changed floor")
	}
	cacheHistoryAfterSecond, err := store.History(ctx, 0, 10)
	if err != nil || !reflect.DeepEqual(cacheHistoryAfterSecond, finalHistory) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor repeated cache changed accepted history")
	}
	cachePageAfterSecond, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	if err != nil || !reflect.DeepEqual(cachePageAfterSecond, finalPage) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor repeated cache changed attempt evidence")
	}
	cacheActiveAfterSecond, cacheActiveAfterSecondPresent, err := store.ActiveAttempt(ctx)
	if err != nil || !cacheActiveAfterSecondPresent || cacheActiveAfterSecond.ID != created.ID || cacheActiveAfterSecond.Lifecycle != publicationstate.AttemptMayHaveSubmitted || cacheActiveAfterSecond.Outcome != publicationstate.OutcomeAbsentUnresolved || cacheActiveAfterSecond.Blocked != "" || cacheActiveAfterSecond.StateDigest != resolution.Attempt.StateDigest || cacheActiveAfterSecond.CapturedFloor == nil || !reflect.DeepEqual(*cacheActiveAfterSecond.CapturedFloor, replacementFloor) || cacheActiveAfterSecond.CapturedRevision != replacementFloor.Revision || cacheActiveAfterSecond.CapturedGeneration != replacementFloor.Generation {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor repeated cache changed active attempt")
	}
	cacheMaterialAfterSecond, err := store.ReadCandidate(ctx, created.ID)
	if err != nil || !reflect.DeepEqual(cacheMaterialAfterSecond, candidateMaterial) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor repeated cache changed candidate material")
	}
	cacheConflictAfterSecond, cacheConflictAfterSecondPresent, err := store.ReadFirstConflict(ctx, abandonedAttemptID)
	if err != nil || !cacheConflictAfterSecondPresent || cacheConflictAfterSecond.AttemptID != finalConflict.AttemptID || cacheConflictAfterSecond.ID != finalConflict.ID || !bytes.Equal(cacheConflictAfterSecond.Evidence, finalConflict.Evidence) || !bytes.Equal(cacheConflictAfterSecond.Head, finalConflict.Head) || cacheConflictAfterSecond.HeadKey != finalConflict.HeadKey || !bytes.Equal(cacheConflictAfterSecond.HeadRecord, finalConflict.HeadRecord) || cacheConflictAfterSecond.HeadSequence != finalConflict.HeadSequence {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor repeated cache changed first-conflict")
	}
	finalGenesisMaterial, err := store.ReadCandidate(ctx, genesisAttemptID)
	if err != nil || !reflect.DeepEqual(finalGenesisMaterial, genesisMaterial) {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor retained genesis material changed")
	}
	abandonedAfterCache, abandonedAfterCacheErr := store.ReadCandidate(ctx, abandonedAttemptID)
	var abandonedAfterCacheStateErr *publicationstate.Error
	if abandonedAfterCacheErr == nil || !reflect.DeepEqual(abandonedAfterCache, publicationstate.CandidateMaterial{}) || !errors.As(abandonedAfterCacheErr, &abandonedAfterCacheStateErr) || abandonedAfterCacheStateErr == nil || abandonedAfterCacheStateErr.Class() != publicationstate.ErrStorage || abandonedAfterCacheStateErr.Stage() != publicationstate.StageCustody || abandonedAfterCacheStateErr.Reason() != publicationstate.ReasonCandidateMissing {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor abandoned candidate refusal changed")
	}
	unretainedAfterCache, unretainedAfterCacheErr := store.ReadAcceptedMaterial(ctx, binding, finalFloor)
	var unretainedAfterCacheStateErr *publicationstate.Error
	if unretainedAfterCacheErr == nil || !reflect.DeepEqual(unretainedAfterCache, publicationstate.AcceptedMaterial{}) || !errors.As(unretainedAfterCacheErr, &unretainedAfterCacheStateErr) || unretainedAfterCacheStateErr == nil || unretainedAfterCacheStateErr.Class() != publicationstate.ErrStorage || unretainedAfterCacheStateErr.Stage() != publicationstate.StageReadAcceptedMaterial || unretainedAfterCacheStateErr.Reason() != publicationstate.ReasonMaterialNotRetained {
		return publicationstate.Floor{}, publicationstate.AttemptResolution{}, [32]byte{}, publicationstate.CandidateMaterial{}, publicationstate.AttemptPage{}, publicationstate.HistoryPage{}, publicationstate.FirstConflictEvidence{}, errors.New("replacement successor position-only refusal changed")
	}
	return finalFloor, resolution, cacheID, candidateMaterial, finalPage, finalHistory, finalConflict, nil
}

func syntheticCandidate(binding publicationstate.Binding, publicationID [16]byte, sequence uint64, parentCID []byte, content string) (publicationstate.CandidateInput, candidateValue, error) {
	if binding.Backend != publicationstate.BackendPublicRepo || allZero(publicationID[:]) || sequence > publication.MaxSequence || len(parentCID) > publication.MaxCIDBytes || (sequence == 0 && len(parentCID) != 0) || (sequence > 0 && len(parentCID) == 0) || content == "" {
		return publicationstate.CandidateInput{}, candidateValue{}, errors.New("synthetic candidate inputs are invalid")
	}
	key, err := publication.SequenceKey(sequence)
	if err != nil {
		return publicationstate.CandidateInput{}, candidateValue{}, errors.New("synthetic candidate sequence is invalid")
	}
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{{
			ID:            "synthetic-files",
			Source:        model.SourceFiles,
			SourceVersion: model.SourceVersion,
			Root:          &model.FileRoot{Base: model.RootHome, Path: "config", Kind: model.SelectionDirectory},
		}},
		Entries: []model.Entry{{
			TargetID: "synthetic-files",
			File: &model.FileEntry{
				Path:    "init.lua",
				State:   model.FilePresent,
				Kind:    model.FileRegular,
				Content: []byte(content),
				Mode:    0o600,
			},
		}},
	}
	if err := snapshot.Validate(); err != nil {
		return publicationstate.CandidateInput{}, candidateValue{}, errors.New("synthetic candidate snapshot is invalid")
	}
	packed, err := vault.Pack(snapshot)
	if err != nil {
		return publicationstate.CandidateInput{}, candidateValue{}, errors.New("synthetic candidate packing failed")
	}
	blobCID, err := publication.RawPayloadCID(packed.Payload)
	if err != nil {
		return publicationstate.CandidateInput{}, candidateValue{}, errors.New("synthetic candidate payload CID failed")
	}
	record, err := publication.EncodeSnapshot(publication.SnapshotRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          binding.Vault,
		PublicationID:  publicationID,
		PublicationSeq: sequence,
		Parent:         bytes.Clone(parentCID),
		Blob: publication.BlobReference{
			CID:  bytes.Clone(blobCID),
			Size: uint64(len(packed.Payload)),
		},
	})
	if err != nil {
		return publicationstate.CandidateInput{}, candidateValue{}, errors.New("synthetic candidate snapshot record encoding failed")
	}
	recordCID, err := publication.RecordCID(record)
	if err != nil {
		return publicationstate.CandidateInput{}, candidateValue{}, errors.New("synthetic candidate record CID failed")
	}
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion:  publication.SchemaVersion,
		Vault:          binding.Vault,
		PublicationSeq: sequence,
		SnapshotCID:    bytes.Clone(recordCID),
		BlobCID:        bytes.Clone(blobCID),
	})
	if err != nil {
		return publicationstate.CandidateInput{}, candidateValue{}, errors.New("synthetic candidate head encoding failed")
	}
	headCID, err := publication.RecordCID(head)
	if err != nil {
		return publicationstate.CandidateInput{}, candidateValue{}, errors.New("synthetic candidate head CID failed")
	}
	input := publicationstate.CandidateInput{
		SnapshotKey:    key,
		SnapshotRecord: bytes.Clone(record),
		HeadRecord:     bytes.Clone(head),
		Payload:        bytes.Clone(packed.Payload),
	}
	metadata := candidateValue{
		PublicationID:  hex.EncodeToString(publicationID[:]),
		SnapshotKey:    key,
		SnapshotCID:    encodeBytes(recordCID),
		HeadCID:        encodeBytes(headCID),
		BlobCID:        encodeBytes(blobCID),
		BlobSize:       uint64(len(input.Payload)),
		SnapshotRecord: encodeBytes(input.SnapshotRecord),
		HeadRecord:     encodeBytes(input.HeadRecord),
		Payload:        encodeBytes(input.Payload),
	}
	decodedRecord, err := publication.DecodeSnapshot(input.SnapshotRecord)
	if err != nil || decodedRecord.SchemaVersion != publication.SchemaVersion || decodedRecord.Vault != binding.Vault || decodedRecord.PublicationID != publicationID || decodedRecord.PublicationSeq != sequence || !bytes.Equal(decodedRecord.Parent, parentCID) || !bytes.Equal(decodedRecord.Blob.CID, blobCID) || decodedRecord.Blob.Size != uint64(len(input.Payload)) {
		return publicationstate.CandidateInput{}, candidateValue{}, errors.New("synthetic candidate record validation failed")
	}
	if !reflect.DeepEqual(encodeBytes(recordCID), metadata.SnapshotCID) || !reflect.DeepEqual(encodeBytes(headCID), metadata.HeadCID) || !reflect.DeepEqual(encodeBytes(blobCID), metadata.BlobCID) || metadata.SnapshotKey != input.SnapshotKey || metadata.BlobSize != uint64(len(input.Payload)) || !reflect.DeepEqual(encodeBytes(input.SnapshotRecord), metadata.SnapshotRecord) || !reflect.DeepEqual(encodeBytes(input.HeadRecord), metadata.HeadRecord) || !reflect.DeepEqual(encodeBytes(input.Payload), metadata.Payload) {
		return publicationstate.CandidateInput{}, candidateValue{}, errors.New("synthetic candidate metadata differs")
	}
	decodedHead, err := publication.DecodeHead(input.HeadRecord)
	if err != nil || decodedHead.SchemaVersion != publication.SchemaVersion || decodedHead.Vault != binding.Vault || decodedHead.PublicationSeq != sequence || !bytes.Equal(decodedHead.SnapshotCID, recordCID) || !bytes.Equal(decodedHead.BlobCID, blobCID) || publication.VerifyHeadBinding(input.HeadRecord, input.SnapshotRecord, key) != nil {
		return publicationstate.CandidateInput{}, candidateValue{}, errors.New("synthetic candidate head binding is invalid")
	}
	if err := publication.VerifyPayload(input.Payload, decodedRecord.Blob); err != nil {
		return publicationstate.CandidateInput{}, candidateValue{}, errors.New("synthetic candidate payload reference is invalid")
	}
	decodedSnapshot, err := publication.DecodePayload(input.Payload, decodedRecord.Blob)
	if err != nil || decodedSnapshot.Version != snapshot.Version || len(decodedSnapshot.Targets) != 1 || len(decodedSnapshot.Entries) != 1 {
		return publicationstate.CandidateInput{}, candidateValue{}, errors.New("synthetic candidate payload decoding failed")
	}
	decodedTarget := decodedSnapshot.Targets[0]
	decodedEntry := decodedSnapshot.Entries[0]
	if decodedTarget.ID != "synthetic-files" || decodedTarget.Source != model.SourceFiles || decodedTarget.SourceVersion != model.SourceVersion || decodedTarget.Root == nil || decodedTarget.Root.Base != model.RootHome || decodedTarget.Root.Path != "config" || decodedTarget.Root.Kind != model.SelectionDirectory || decodedEntry.TargetID != "synthetic-files" || decodedEntry.File == nil || decodedEntry.Setting != nil || decodedEntry.File.Path != "init.lua" || decodedEntry.File.State != model.FilePresent || decodedEntry.File.Kind != model.FileRegular || !bytes.Equal(decodedEntry.File.Content, []byte(content)) || decodedEntry.File.Mode != 0o600 || decodedEntry.File.LinkTarget != "" {
		return publicationstate.CandidateInput{}, candidateValue{}, errors.New("synthetic candidate decoded snapshot shape differs")
	}
	return input, metadata, nil
}

type mixedLifecycleState struct {
	Binding                     publicationstate.Binding
	Review                      publicationstate.LocalReviewContext
	GenesisInput                publicationstate.CandidateInput
	GenesisMetadata             candidateValue
	OwnSuccessorInput           publicationstate.CandidateInput
	OwnSuccessorMetadata        candidateValue
	CompetingOccupantInput      publicationstate.CandidateInput
	CompetingOccupantMetadata   candidateValue
	CompetingExtensionInput     publicationstate.CandidateInput
	CompetingExtensionMetadata  candidateValue
	ReplacementInput            publicationstate.CandidateInput
	ReplacementMetadata         candidateValue
	RetirementExtensionInput    publicationstate.CandidateInput
	RetirementExtensionMetadata candidateValue
	ActiveSuccessorInput        publicationstate.CandidateInput
	ActiveSuccessorMetadata     candidateValue
	EmptyGenesisView            publicationstate.SuppliedRepositoryView
	GenesisCurrentView          publicationstate.SuppliedRepositoryView
	PredecessorView             publicationstate.SuppliedRepositoryView
	FirstConflictView           publicationstate.SuppliedRepositoryView
	ExtendedView                publicationstate.SuppliedRepositoryView
	ReplacementObservation      publicationstate.Observation
	RetirementView              publicationstate.SuppliedRepositoryView
	AbsenceView                 publicationstate.SuppliedRepositoryView
	CacheObservation            publicationstate.Observation
	Genesis                     publicationstate.Finalization
	PriorLatest                 publicationstate.AttemptResolution
	PriorLatestEvidence         []byte
	FirstConflict               publicationstate.FirstConflictEvidence
	ReplacementFloor            publicationstate.Floor
	RetiredAttempt              publicationstate.Attempt
	RetirementPage              publicationstate.AttemptPage
	FinalFloor                  publicationstate.Floor
	AbsentResolution            publicationstate.AttemptResolution
	CacheID                     [32]byte
	ActiveMaterial              publicationstate.CandidateMaterial
	FinalPage                   publicationstate.AttemptPage
	FinalHistory                publicationstate.HistoryPage
	FinalFirstConflict          publicationstate.FirstConflictEvidence
}

func buildMixedLifecycle(ctx context.Context, store *publicationstate.Store, binding publicationstate.Binding) (mixedLifecycleState, error) {
	if ctx == nil || store == nil {
		return mixedLifecycleState{}, errors.New("mixed lifecycle inputs are invalid")
	}
	if ctx.Err() != nil {
		return mixedLifecycleState{}, errors.New("mixed lifecycle context is invalid")
	}
	var expectedBinding publicationstate.Binding
	expectedBinding.AccountDID = "did:plc:abcdefghijklmnopqrstuvwx"
	expectedBinding.Backend = publicationstate.BackendPublicRepo
	expectedBinding.Repository = "at://" + expectedBinding.AccountDID
	expectedBinding.Vault[0] = 9
	if binding != expectedBinding {
		return mixedLifecycleState{}, errors.New("mixed lifecycle binding is invalid")
	}
	state := mixedLifecycleState{Binding: binding}
	state.Review.SelectionDigest[0] = 0x51
	state.Review.ApprovalDigest[0] = 0x52
	state.Review.SelectionRevision = 1
	state.Review.ApprovalRevision = 1

	var genesisID [16]byte
	genesisID[0] = 0x43
	genesisID[15] = 0x18
	var ownSuccessorID [16]byte
	ownSuccessorID[0] = 0x44
	ownSuccessorID[15] = 0x19
	var competingID [16]byte
	competingID[0] = 0x45
	competingID[15] = 0x1a
	var extensionID [16]byte
	extensionID[0] = 0x46
	extensionID[15] = 0x1b
	var replacementID [16]byte
	replacementID[0] = 0x47
	replacementID[15] = 0x1c
	var retirementID [16]byte
	retirementID[0] = 0x48
	retirementID[15] = 0x1d
	var activeID [16]byte
	activeID[0] = 0x49
	activeID[15] = 0x1e

	var err error
	state.GenesisInput, state.GenesisMetadata, err = syntheticCandidate(binding, genesisID, 0, nil, "mixed retained genesis synthetic payload")
	if err != nil {
		return mixedLifecycleState{}, errors.New("mixed genesis candidate construction failed")
	}
	genesisCID, err := publication.RecordCID(state.GenesisInput.SnapshotRecord)
	if err != nil {
		return mixedLifecycleState{}, errors.New("mixed genesis record CID failed")
	}
	state.OwnSuccessorInput, state.OwnSuccessorMetadata, err = syntheticCandidate(binding, ownSuccessorID, 1, genesisCID, "original submitted successor payload")
	if err != nil {
		return mixedLifecycleState{}, errors.New("mixed submitted successor construction failed")
	}
	state.CompetingOccupantInput, state.CompetingOccupantMetadata, err = syntheticCandidate(binding, competingID, 1, genesisCID, "competing sequence-one occupant payload")
	if err != nil {
		return mixedLifecycleState{}, errors.New("mixed conflict occupant construction failed")
	}
	competingCID, err := publication.RecordCID(state.CompetingOccupantInput.SnapshotRecord)
	if err != nil {
		return mixedLifecycleState{}, errors.New("mixed conflict record CID failed")
	}
	state.CompetingExtensionInput, state.CompetingExtensionMetadata, err = syntheticCandidate(binding, extensionID, 2, competingCID, "competing sequence-two extension payload")
	if err != nil {
		return mixedLifecycleState{}, errors.New("mixed conflict extension construction failed")
	}
	state.ReplacementInput, state.ReplacementMetadata, err = syntheticCandidate(binding, replacementID, 0, nil, "replacement genesis synthetic payload")
	if err != nil {
		return mixedLifecycleState{}, errors.New("mixed replacement candidate construction failed")
	}
	replacementCID, err := publication.RecordCID(state.ReplacementInput.SnapshotRecord)
	if err != nil {
		return mixedLifecycleState{}, errors.New("mixed replacement record CID failed")
	}
	extensionCID, err := publication.RecordCID(state.CompetingExtensionInput.SnapshotRecord)
	if err != nil {
		return mixedLifecycleState{}, errors.New("mixed extension record CID failed")
	}
	state.RetirementExtensionInput, state.RetirementExtensionMetadata, err = syntheticCandidate(binding, retirementID, 3, extensionCID, "original-lineage sequence-three retirement extension payload")
	if err != nil {
		return mixedLifecycleState{}, errors.New("mixed retirement extension construction failed")
	}
	state.ActiveSuccessorInput, state.ActiveSuccessorMetadata, err = syntheticCandidate(binding, activeID, 1, replacementCID, "replacement-parented unresolved successor payload")
	if err != nil {
		return mixedLifecycleState{}, errors.New("mixed active successor construction failed")
	}

	inputs := []publicationstate.CandidateInput{state.GenesisInput, state.OwnSuccessorInput, state.CompetingOccupantInput, state.CompetingExtensionInput, state.ReplacementInput, state.RetirementExtensionInput, state.ActiveSuccessorInput}
	metadata := []candidateValue{state.GenesisMetadata, state.OwnSuccessorMetadata, state.CompetingOccupantMetadata, state.CompetingExtensionMetadata, state.ReplacementMetadata, state.RetirementExtensionMetadata, state.ActiveSuccessorMetadata}
	for index := range inputs {
		if metadata[index].AttemptID != "" || metadata[index].PublicationID == "" || inputs[index].SnapshotKey != metadata[index].SnapshotKey {
			return mixedLifecycleState{}, errors.New("mixed candidate metadata identity differs")
		}
		for prior := 0; prior < index; prior++ {
			if metadata[index].PublicationID == metadata[prior].PublicationID || bytes.Equal(inputs[index].Payload, inputs[prior].Payload) || bytes.Equal(mustDecodeBytes(metadata[index].BlobCID), mustDecodeBytes(metadata[prior].BlobCID)) || bytes.Equal(mustDecodeBytes(metadata[index].SnapshotCID), mustDecodeBytes(metadata[prior].SnapshotCID)) || bytes.Equal(mustDecodeBytes(metadata[index].HeadCID), mustDecodeBytes(metadata[prior].HeadCID)) {
				return mixedLifecycleState{}, errors.New("mixed candidate identities or bytes are not distinct")
			}
		}
	}

	emptyGenesisContext := publicationstate.SuppliedContext{RepositoryRevision: "synthetic-genesis-revision", RepositoryDigest: []byte{0x31, 0x32, 0x33, 0x34}}
	genesisContext := publicationstate.SuppliedContext{RepositoryRevision: "mixed-genesis-accepted-revision", RepositoryDigest: []byte{0x41, 0x42, 0x43, 0x44}}
	firstConflictContext := publicationstate.SuppliedContext{RepositoryRevision: "mixed-first-conflict-revision", RepositoryDigest: []byte{0x51, 0x52, 0x53, 0x54}}
	extendedContext := publicationstate.SuppliedContext{RepositoryRevision: "mixed-extended-conflict-revision", RepositoryDigest: []byte{0x61, 0x62, 0x63, 0x64}}
	replacementContext := publicationstate.SuppliedContext{RepositoryRevision: "mixed-replacement-floor-revision", RepositoryDigest: []byte{0x71, 0x72, 0x73, 0x74}}
	retirementContext := publicationstate.SuppliedContext{RepositoryRevision: "mixed-retirement-revision", RepositoryDigest: []byte{0x81, 0x82, 0x83, 0x84}}
	absenceContext := publicationstate.SuppliedContext{RepositoryRevision: "mixed-absence-revision", RepositoryDigest: []byte{0x91, 0x92, 0x93, 0x94}}
	cacheContext := publicationstate.SuppliedContext{RepositoryRevision: "mixed-cache-revision", RepositoryDigest: []byte{0xa1, 0xa2, 0xa3, 0xa4}}
	contexts := []publicationstate.SuppliedContext{emptyGenesisContext, genesisContext, firstConflictContext, extendedContext, replacementContext, retirementContext, absenceContext, cacheContext}
	for index, supplied := range contexts {
		if len(supplied.RepositoryRevision) == 0 || len(supplied.RepositoryRevision) > 1024 || strings.ToValidUTF8(supplied.RepositoryRevision, "") != supplied.RepositoryRevision || len(supplied.RepositoryDigest) == 0 || len(supplied.RepositoryDigest) > 128 || allZero(supplied.RepositoryDigest) || supplied.Policy != nil {
			return mixedLifecycleState{}, errors.New("mixed repository context is invalid")
		}
		for prior := 0; prior < index; prior++ {
			if supplied.RepositoryRevision == contexts[prior].RepositoryRevision || bytes.Equal(supplied.RepositoryDigest, contexts[prior].RepositoryDigest) {
				return mixedLifecycleState{}, errors.New("mixed repository contexts are not distinct")
			}
		}
	}

	genesisBlock := publicationstate.SnapshotBlock{Key: state.GenesisInput.SnapshotKey, Raw: bytes.Clone(state.GenesisInput.SnapshotRecord)}
	competingBlock := publicationstate.SnapshotBlock{Key: state.CompetingOccupantInput.SnapshotKey, Raw: bytes.Clone(state.CompetingOccupantInput.SnapshotRecord)}
	extensionBlock := publicationstate.SnapshotBlock{Key: state.CompetingExtensionInput.SnapshotKey, Raw: bytes.Clone(state.CompetingExtensionInput.SnapshotRecord)}
	replacementBlock := publicationstate.SnapshotBlock{Key: state.ReplacementInput.SnapshotKey, Raw: bytes.Clone(state.ReplacementInput.SnapshotRecord)}
	retirementBlock := publicationstate.SnapshotBlock{Key: state.RetirementExtensionInput.SnapshotKey, Raw: bytes.Clone(state.RetirementExtensionInput.SnapshotRecord)}
	state.EmptyGenesisView = publicationstate.SuppliedRepositoryView{Origin: binding, Scope: publicationstate.ViewScopeWholeRepository, SuppliedContext: emptyGenesisContext, Snapshots: []publicationstate.SnapshotBlock{}}
	state.GenesisCurrentView = publicationstate.SuppliedRepositoryView{Origin: binding, Scope: publicationstate.ViewScopeWholeRepository, SuppliedContext: genesisContext, Head: bytes.Clone(state.GenesisInput.HeadRecord), Snapshots: []publicationstate.SnapshotBlock{genesisBlock}}
	state.PredecessorView = publicationstate.SuppliedRepositoryView{Origin: binding, Scope: publicationstate.ViewScopeWholeRepository, SuppliedContext: genesisContext, Head: bytes.Clone(state.GenesisInput.HeadRecord), Snapshots: []publicationstate.SnapshotBlock{genesisBlock}}
	state.FirstConflictView = publicationstate.SuppliedRepositoryView{Origin: binding, Scope: publicationstate.ViewScopeWholeRepository, SuppliedContext: firstConflictContext, Head: bytes.Clone(state.CompetingOccupantInput.HeadRecord), Snapshots: []publicationstate.SnapshotBlock{genesisBlock, competingBlock}}
	state.ExtendedView = publicationstate.SuppliedRepositoryView{Origin: binding, Scope: publicationstate.ViewScopeWholeRepository, SuppliedContext: extendedContext, Head: bytes.Clone(state.CompetingExtensionInput.HeadRecord), Snapshots: []publicationstate.SnapshotBlock{genesisBlock, competingBlock, extensionBlock}}
	state.ReplacementObservation = publicationstate.Observation{Origin: binding, SuppliedContext: replacementContext, Head: bytes.Clone(state.ReplacementInput.HeadRecord), Snapshots: []publicationstate.SnapshotBlock{replacementBlock}}
	state.RetirementView = publicationstate.SuppliedRepositoryView{Origin: binding, Scope: publicationstate.ViewScopeWholeRepository, SuppliedContext: retirementContext, Head: bytes.Clone(state.RetirementExtensionInput.HeadRecord), Snapshots: []publicationstate.SnapshotBlock{genesisBlock, competingBlock, extensionBlock, retirementBlock}}
	state.AbsenceView = publicationstate.SuppliedRepositoryView{Origin: binding, Scope: publicationstate.ViewScopeWholeRepository, SuppliedContext: absenceContext, Head: bytes.Clone(state.ReplacementInput.HeadRecord), Snapshots: []publicationstate.SnapshotBlock{replacementBlock}}
	state.CacheObservation = publicationstate.Observation{Origin: binding, SuppliedContext: cacheContext, Head: bytes.Clone(state.ReplacementInput.HeadRecord), Snapshots: []publicationstate.SnapshotBlock{replacementBlock}}
	if len(state.EmptyGenesisView.Head) != 0 || len(state.EmptyGenesisView.Snapshots) != 0 || state.EmptyGenesisView.Origin != binding || state.EmptyGenesisView.Scope != publicationstate.ViewScopeWholeRepository || state.GenesisCurrentView.Origin != binding || state.GenesisCurrentView.Scope != publicationstate.ViewScopeWholeRepository || !reflect.DeepEqual(state.GenesisCurrentView.Snapshots, state.PredecessorView.Snapshots) || !bytes.Equal(state.GenesisCurrentView.Head, state.PredecessorView.Head) || !reflect.DeepEqual(state.GenesisCurrentView.SuppliedContext, state.PredecessorView.SuppliedContext) {
		return mixedLifecycleState{}, errors.New("mixed genesis views are inconsistent")
	}
	views := []publicationstate.SuppliedRepositoryView{state.GenesisCurrentView, state.PredecessorView, state.FirstConflictView, state.ExtendedView, state.RetirementView, state.AbsenceView}
	for _, view := range views {
		if view.Origin != binding || view.Scope != publicationstate.ViewScopeWholeRepository || len(view.Head) == 0 || len(view.Head) > publication.MaxRecordBytes || len(view.Snapshots) == 0 || len(view.Snapshots) > 4 {
			return mixedLifecycleState{}, errors.New("mixed repository view shape is invalid")
		}
		var lastRecord []byte
		for index, block := range view.Snapshots {
			key, keyErr := publication.SequenceKey(uint64(index))
			if keyErr != nil || block.Key != key || len(block.Raw) == 0 || len(block.Raw) > publication.MaxRecordBytes {
				return mixedLifecycleState{}, errors.New("mixed repository view record shape is invalid")
			}
			record, recordErr := publication.DecodeSnapshot(block.Raw)
			if recordErr != nil || record.Vault != binding.Vault || record.PublicationSeq != uint64(index) || allZero(record.PublicationID[:]) {
				return mixedLifecycleState{}, errors.New("mixed repository view record is invalid")
			}
			if index == 0 {
				if len(record.Parent) != 0 {
					return mixedLifecycleState{}, errors.New("mixed repository view genesis has a parent")
				}
			} else if err := publication.VerifySuccessor(lastRecord, block.Raw, block.Key); err != nil {
				return mixedLifecycleState{}, errors.New("mixed repository view lineage is invalid")
			}
			lastRecord = block.Raw
		}
		if err := publication.VerifyHeadBinding(view.Head, lastRecord, view.Snapshots[len(view.Snapshots)-1].Key); err != nil {
			return mixedLifecycleState{}, errors.New("mixed repository view head binding is invalid")
		}
	}
	if !bytes.Equal(state.FirstConflictView.Snapshots[0].Raw, state.GenesisInput.SnapshotRecord) || !bytes.Equal(state.ExtendedView.Snapshots[0].Raw, state.FirstConflictView.Snapshots[0].Raw) || !bytes.Equal(state.ExtendedView.Snapshots[1].Raw, state.FirstConflictView.Snapshots[1].Raw) || !bytes.Equal(state.RetirementView.Snapshots[0].Raw, state.ExtendedView.Snapshots[0].Raw) || !bytes.Equal(state.RetirementView.Snapshots[1].Raw, state.ExtendedView.Snapshots[1].Raw) || !bytes.Equal(state.RetirementView.Snapshots[2].Raw, state.ExtendedView.Snapshots[2].Raw) || !bytes.Equal(state.AbsenceView.Snapshots[0].Raw, state.ReplacementInput.SnapshotRecord) || !bytes.Equal(state.CacheObservation.Snapshots[0].Raw, state.ReplacementInput.SnapshotRecord) || !bytes.Equal(state.AbsenceView.Head, state.ReplacementInput.HeadRecord) || !bytes.Equal(state.CacheObservation.Head, state.ReplacementInput.HeadRecord) {
		return mixedLifecycleState{}, errors.New("mixed lifecycle view prefixes differ")
	}
	if state.ReplacementObservation.Origin != binding || len(state.ReplacementObservation.Snapshots) != 1 || !bytes.Equal(state.ReplacementObservation.Snapshots[0].Raw, state.ReplacementInput.SnapshotRecord) || state.ReplacementObservation.Snapshots[0].Key != state.ReplacementInput.SnapshotKey || !bytes.Equal(state.ReplacementObservation.Head, state.ReplacementInput.HeadRecord) || publication.VerifyHeadBinding(state.ReplacementObservation.Head, state.ReplacementObservation.Snapshots[0].Raw, state.ReplacementObservation.Snapshots[0].Key) != nil {
		return mixedLifecycleState{}, errors.New("mixed replacement observation differs")
	}

	genesis, err := finalizeGenesis(ctx, store, binding, state.GenesisInput, state.GenesisMetadata, state.EmptyGenesisView, state.GenesisCurrentView, state.Review)
	if err != nil {
		return mixedLifecycleState{}, errors.New("mixed genesis finalization failed")
	}
	if genesis.Attempt.ID != genesisID || genesis.Floor.Binding != binding || allZero(genesis.Floor.DatabaseID[:]) || genesis.Floor.Revision != 1 || genesis.Floor.Generation != 1 || genesis.Floor.SuppliedContext.Policy != nil || !reflect.DeepEqual(genesis.Floor.SuppliedContext, genesisContext) || !bytes.Equal(genesis.Floor.RecordCID, mustDecodeBytes(state.GenesisMetadata.SnapshotCID)) || !bytes.Equal(genesis.Floor.BlobCID, mustDecodeBytes(state.GenesisMetadata.BlobCID)) {
		return mixedLifecycleState{}, errors.New("mixed finalized genesis does not match constructed inputs")
	}
	state.Genesis = genesis
	state.PredecessorView.SuppliedContext = publicationstate.SuppliedContext{
		RepositoryRevision: genesis.Floor.SuppliedContext.RepositoryRevision,
		RepositoryDigest:   bytes.Clone(genesis.Floor.SuppliedContext.RepositoryDigest),
	}
	if !reflect.DeepEqual(state.PredecessorView.SuppliedContext, genesis.Floor.SuppliedContext) {
		return mixedLifecycleState{}, errors.New("mixed predecessor view does not use actual genesis floor context")
	}

	priorLatest, firstConflict, err := submitSuccessorThenExtendLostFence(ctx, store, binding, state.Genesis, state.GenesisInput, state.GenesisMetadata, state.OwnSuccessorInput, state.OwnSuccessorMetadata, state.PredecessorView, state.FirstConflictView, state.ExtendedView, state.Review)
	if err != nil {
		return mixedLifecycleState{}, errors.New("mixed lost-fence lifecycle failed")
	}
	if priorLatest.Outcome != publicationstate.OutcomeLostFence || priorLatest.Attempt.ID != ownSuccessorID || len(priorLatest.Evidence) == 0 || firstConflict.AttemptID != ownSuccessorID || allZero(firstConflict.ID[:]) || len(firstConflict.Evidence) == 0 {
		return mixedLifecycleState{}, errors.New("mixed pre-abandon proof identities differ")
	}
	state.PriorLatest = priorLatest
	state.PriorLatestEvidence = bytes.Clone(priorLatest.Evidence)
	state.FirstConflict = firstConflict

	replacementFloor, retiredAttempt, finalConflict, retirementPage, err := replaceFloorThenRetireLostFence(ctx, store, binding, state.Genesis, state.GenesisInput, state.GenesisMetadata, state.PriorLatest, state.ExtendedView, state.FirstConflict, state.ReplacementInput, state.ReplacementMetadata, state.ReplacementObservation, state.RetirementView)
	if err != nil {
		return mixedLifecycleState{}, errors.New("mixed replacement retirement lifecycle failed")
	}
	if replacementFloor.Binding != binding || replacementFloor.DatabaseID != state.Genesis.Floor.DatabaseID || replacementFloor.Revision != 2 || replacementFloor.Generation != 2 || replacementFloor.Provenance != publicationstate.ProvenanceReplace || !reflect.DeepEqual(replacementFloor.SuppliedContext, state.ReplacementObservation.SuppliedContext) || retiredAttempt.ID != ownSuccessorID || retiredAttempt.Lifecycle != publicationstate.AttemptRetiredAbandoned || retiredAttempt.Outcome != publicationstate.OutcomeLostFence || !reflect.DeepEqual(finalConflict, state.FirstConflict) || len(retirementPage.Attempts) != 2 || len(retirementPage.Evidence) != 6 || retirementPage.HasMore || retirementPage.NextID != ownSuccessorID || len(state.PriorLatestEvidence) == 0 {
		return mixedLifecycleState{}, errors.New("mixed replacement retirement outputs differ")
	}
	state.ReplacementFloor = replacementFloor
	state.RetiredAttempt = retiredAttempt
	state.RetirementPage = retirementPage
	state.FinalFirstConflict = finalConflict

	finalFloor, absentResolution, cacheID, activeMaterial, finalPage, finalHistory, finalConflict, err := submitReplacementSuccessorAbsentAndCache(ctx, store, binding, state.Genesis, state.GenesisInput, state.GenesisMetadata, state.ReplacementFloor, state.ReplacementInput, state.ReplacementMetadata, state.RetiredAttempt, state.OwnSuccessorMetadata, state.FirstConflict, state.RetirementPage, state.ActiveSuccessorInput, state.ActiveSuccessorMetadata, state.AbsenceView, state.CacheObservation, state.Review)
	if err != nil {
		return mixedLifecycleState{}, errors.New("mixed absent-unresolved cache lifecycle failed")
	}
	if !reflect.DeepEqual(finalFloor, state.ReplacementFloor) || absentResolution.Outcome != publicationstate.OutcomeAbsentUnresolved || absentResolution.Attempt.ID != activeID || absentResolution.Attempt.Lifecycle != publicationstate.AttemptMayHaveSubmitted || absentResolution.Attempt.Outcome != publicationstate.OutcomeAbsentUnresolved || absentResolution.Attempt.Blocked != "" || allZero(cacheID[:]) || activeMaterial.AttemptID != activeID || activeMaterial.SnapshotKey != state.ActiveSuccessorInput.SnapshotKey || !bytes.Equal(activeMaterial.SnapshotRecord, state.ActiveSuccessorInput.SnapshotRecord) || !bytes.Equal(activeMaterial.HeadRecord, state.ActiveSuccessorInput.HeadRecord) || !bytes.Equal(activeMaterial.Payload, state.ActiveSuccessorInput.Payload) || len(finalPage.Attempts) != 3 || len(finalPage.Evidence) != 8 || finalPage.HasMore || finalPage.NextID != activeID || len(finalHistory.Events) != 2 || len(finalHistory.Records) != 2 || finalHistory.HasMore || finalHistory.NextRevision != 2 || !reflect.DeepEqual(finalConflict, state.FirstConflict) || !bytes.Equal(state.PriorLatestEvidence, state.PriorLatest.Evidence) {
		return mixedLifecycleState{}, errors.New("mixed final lifecycle outputs differ")
	}
	state.FinalFloor = finalFloor
	state.AbsentResolution = absentResolution
	state.CacheID = cacheID
	state.ActiveMaterial = activeMaterial
	state.FinalPage = finalPage
	state.FinalHistory = finalHistory
	state.FinalFirstConflict = finalConflict
	return state, nil
}

type databaseSnapshot struct {
	Length int64
	SHA256 string
}

func snapshotClosedDatabase(path string) (databaseSnapshot, error) {
	sidecarPresent := false
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Lstat(path + suffix); err == nil {
			sidecarPresent = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return databaseSnapshot{}, errors.New("SQLite sidecar state cannot be checked")
		}
	}
	if sidecarPresent {
		return databaseSnapshot{}, errors.New("SQLite sidecar prevents immutable inventory")
	}
	if err := verifyPrivateFile(path); err != nil {
		return databaseSnapshot{}, errors.New("main database file is unsafe")
	}
	digest, length, err := hashFile(path, maxOutputBytes)
	if err != nil {
		return databaseSnapshot{}, errors.New("main database snapshot failed")
	}
	return databaseSnapshot{Length: length, SHA256: digest}, nil
}

func inspectDatabase(path string) (rowInventory, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || !filepath.IsAbs(absolute) {
		return rowInventory{}, errors.New("database path is invalid")
	}
	before, err := snapshotClosedDatabase(absolute)
	if err != nil {
		return rowInventory{}, err
	}
	dsn := (&url.URL{Scheme: "file", Path: absolute, RawQuery: "mode=ro&immutable=1"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return rowInventory{}, errors.New("read-only database open failed")
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	closed := false
	defer func() {
		if !closed {
			_ = db.Close()
		}
	}()
	var applicationID, userVersion int64
	if err := db.QueryRowContext(context.Background(), "PRAGMA application_id").Scan(&applicationID); err != nil {
		return rowInventory{}, errors.New("database application ID read failed")
	}
	if err := db.QueryRowContext(context.Background(), "PRAGMA user_version").Scan(&userVersion); err != nil {
		return rowInventory{}, errors.New("database schema version read failed")
	}
	if applicationID != sqliteApplicationID || userVersion != 2 {
		return rowInventory{}, errors.New("database is not the expected schema-2 store")
	}
	objects, err := readSchemaObjects(db)
	if err != nil {
		return rowInventory{}, err
	}
	metadataKeys, err := readMetadataKeys(db)
	if err != nil {
		return rowInventory{}, err
	}
	wantedKeys := []string{"attempt_limits", "attempt_mutation_revision", "binding", "database_id", "generation", "limits", "revision"}
	if !equalStrings(metadataKeys, wantedKeys) {
		return rowInventory{}, errors.New("database metadata key inventory differs")
	}
	inventory := rowInventory{
		FormatVersion: 1,
		ApplicationID: applicationID,
		UserVersion:   userVersion,
		MetadataKeys:  metadataKeys,
		SchemaObjects: objects,
		Tables:        make([]rawTable, 0, len(tableSpecs)),
	}
	var totalBytes int64
	for _, spec := range tableSpecs {
		table, err := readTable(db, spec)
		if err != nil {
			return rowInventory{}, err
		}
		encoded, err := json.Marshal(table)
		if err != nil || len(encoded) > maxJSONBytes {
			return rowInventory{}, errors.New("table inventory exceeds its bound")
		}
		totalBytes += int64(len(encoded))
		if totalBytes > maxJSONBytes {
			return rowInventory{}, errors.New("database inventory exceeds its bound")
		}
		inventory.Tables = append(inventory.Tables, table)
	}
	if err := validateInventoryShape(inventory); err != nil {
		return rowInventory{}, err
	}
	if err := db.Close(); err != nil {
		closed = true
		return rowInventory{}, errors.New("read-only database close failed")
	}
	closed = true
	after, err := snapshotClosedDatabase(absolute)
	if err != nil || after != before {
		return rowInventory{}, errors.New("main database changed during immutable inventory")
	}
	return inventory, nil
}

func readSchemaObjects(db *sql.DB) ([]schemaObject, error) {
	rows, err := db.QueryContext(context.Background(), "SELECT name,type,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' ORDER BY name")
	if err != nil {
		return nil, errors.New("schema object inventory query failed")
	}
	var resultErr error
	objects := make([]schemaObject, 0, len(tableSpecs)+len(indexSpecs))
	actual := make(map[string]schemaObject)
	for rows.Next() {
		var object schemaObject
		if err := rows.Scan(&object.Name, &object.Kind, &object.SQL); err != nil {
			resultErr = errors.New("schema object inventory scan failed")
			break
		}
		if _, exists := actual[object.Name]; exists {
			resultErr = errors.New("duplicate schema object")
			break
		}
		actual[object.Name] = object
		objects = append(objects, object)
	}
	if resultErr == nil && rows.Err() != nil {
		resultErr = errors.New("schema object inventory read failed")
	}
	if closeErr := rows.Close(); resultErr == nil && closeErr != nil {
		resultErr = errors.New("schema object rows close failed")
	}
	if resultErr != nil {
		return nil, resultErr
	}
	if len(actual) != len(tableSpecs)+len(indexSpecs) {
		return nil, errors.New("schema object count differs")
	}
	for _, spec := range tableSpecs {
		object, ok := actual[spec.Name]
		if !ok || object.Kind != "table" || strings.TrimSpace(object.SQL) != spec.DDL {
			return nil, errors.New("table definition differs from schema 2")
		}
	}
	for _, spec := range indexSpecs {
		object, ok := actual[spec.Name]
		if !ok || object.Kind != spec.Kind || strings.TrimSpace(object.SQL) != spec.SQL {
			return nil, errors.New("index definition differs from schema 2")
		}
	}
	return objects, nil
}

func readMetadataKeys(db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(context.Background(), "SELECT key FROM store_meta ORDER BY key")
	if err != nil {
		return nil, errors.New("metadata key query failed")
	}
	keys := make([]string, 0, 7)
	var resultErr error
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			resultErr = errors.New("metadata key scan failed")
			break
		}
		keys = append(keys, key)
		if len(keys) > 7 {
			resultErr = errors.New("metadata key count exceeds schema 2")
			break
		}
	}
	if resultErr == nil && rows.Err() != nil {
		resultErr = errors.New("metadata key read failed")
	}
	if closeErr := rows.Close(); resultErr == nil && closeErr != nil {
		resultErr = errors.New("metadata rows close failed")
	}
	if resultErr != nil {
		return nil, resultErr
	}
	return keys, nil
}

func readTable(db *sql.DB, spec tableSpec) (rawTable, error) {
	var count int64
	countQuery := "SELECT COUNT(*) FROM \"" + spec.Name + "\""
	if err := db.QueryRowContext(context.Background(), countQuery).Scan(&count); err != nil || count < 0 || count > maxTableRows {
		return rawTable{}, errors.New("table row count is invalid")
	}
	query := "SELECT * FROM \"" + spec.Name + "\" ORDER BY " + spec.OrderBy
	rows, err := db.QueryContext(context.Background(), query)
	if err != nil {
		return rawTable{}, errors.New("table row query failed")
	}
	result := rawTable{Name: spec.Name, DDL: spec.DDL, Columns: spec.Columns, RowCount: count, Rows: make([][]rawCell, 0, int(count))}
	var totalCellBytes int
	var resultErr error
	for rows.Next() {
		values := make([]any, len(spec.Columns))
		destinations := make([]any, len(values))
		for index := range values {
			destinations[index] = &values[index]
		}
		if err := rows.Scan(destinations...); err != nil {
			resultErr = errors.New("table row scan failed")
			break
		}
		row := make([]rawCell, len(values))
		for index, value := range values {
			cell, size, err := encodeCell(value)
			if err != nil || size > maxCellBytes {
				resultErr = errors.New("table cell has an unsupported type or size")
				break
			}
			totalCellBytes += size
			if totalCellBytes > maxJSONBytes {
				resultErr = errors.New("table cells exceed inventory bound")
				break
			}
			row[index] = cell
		}
		if resultErr != nil {
			break
		}
		result.Rows = append(result.Rows, row)
	}
	if resultErr == nil && rows.Err() != nil {
		resultErr = errors.New("table row read failed")
	}
	if closeErr := rows.Close(); resultErr == nil && closeErr != nil {
		resultErr = errors.New("table rows close failed")
	}
	if resultErr != nil {
		return rawTable{}, resultErr
	}
	if int64(len(result.Rows)) != count {
		return rawTable{}, errors.New("table row count changed during inventory")
	}
	return result, nil
}

func encodeCell(value any) (rawCell, int, error) {
	switch cell := value.(type) {
	case nil:
		return rawCell{Type: "null"}, 0, nil
	case int64:
		text := strconv.FormatInt(cell, 10)
		return rawCell{Type: "integer", Value: text}, len(text), nil
	case float64:
		bits := strconv.FormatUint(math.Float64bits(cell), 16)
		return rawCell{Type: "real64bits", Value: bits}, len(bits), nil
	case string:
		encoded := base64.StdEncoding.EncodeToString([]byte(cell))
		return rawCell{Type: "text-base64", Value: encoded}, len(cell), nil
	case []byte:
		encoded := base64.StdEncoding.EncodeToString(cell)
		return rawCell{Type: "blob-base64", Value: encoded}, len(cell), nil
	default:
		return rawCell{}, 0, errors.New("unsupported SQLite cell type")
	}
}

func validateInventoryShape(inventory rowInventory) error {
	if inventory.FormatVersion != 1 || len(inventory.Tables) != len(tableSpecs) || len(inventory.SchemaObjects) != len(tableSpecs)+len(indexSpecs) || inventory.UserVersion != 2 || inventory.ApplicationID != sqliteApplicationID || !equalStrings(inventory.MetadataKeys, []string{"attempt_limits", "attempt_mutation_revision", "binding", "database_id", "generation", "limits", "revision"}) {
		return errors.New("schema-2 inventory shape differs")
	}
	expectedObjects := make(map[string]schemaObject, len(tableSpecs)+len(indexSpecs))
	for _, spec := range tableSpecs {
		expectedObjects[spec.Name] = schemaObject{Name: spec.Name, Kind: "table", SQL: spec.DDL}
	}
	for _, spec := range indexSpecs {
		expectedObjects[spec.Name] = schemaObject{Name: spec.Name, Kind: spec.Kind, SQL: spec.SQL}
	}
	for _, object := range inventory.SchemaObjects {
		expected, exists := expectedObjects[object.Name]
		if !exists || object.Kind != expected.Kind || strings.TrimSpace(object.SQL) != expected.SQL {
			return errors.New("schema-2 schema object differs")
		}
		delete(expectedObjects, object.Name)
	}
	if len(expectedObjects) != 0 {
		return errors.New("schema-2 schema object set is incomplete")
	}
	for tableIndex, spec := range tableSpecs {
		table := inventory.Tables[tableIndex]
		if table.Name != spec.Name || strings.TrimSpace(table.DDL) != spec.DDL || !reflect.DeepEqual(table.Columns, spec.Columns) || table.RowCount < 0 || table.RowCount > maxTableRows || int64(len(table.Rows)) != table.RowCount {
			return errors.New("schema-2 table shape differs")
		}
		for _, row := range table.Rows {
			if len(row) != len(spec.Columns) {
				return errors.New("schema-2 row column count differs")
			}
			for columnIndex, cell := range row {
				wantType := map[string]string{"TEXT": "text-base64", "BLOB": "blob-base64", "INTEGER": "integer"}[spec.Columns[columnIndex].Type]
				if cell.Type == "null" {
					if (spec.Name == "accepted_events" && columnIndex == 4) || (spec.Name == "publication_attempts" && (columnIndex == 9 || columnIndex == 10)) {
						continue
					}
					return errors.New("schema-2 non-null column is null")
				}
				if wantType == "" || cell.Type != wantType {
					return errors.New("schema-2 cell type differs from declared column")
				}
			}
		}
	}
	return nil
}

func validateMixedRows(inventory rowInventory, state mixedLifecycleState) error {
	type wireBinding struct {
		AccountDID string `json:"accountDid"`
		Backend    string `json:"backend"`
		Repository string `json:"repository"`
		Vault      []byte `json:"vault"`
		Profile    string `json:"profile"`
	}
	type wirePolicy struct {
		Revision  string `json:"revision"`
		Identity  []byte `json:"identity"`
		OwnerOnly bool   `json:"ownerOnly"`
	}
	type wireContext struct {
		RepositoryRevision string      `json:"repositoryRevision"`
		RepositoryDigest   []byte      `json:"repositoryDigest"`
		Policy             *wirePolicy `json:"policy"`
	}
	type wireFloorCore struct {
		Version           uint32      `json:"version"`
		DatabaseID        []byte      `json:"databaseId"`
		Revision          uint64      `json:"revision"`
		Generation        uint64      `json:"generation"`
		Provenance        string      `json:"provenance"`
		AnchorCID         []byte      `json:"anchorCid"`
		Binding           wireBinding `json:"binding"`
		SuppliedContext   wireContext `json:"suppliedContext"`
		Head              []byte      `json:"head"`
		SnapshotKey       string      `json:"snapshotKey"`
		Sequence          uint64      `json:"sequence"`
		PublicationID     []byte      `json:"publicationId"`
		RecordCID         []byte      `json:"recordCid"`
		BlobCID           []byte      `json:"blobCid"`
		BlobSize          uint64      `json:"blobSize"`
		ObservationDigest []byte      `json:"observationDigest"`
	}
	type wireFloor struct {
		Version             uint32      `json:"version"`
		DatabaseID          []byte      `json:"databaseId"`
		Revision            uint64      `json:"revision"`
		Generation          uint64      `json:"generation"`
		Provenance          string      `json:"provenance"`
		AnchorCID           []byte      `json:"anchorCid"`
		Binding             wireBinding `json:"binding"`
		SuppliedContext     wireContext `json:"suppliedContext"`
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
	type wireReference struct {
		Key      string `json:"key"`
		CID      []byte `json:"cid"`
		Sequence uint64 `json:"sequence"`
	}
	type wireEventBody struct {
		Version           uint32          `json:"version"`
		Mode              string          `json:"mode"`
		Reason            string          `json:"reason"`
		OldFloor          *wireFloor      `json:"oldFloor"`
		NewFloor          wireFloorCore   `json:"newFloor"`
		Trace             []wireReference `json:"trace"`
		Stop              string          `json:"stop"`
		ObservationDigest []byte          `json:"observationDigest"`
		SuppliedSetDigest []byte          `json:"suppliedSetDigest"`
	}
	type wireLimits struct {
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
	type wireAttemptLimits struct {
		ActiveAttempts       uint32 `json:"activeAttempts"`
		HistoricalAttempts   uint32 `json:"historicalAttempts"`
		RetainedPublications uint32 `json:"retainedPublications"`
		ManagedObjects       uint32 `json:"managedObjects"`
		CustodyBytes         uint64 `json:"custodyBytes"`
		MetadataBytes        uint64 `json:"metadataBytes"`
		EvidenceBytes        uint64 `json:"evidenceBytes"`
		EvidenceSlotBytes    uint64 `json:"evidenceSlotBytes"`
		LifecycleEvents      uint32 `json:"lifecycleEvents"`
		EventBytes           uint64 `json:"eventBytes"`
		CoreBytes            uint64 `json:"coreBytes"`
		HistoryPageEntries   uint32 `json:"historyPageEntries"`
		HistoryPageBytes     uint64 `json:"historyPageBytes"`
	}
	type wireReview struct {
		SelectionDigest   []byte `json:"selectionDigest"`
		SelectionRevision uint64 `json:"selectionRevision"`
		ApprovalDigest    []byte `json:"approvalDigest"`
		ApprovalRevision  uint64 `json:"approvalRevision"`
	}
	type wireAttemptCore struct {
		Version                 uint32      `json:"version"`
		AttemptID               []byte      `json:"attemptId"`
		DatabaseID              []byte      `json:"databaseId"`
		Binding                 wireBinding `json:"binding"`
		Kind                    string      `json:"kind"`
		CapturedFloor           *wireFloor  `json:"capturedFloor"`
		CapturedRevision        uint64      `json:"capturedRevision"`
		CapturedGeneration      uint64      `json:"capturedGeneration"`
		PredecessorKey          string      `json:"predecessorKey"`
		PredecessorRecord       []byte      `json:"predecessorRecord"`
		PredecessorCID          []byte      `json:"predecessorCid"`
		SnapshotKey             string      `json:"snapshotKey"`
		SnapshotRecord          []byte      `json:"snapshotRecord"`
		SnapshotCID             []byte      `json:"snapshotCid"`
		HeadRecord              []byte      `json:"headRecord"`
		HeadCID                 []byte      `json:"headCid"`
		BlobCID                 []byte      `json:"blobCid"`
		BlobSize                uint64      `json:"blobSize"`
		InitialContext          wireContext `json:"initialContext"`
		InitialViewDigest       []byte      `json:"initialViewDigest"`
		Review                  wireReview  `json:"review"`
		CandidateConfirmation   []byte      `json:"candidateConfirmation"`
		ReservedCompletionBytes uint64      `json:"reservedCompletionBytes"`
	}
	type wireAttemptEvent struct {
		Version        uint32 `json:"version"`
		Ordinal        uint32 `json:"ordinal"`
		Kind           string `json:"kind"`
		PreviousDigest []byte `json:"previousDigest"`
		Evidence       []byte `json:"evidence"`
		StateDigest    []byte `json:"stateDigest"`
	}
	type wireAttemptEvidence struct {
		Version           uint32                           `json:"version"`
		Role              string                           `json:"role"`
		Scope             string                           `json:"scope"`
		ViewDigest        []byte                           `json:"viewDigest"`
		Origin            wireBinding                      `json:"origin"`
		Context           wireContext                      `json:"context"`
		Head              []byte                           `json:"head"`
		AttemptedKey      string                           `json:"attemptedKey"`
		AttemptedRecord   []byte                           `json:"attemptedRecord"`
		PredecessorRecord []byte                           `json:"predecessorRecord"`
		Suffix            []publicationstate.SnapshotBlock `json:"suffix"`
		Outcome           string                           `json:"outcome"`
	}
	type wireFirstConflict struct {
		Version          uint32              `json:"version"`
		AttemptID        []byte              `json:"attemptId"`
		CoreDigest       []byte              `json:"coreDigest"`
		EventOrdinal     uint32              `json:"eventOrdinal"`
		MutationRevision uint64              `json:"mutationRevision"`
		EventStateDigest []byte              `json:"eventStateDigest"`
		Blocked          string              `json:"blocked"`
		Proof            wireAttemptEvidence `json:"proof"`
	}
	type wireCacheObservation struct {
		Version           uint32        `json:"version"`
		ObservationDigest []byte        `json:"observationDigest"`
		SuppliedSetDigest []byte        `json:"suppliedSetDigest"`
		Context           wireContext   `json:"context"`
		Head              []byte        `json:"head"`
		Candidate         wireReference `json:"candidate"`
	}
	type wireObservation struct {
		Version           uint32      `json:"version"`
		Origin            wireBinding `json:"origin"`
		SuppliedContext   wireContext `json:"suppliedContext"`
		Head              []byte      `json:"head"`
		SuppliedSetDigest []byte      `json:"suppliedSetDigest"`
	}
	type candidateData struct {
		id        [16]byte
		input     publicationstate.CandidateInput
		record    publication.SnapshotRecord
		recordCID []byte
		headCID   []byte
		blobCID   []byte
	}

	decodeWire := func(raw []byte, target any) bool {
		if len(raw) == 0 || len(raw) > maxCellBytes {
			return false
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(target) != nil {
			return false
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return false
		}
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(false)
		if encoder.Encode(target) != nil {
			return false
		}
		return bytes.Equal(raw, bytes.TrimSuffix(encoded.Bytes(), []byte("\n")))
	}
	blobAt := func(row []rawCell, index int) ([]byte, bool) {
		if index < 0 || index >= len(row) || row[index].Type != "blob-base64" {
			return nil, false
		}
		value, err := base64.StdEncoding.DecodeString(row[index].Value)
		return value, err == nil
	}
	textAt := func(row []rawCell, index int) (string, bool) {
		if index < 0 || index >= len(row) || row[index].Type != "text-base64" {
			return "", false
		}
		value, err := base64.StdEncoding.DecodeString(row[index].Value)
		return string(value), err == nil
	}
	intAt := func(row []rawCell, index int) (int64, bool) {
		if index < 0 || index >= len(row) || row[index].Type != "integer" {
			return 0, false
		}
		value, err := strconv.ParseInt(row[index].Value, 10, 64)
		return value, err == nil && strconv.FormatInt(value, 10) == row[index].Value
	}
	bindMatches := func(wire wireBinding, binding publicationstate.Binding) bool {
		return wire.AccountDID == binding.AccountDID && wire.Backend == string(binding.Backend) && wire.Repository == binding.Repository && bytes.Equal(wire.Vault, binding.Vault[:]) && wire.Profile == storageProfile
	}
	contextMatches := func(wire wireContext, supplied publicationstate.SuppliedContext) bool {
		if wire.RepositoryRevision != supplied.RepositoryRevision || !bytes.Equal(wire.RepositoryDigest, supplied.RepositoryDigest) {
			return false
		}
		if supplied.Policy == nil {
			return wire.Policy == nil
		}
		return wire.Policy != nil && wire.Policy.Revision == supplied.Policy.Revision && bytes.Equal(wire.Policy.Identity, supplied.Policy.Identity) && wire.Policy.OwnerOnly == supplied.Policy.OwnerOnly
	}
	floorCoreMatches := func(wire wireFloorCore, floor publicationstate.Floor) bool {
		return wire.Version == 1 && bytes.Equal(wire.DatabaseID, floor.DatabaseID[:]) && wire.Revision == floor.Revision && wire.Generation == floor.Generation && wire.Provenance == string(floor.Provenance) && bytes.Equal(wire.AnchorCID, floor.AnchorCID) && bindMatches(wire.Binding, floor.Binding) && contextMatches(wire.SuppliedContext, floor.SuppliedContext) && bytes.Equal(wire.Head, floor.Head) && wire.SnapshotKey == floor.SnapshotKey && wire.Sequence == floor.Sequence && bytes.Equal(wire.PublicationID, floor.PublicationID[:]) && bytes.Equal(wire.RecordCID, floor.RecordCID) && bytes.Equal(wire.BlobCID, floor.BlobCID) && wire.BlobSize == floor.BlobSize && bytes.Equal(wire.ObservationDigest, floor.ObservationDigest[:])
	}
	floorMatches := func(wire wireFloor, floor publicationstate.Floor) bool {
		core := wireFloorCore{Version: wire.Version, DatabaseID: wire.DatabaseID, Revision: wire.Revision, Generation: wire.Generation, Provenance: wire.Provenance, AnchorCID: wire.AnchorCID, Binding: wire.Binding, SuppliedContext: wire.SuppliedContext, Head: wire.Head, SnapshotKey: wire.SnapshotKey, Sequence: wire.Sequence, PublicationID: wire.PublicationID, RecordCID: wire.RecordCID, BlobCID: wire.BlobCID, BlobSize: wire.BlobSize, ObservationDigest: wire.ObservationDigest}
		return floorCoreMatches(core, floor) && bytes.Equal(wire.AcceptedEventDigest, floor.AcceptedEventDigest[:])
	}
	domainHash := func(domain string, body []byte) []byte {
		hash := sha256.New()
		_, _ = hash.Write([]byte(domain))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(body)
		return hash.Sum(nil)
	}
	canonicalWire := func(value any) ([]byte, bool) {
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(false)
		if encoder.Encode(value) != nil {
			return nil, false
		}
		return bytes.TrimSuffix(encoded.Bytes(), []byte("\n")), true
	}
	bindingWireFor := func(value publicationstate.Binding) wireBinding {
		return wireBinding{AccountDID: value.AccountDID, Backend: string(value.Backend), Repository: value.Repository, Vault: bytes.Clone(value.Vault[:]), Profile: storageProfile}
	}
	contextWireFor := func(value publicationstate.SuppliedContext) wireContext {
		result := wireContext{RepositoryRevision: value.RepositoryRevision, RepositoryDigest: bytes.Clone(value.RepositoryDigest)}
		if value.Policy != nil {
			result.Policy = &wirePolicy{Revision: value.Policy.Revision, Identity: bytes.Clone(value.Policy.Identity), OwnerOnly: value.Policy.OwnerOnly}
		}
		return result
	}
	setDigestFor := func(blocks []publicationstate.SnapshotBlock) ([32]byte, error) {
		if len(blocks) == 0 || uint64(len(blocks)) > uint64(publicationstate.DefaultLimits().SuppliedSnapshotCount) {
			return [32]byte{}, errors.New("mixed observation block count is invalid")
		}
		hash := sha256.New()
		_, _ = hash.Write([]byte("systems.lamb.dottie.local-record-set.v1\x00"))
		var number [4]byte
		binary.BigEndian.PutUint32(number[:], uint32(len(blocks)))
		_, _ = hash.Write(number[:])
		for _, block := range blocks {
			if len(block.Key) == 0 || len(block.Key) > publication.MaxRecordBytes || len(block.Raw) == 0 || len(block.Raw) > publication.MaxRecordBytes {
				return [32]byte{}, errors.New("mixed observation block exceeds its bound")
			}
			_, _ = hash.Write([]byte(block.Key))
			binary.BigEndian.PutUint32(number[:], uint32(len(block.Raw)))
			_, _ = hash.Write(number[:])
			_, _ = hash.Write(block.Raw)
		}
		var digest [32]byte
		copy(digest[:], hash.Sum(nil))
		return digest, nil
	}
	observationDigests := func(origin publicationstate.Binding, supplied publicationstate.SuppliedContext, head []byte, blocks []publicationstate.SnapshotBlock) ([32]byte, [32]byte, error) {
		setDigest, err := setDigestFor(blocks)
		if err != nil {
			return [32]byte{}, [32]byte{}, err
		}
		wire := wireObservation{Version: 1, Origin: bindingWireFor(origin), SuppliedContext: contextWireFor(supplied), Head: bytes.Clone(head), SuppliedSetDigest: bytes.Clone(setDigest[:])}
		encoded, ok := canonicalWire(wire)
		if !ok {
			return [32]byte{}, [32]byte{}, errors.New("mixed observation wire encoding failed")
		}
		observationDigestRaw := domainHash("systems.lamb.dottie.local-observation.v1", encoded)
		var observationDigest [32]byte
		copy(observationDigest[:], observationDigestRaw)
		return setDigest, observationDigest, nil
	}
	if err := validateInventoryShape(inventory); err != nil {
		return err
	}
	if state.EmptyGenesisView.Origin != state.Binding || state.EmptyGenesisView.Scope != publicationstate.ViewScopeWholeRepository || len(state.EmptyGenesisView.Head) != 0 || len(state.EmptyGenesisView.Snapshots) != 0 || state.EmptyGenesisView.SuppliedContext.RepositoryRevision != "synthetic-genesis-revision" || !bytes.Equal(state.EmptyGenesisView.SuppliedContext.RepositoryDigest, []byte{0x31, 0x32, 0x33, 0x34}) || state.EmptyGenesisView.SuppliedContext.Policy != nil {
		return errors.New("mixed empty genesis input view differs")
	}
	wantedCounts := map[string]int64{
		"store_meta": 7, "cache_records": 1, "cache_observations": 1,
		"accepted_records": 2, "accepted_events": 2, "active_floor": 1,
		"publication_attempts": 3, "active_publication_attempt": 1,
		"pending_genesis": 0, "attempt_events": 15, "attempt_evidence": 5,
		"payload_objects": 3, "attempt_payload_refs": 1,
		"retained_publications": 1, "attempt_reservations": 1,
	}
	for _, table := range inventory.Tables {
		count, ok := wantedCounts[table.Name]
		if !ok || table.RowCount != count || int64(len(table.Rows)) != count {
			return errors.New("mixed schema-2 table count differs")
		}
	}
	binding := state.Binding
	var genesisID [16]byte
	genesisID[0], genesisID[15] = 0x43, 0x18
	var abandonedID [16]byte
	abandonedID[0], abandonedID[15] = 0x44, 0x19
	var replacementID [16]byte
	replacementID[0], replacementID[15] = 0x47, 0x1c
	var activeID [16]byte
	activeID[0], activeID[15] = 0x49, 0x1e
	if state.Genesis.Attempt.ID != genesisID || state.RetiredAttempt.ID != abandonedID || state.AbsentResolution.Attempt.ID != activeID || state.FinalFloor.Revision != 2 || state.FinalFloor.Generation != 2 || state.Genesis.Floor.Revision != 1 || state.Genesis.Floor.Generation != 1 || state.CacheID == [32]byte{} || !bytes.Equal(state.PriorLatestEvidence, state.PriorLatest.Evidence) {
		return errors.New("mixed fixed fixture identities or public lifecycle state differ")
	}
	candidateFor := func(input publicationstate.CandidateInput, id [16]byte, sequence uint64, parent []byte) (candidateData, error) {
		if len(input.SnapshotRecord) == 0 || len(input.HeadRecord) == 0 || len(input.Payload) == 0 {
			return candidateData{}, errors.New("mixed candidate bytes are empty")
		}
		record, err := publication.DecodeSnapshot(input.SnapshotRecord)
		if err != nil || record.Vault != binding.Vault || record.PublicationID != id || record.PublicationSeq != sequence || !bytes.Equal(record.Parent, parent) || record.Blob.Size != uint64(len(input.Payload)) {
			return candidateData{}, errors.New("mixed candidate record binding differs")
		}
		key, err := publication.SequenceKey(sequence)
		if err != nil || input.SnapshotKey != key {
			return candidateData{}, errors.New("mixed candidate key differs")
		}
		recordCID, err := publication.RecordCID(input.SnapshotRecord)
		if err != nil {
			return candidateData{}, errors.New("mixed candidate record CID differs")
		}
		head, err := publication.DecodeHead(input.HeadRecord)
		if err != nil || head.Vault != binding.Vault || head.PublicationSeq != sequence || !bytes.Equal(head.SnapshotCID, recordCID) || !bytes.Equal(head.BlobCID, record.Blob.CID) || publication.VerifyHeadBinding(input.HeadRecord, input.SnapshotRecord, input.SnapshotKey) != nil {
			return candidateData{}, errors.New("mixed candidate head binding differs")
		}
		headCID, err := publication.RecordCID(input.HeadRecord)
		if err != nil {
			return candidateData{}, errors.New("mixed candidate head CID is invalid")
		}
		blobCID, err := publication.RawPayloadCID(input.Payload)
		if err != nil || !bytes.Equal(blobCID, record.Blob.CID) || publication.VerifyPayload(input.Payload, record.Blob) != nil {
			return candidateData{}, errors.New("mixed candidate payload CID differs")
		}
		if _, err := publication.DecodePayload(input.Payload, record.Blob); err != nil {
			return candidateData{}, errors.New("mixed candidate packed payload differs")
		}
		return candidateData{id: id, input: input, record: record, recordCID: recordCID, headCID: headCID, blobCID: blobCID}, nil
	}
	genesis, err := candidateFor(state.GenesisInput, genesisID, 0, nil)
	if err != nil {
		return err
	}
	abandonedParentCID, err := publication.RecordCID(state.GenesisInput.SnapshotRecord)
	if err != nil {
		return errors.New("mixed abandoned predecessor CID is invalid")
	}
	abandoned, err := candidateFor(state.OwnSuccessorInput, abandonedID, 1, abandonedParentCID)
	if err != nil {
		return err
	}
	replacementData, err := candidateFor(state.ReplacementInput, replacementID, 0, nil)
	if err != nil {
		return errors.New("mixed fixed replacement candidate differs")
	}
	replacementCID := replacementData.recordCID
	active, err := candidateFor(state.ActiveSuccessorInput, activeID, 1, replacementCID)
	if err != nil {
		return err
	}
	if bytes.Equal(genesis.recordCID, abandoned.recordCID) || bytes.Equal(genesis.recordCID, replacementData.recordCID) || bytes.Equal(genesis.recordCID, active.recordCID) || bytes.Equal(abandoned.recordCID, replacementData.recordCID) || bytes.Equal(abandoned.recordCID, active.recordCID) || bytes.Equal(replacementData.recordCID, active.recordCID) || bytes.Equal(genesis.blobCID, abandoned.blobCID) || bytes.Equal(genesis.blobCID, replacementData.blobCID) || bytes.Equal(genesis.blobCID, active.blobCID) || bytes.Equal(abandoned.blobCID, replacementData.blobCID) || bytes.Equal(abandoned.blobCID, active.blobCID) || bytes.Equal(replacementData.blobCID, active.blobCID) || bytes.Equal(genesis.input.Payload, abandoned.input.Payload) || bytes.Equal(genesis.input.Payload, replacementData.input.Payload) || bytes.Equal(genesis.input.Payload, active.input.Payload) || bytes.Equal(abandoned.input.Payload, replacementData.input.Payload) || bytes.Equal(abandoned.input.Payload, active.input.Payload) || bytes.Equal(replacementData.input.Payload, active.input.Payload) {
		return errors.New("mixed custody role bytes or CIDs are not distinct")
	}
	if state.Genesis.Floor.DatabaseID == [32]byte{} || state.FinalFloor.DatabaseID != state.Genesis.Floor.DatabaseID {
		return errors.New("mixed accepted floor database binding differs")
	}
	if state.GenesisCurrentView.Origin != binding || state.GenesisCurrentView.Scope != publicationstate.ViewScopeWholeRepository || len(state.GenesisCurrentView.Snapshots) != 1 || !reflect.DeepEqual(state.GenesisCurrentView.SuppliedContext, state.Genesis.Floor.SuppliedContext) || state.GenesisCurrentView.Snapshots[0].Key != state.GenesisInput.SnapshotKey || !bytes.Equal(state.GenesisCurrentView.Snapshots[0].Raw, state.GenesisInput.SnapshotRecord) || !bytes.Equal(state.GenesisCurrentView.Head, state.GenesisInput.HeadRecord) || publication.VerifyHeadBinding(state.GenesisCurrentView.Head, state.GenesisCurrentView.Snapshots[0].Raw, state.GenesisCurrentView.Snapshots[0].Key) != nil {
		return errors.New("mixed genesis accepted observation input differs")
	}
	if state.ReplacementObservation.Origin != binding || len(state.ReplacementObservation.Snapshots) != 1 || state.ReplacementObservation.Snapshots[0].Key != state.ReplacementInput.SnapshotKey || !bytes.Equal(state.ReplacementObservation.Snapshots[0].Raw, state.ReplacementInput.SnapshotRecord) || !bytes.Equal(state.ReplacementObservation.Head, state.ReplacementInput.HeadRecord) || !reflect.DeepEqual(state.ReplacementObservation.SuppliedContext, state.FinalFloor.SuppliedContext) || !bytes.Equal(state.FinalFloor.Head, state.ReplacementObservation.Head) {
		return errors.New("mixed replacement accepted observation input differs")
	}
	if state.PredecessorView.Origin != binding || state.PredecessorView.Scope != publicationstate.ViewScopeWholeRepository || len(state.PredecessorView.Snapshots) != 1 || !reflect.DeepEqual(state.PredecessorView.SuppliedContext, state.Genesis.Floor.SuppliedContext) || state.PredecessorView.Snapshots[0].Key != state.GenesisInput.SnapshotKey || !bytes.Equal(state.PredecessorView.Snapshots[0].Raw, state.GenesisInput.SnapshotRecord) || !bytes.Equal(state.PredecessorView.Head, state.GenesisInput.HeadRecord) {
		return errors.New("mixed successor predecessor view differs")
	}
	if state.FirstConflictView.Origin != binding || state.FirstConflictView.Scope != publicationstate.ViewScopeWholeRepository || len(state.FirstConflictView.Snapshots) != 2 || state.FirstConflictView.Snapshots[0].Key != state.GenesisInput.SnapshotKey || !bytes.Equal(state.FirstConflictView.Snapshots[0].Raw, state.GenesisInput.SnapshotRecord) || state.FirstConflictView.Snapshots[1].Key != state.CompetingOccupantInput.SnapshotKey || !bytes.Equal(state.FirstConflictView.Snapshots[1].Raw, state.CompetingOccupantInput.SnapshotRecord) || !bytes.Equal(state.FirstConflictView.Head, state.CompetingOccupantInput.HeadRecord) || publication.VerifySuccessor(state.GenesisInput.SnapshotRecord, state.FirstConflictView.Snapshots[1].Raw, state.FirstConflictView.Snapshots[1].Key) != nil || publication.VerifyHeadBinding(state.FirstConflictView.Head, state.FirstConflictView.Snapshots[1].Raw, state.FirstConflictView.Snapshots[1].Key) != nil {
		return errors.New("mixed first-conflict constructor view differs")
	}
	competingCID, competingCIDErr := publication.RecordCID(state.CompetingOccupantInput.SnapshotRecord)
	if competingCIDErr != nil || bytes.Equal(state.CompetingOccupantInput.SnapshotRecord, abandoned.input.SnapshotRecord) || bytes.Equal(competingCID, abandoned.recordCID) {
		return errors.New("mixed competing occupant is not distinct from abandoned candidate")
	}
	if state.ExtendedView.Origin != binding || state.ExtendedView.Scope != publicationstate.ViewScopeWholeRepository || len(state.ExtendedView.Snapshots) != 3 || state.ExtendedView.Snapshots[0].Key != state.GenesisInput.SnapshotKey || !bytes.Equal(state.ExtendedView.Snapshots[0].Raw, state.GenesisInput.SnapshotRecord) || state.ExtendedView.Snapshots[1].Key != state.CompetingOccupantInput.SnapshotKey || !bytes.Equal(state.ExtendedView.Snapshots[1].Raw, state.CompetingOccupantInput.SnapshotRecord) || state.ExtendedView.Snapshots[2].Key != state.CompetingExtensionInput.SnapshotKey || !bytes.Equal(state.ExtendedView.Snapshots[2].Raw, state.CompetingExtensionInput.SnapshotRecord) || publication.VerifySuccessor(state.ExtendedView.Snapshots[1].Raw, state.ExtendedView.Snapshots[2].Raw, state.ExtendedView.Snapshots[2].Key) != nil || !bytes.Equal(state.ExtendedView.Head, state.CompetingExtensionInput.HeadRecord) || publication.VerifyHeadBinding(state.ExtendedView.Head, state.ExtendedView.Snapshots[2].Raw, state.ExtendedView.Snapshots[2].Key) != nil {
		return errors.New("mixed extended constructor view differs")
	}
	if state.AbsenceView.Origin != binding || state.AbsenceView.Scope != publicationstate.ViewScopeWholeRepository || len(state.AbsenceView.Snapshots) != 1 || state.AbsenceView.Snapshots[0].Key != state.ReplacementInput.SnapshotKey || !bytes.Equal(state.AbsenceView.Snapshots[0].Raw, state.ReplacementInput.SnapshotRecord) || !bytes.Equal(state.AbsenceView.Head, state.ReplacementInput.HeadRecord) || publication.VerifyHeadBinding(state.AbsenceView.Head, state.AbsenceView.Snapshots[0].Raw, state.AbsenceView.Snapshots[0].Key) != nil {
		return errors.New("mixed absence constructor view differs")
	}
	if state.CacheObservation.Origin != binding || len(state.CacheObservation.Snapshots) != 1 || state.CacheObservation.Snapshots[0].Key != state.ReplacementInput.SnapshotKey || !bytes.Equal(state.CacheObservation.Snapshots[0].Raw, state.ReplacementInput.SnapshotRecord) || !bytes.Equal(state.CacheObservation.Head, state.ReplacementInput.HeadRecord) || publication.VerifyHeadBinding(state.CacheObservation.Head, state.CacheObservation.Snapshots[0].Raw, state.CacheObservation.Snapshots[0].Key) != nil {
		return errors.New("mixed cache observation input differs")
	}
	genesisSetDigest, genesisObservationDigest, err := observationDigests(state.GenesisCurrentView.Origin, state.GenesisCurrentView.SuppliedContext, state.GenesisCurrentView.Head, state.GenesisCurrentView.Snapshots)
	if err != nil || genesisObservationDigest != state.Genesis.Floor.ObservationDigest {
		return errors.New("mixed genesis observation digest input differs")
	}
	replacementSetDigest, replacementObservationDigest, err := observationDigests(state.ReplacementObservation.Origin, state.ReplacementObservation.SuppliedContext, state.ReplacementObservation.Head, state.ReplacementObservation.Snapshots)
	if err != nil || replacementObservationDigest != state.FinalFloor.ObservationDigest {
		return errors.New("mixed replacement observation digest input differs")
	}
	cacheSetDigest, cacheObservationDigest, err := observationDigests(state.CacheObservation.Origin, state.CacheObservation.SuppliedContext, state.CacheObservation.Head, state.CacheObservation.Snapshots)
	if err != nil || cacheSetDigest != replacementSetDigest {
		return errors.New("mixed cache observation set digest input differs")
	}
	genesisFloor := state.Genesis.Floor
	if genesisFloor.DatabaseID == [32]byte{} || genesisFloor.Revision != 1 || genesisFloor.Generation != 1 || genesisFloor.Provenance != publicationstate.ProvenanceFirst || genesisFloor.Binding != binding || !bytes.Equal(genesisFloor.AnchorCID, genesis.recordCID) || !bytes.Equal(genesisFloor.Head, genesis.input.HeadRecord) || genesisFloor.SnapshotKey != genesis.input.SnapshotKey || genesisFloor.Sequence != genesis.record.PublicationSeq || genesisFloor.PublicationID != genesisID || !bytes.Equal(genesisFloor.RecordCID, genesis.recordCID) || !bytes.Equal(genesisFloor.BlobCID, genesis.record.Blob.CID) || genesisFloor.BlobSize != genesis.record.Blob.Size || !reflect.DeepEqual(genesisFloor.SuppliedContext, state.GenesisCurrentView.SuppliedContext) || genesisFloor.ObservationDigest != genesisObservationDigest || allZero(genesisFloor.AcceptedEventDigest[:]) {
		return errors.New("mixed genesis public floor does not match constructor record")
	}
	finalFloor := state.FinalFloor
	if finalFloor.Revision != 2 || finalFloor.Generation != 2 || finalFloor.Provenance != publicationstate.ProvenanceReplace || finalFloor.Binding != binding || finalFloor.DatabaseID != genesisFloor.DatabaseID || !bytes.Equal(finalFloor.AnchorCID, replacementData.recordCID) || !bytes.Equal(finalFloor.Head, replacementData.input.HeadRecord) || finalFloor.SnapshotKey != replacementData.input.SnapshotKey || finalFloor.Sequence != replacementData.record.PublicationSeq || finalFloor.PublicationID != replacementID || !bytes.Equal(finalFloor.RecordCID, replacementData.recordCID) || !bytes.Equal(finalFloor.BlobCID, replacementData.record.Blob.CID) || finalFloor.BlobSize != replacementData.record.Blob.Size || !reflect.DeepEqual(finalFloor.SuppliedContext, state.ReplacementObservation.SuppliedContext) || finalFloor.ObservationDigest != replacementObservationDigest || allZero(finalFloor.AcceptedEventDigest[:]) || !reflect.DeepEqual(state.ReplacementFloor, finalFloor) {
		return errors.New("mixed replacement public floor does not match constructor record")
	}

	rowsFor := func(name string) [][]rawCell { return tableByName(inventory, name).Rows }
	meta := make(map[string][]byte, 7)
	metaKeys := make([]string, 0, 7)
	for _, row := range rowsFor("store_meta") {
		key, keyOK := textAt(row, 0)
		value, valueOK := blobAt(row, 1)
		if !keyOK || !valueOK || len(value) == 0 {
			return errors.New("mixed metadata cell type differs")
		}
		if _, exists := meta[key]; exists {
			return errors.New("mixed metadata key is duplicated")
		}
		meta[key] = value
		metaKeys = append(metaKeys, key)
	}
	if !equalStrings(metaKeys, []string{"attempt_limits", "attempt_mutation_revision", "binding", "database_id", "generation", "limits", "revision"}) || len(meta["database_id"]) != 32 || !bytes.Equal(meta["database_id"], state.FinalFloor.DatabaseID[:]) || len(meta["revision"]) != 8 || binary.BigEndian.Uint64(meta["revision"]) != 2 || len(meta["generation"]) != 8 || binary.BigEndian.Uint64(meta["generation"]) != 2 || len(meta["attempt_mutation_revision"]) != 8 || binary.BigEndian.Uint64(meta["attempt_mutation_revision"]) != 17 {
		return errors.New("mixed metadata values differ")
	}
	var storedBinding wireBinding
	if !decodeWire(meta["binding"], &storedBinding) || !bindMatches(storedBinding, binding) {
		return errors.New("mixed stored binding wire differs")
	}
	var storedLimits wireLimits
	positionLimits := publicationstate.DefaultLimits()
	wantedLimits := wireLimits{positionLimits.SuppliedSnapshotCount, positionLimits.SuppliedTotalBytes, positionLimits.SuppliedContextBytes, positionLimits.MaxLineageLinks, positionLimits.CacheRecordCount, positionLimits.CacheObservationCount, positionLimits.CacheLogicalBytes, positionLimits.AcceptedRecordCount, positionLimits.AcceptedEventCount, positionLimits.AcceptedLogicalBytes, positionLimits.HistoryPageEvents, positionLimits.HistoryEvidenceBytes}
	if !decodeWire(meta["limits"], &storedLimits) || storedLimits != wantedLimits {
		return errors.New("mixed position limits wire differs")
	}
	var storedAttemptLimits wireAttemptLimits
	attemptLimits := publicationstate.DefaultAttemptLimits()
	wantedAttemptLimits := wireAttemptLimits{attemptLimits.ActiveAttempts, attemptLimits.HistoricalAttempts, attemptLimits.RetainedPublications, attemptLimits.ManagedObjects, attemptLimits.CustodyBytes, attemptLimits.MetadataBytes, attemptLimits.EvidenceBytes, attemptLimits.EvidenceSlotBytes, attemptLimits.LifecycleEvents, attemptLimits.EventBytes, attemptLimits.CoreBytes, attemptLimits.HistoryPageEntries, attemptLimits.HistoryPageBytes}
	if !decodeWire(meta["attempt_limits"], &storedAttemptLimits) || storedAttemptLimits != wantedAttemptLimits {
		return errors.New("mixed attempt limits wire differs")
	}

	floorRows := rowsFor("active_floor")
	if len(floorRows) != 1 || !cellIntegerIs(floorRows[0], 0, 1) {
		return errors.New("mixed active floor row differs")
	}
	floorBytes, ok := blobAt(floorRows[0], 1)
	var activeFloorWire wireFloor
	if !ok || !decodeWire(floorBytes, &activeFloorWire) || !floorMatches(activeFloorWire, state.FinalFloor) {
		return errors.New("mixed active floor wire differs")
	}

	expectedRecords := map[string]candidateData{string(genesis.recordCID): genesis}
	expectedRecords[string(replacementData.recordCID)] = replacementData
	for _, row := range rowsFor("accepted_records") {
		cid, cidOK := blobAt(row, 0)
		key, keyOK := textAt(row, 1)
		sequence, sequenceOK := intAt(row, 2)
		raw, rawOK := blobAt(row, 3)
		logical, logicalOK := intAt(row, 4)
		want, exists := expectedRecords[string(cid)]
		if !cidOK || !keyOK || !sequenceOK || !rawOK || !logicalOK || !exists || key != want.input.SnapshotKey || sequence != int64(want.record.PublicationSeq) || !bytes.Equal(raw, want.input.SnapshotRecord) || logical != int64(len(raw)+len(cid)+len(key)+8) {
			return errors.New("mixed accepted record row differs")
		}
		delete(expectedRecords, string(cid))
	}
	if len(expectedRecords) != 0 {
		return errors.New("mixed accepted record join is incomplete")
	}

	history := state.FinalHistory
	if len(history.Events) != 2 || len(history.Records) != 2 || history.HasMore || history.NextRevision != 2 || history.Events[0].Revision != 1 || history.Events[1].Revision != 2 || history.Events[0].Mode != publicationstate.ModeFirstUse || history.Events[0].Stop != "first_use" || history.Events[0].OldFloor != nil || history.Events[1].Mode != publicationstate.ModeReplaceFloor || history.Events[1].Reason != publicationstate.ReasonFork || history.Events[1].Stop != "fork" || history.Events[1].OldFloor == nil || !reflect.DeepEqual(*history.Events[1].OldFloor, state.Genesis.Floor) || !reflect.DeepEqual(history.Events[0].NewFloor, state.Genesis.Floor) || !reflect.DeepEqual(history.Events[1].NewFloor, state.FinalFloor) {
		return errors.New("mixed public accepted history differs")
	}
	historyRecords := map[string]candidateData{string(genesis.recordCID): genesis, string(replacementData.recordCID): replacementData}
	for _, record := range history.Records {
		want, exists := historyRecords[string(record.Reference.CID)]
		if !exists || record.Reference.Key != want.input.SnapshotKey || record.Reference.Sequence != want.record.PublicationSeq || !bytes.Equal(record.Raw, want.input.SnapshotRecord) {
			return errors.New("mixed public accepted record page differs")
		}
		delete(historyRecords, string(record.Reference.CID))
	}
	if len(historyRecords) != 0 {
		return errors.New("mixed public accepted record page is incomplete")
	}
	eventExpected := []struct {
		floor             publicationstate.Floor
		mode              publicationstate.Mode
		reason            publicationstate.Reason
		stop              string
		input             publicationstate.CandidateInput
		setDigest         [32]byte
		observationDigest [32]byte
		old               *publicationstate.Floor
	}{
		{floor: state.Genesis.Floor, mode: publicationstate.ModeFirstUse, stop: "first_use", input: state.GenesisInput, setDigest: genesisSetDigest, observationDigest: genesisObservationDigest},
		{floor: state.FinalFloor, mode: publicationstate.ModeReplaceFloor, reason: publicationstate.ReasonFork, stop: "fork", input: state.ReplacementInput, setDigest: replacementSetDigest, observationDigest: replacementObservationDigest, old: &state.Genesis.Floor},
	}
	for index, row := range rowsFor("accepted_events") {
		want := eventExpected[index]
		revision, revisionOK := intAt(row, 0)
		mode, modeOK := textAt(row, 1)
		reason, reasonOK := textAt(row, 2)
		stop, stopOK := textAt(row, 3)
		oldRaw, oldOK := blobAt(row, 4)
		newRaw, newOK := blobAt(row, 5)
		body, bodyOK := blobAt(row, 6)
		digest, digestOK := blobAt(row, 7)
		logical, logicalOK := intAt(row, 8)
		if !revisionOK || !modeOK || !reasonOK || !stopOK || (!oldOK && !cellIsNull(row, 4)) || !newOK || !bodyOK || !digestOK || !logicalOK || revision != int64(index+1) || mode != string(want.mode) || reason != string(want.reason) || stop != want.stop || len(digest) != 32 || !bytes.Equal(digest, domainHash("systems.lamb.dottie.local-publication-event.v1", body)) || len(body) == 0 {
			return errors.New("mixed accepted event row fields differ")
		}
		var newFloorWire wireFloor
		if !decodeWire(newRaw, &newFloorWire) || !floorMatches(newFloorWire, want.floor) {
			return errors.New("mixed accepted event new floor wire differs")
		}
		var bodyWire wireEventBody
		traceRecord, traceErr := publication.DecodeSnapshot(want.input.SnapshotRecord)
		traceCID, cidErr := publication.RecordCID(want.input.SnapshotRecord)
		if traceErr != nil || cidErr != nil || !decodeWire(body, &bodyWire) || bodyWire.Version != 1 || bodyWire.Mode != string(want.mode) || bodyWire.Reason != string(want.reason) || bodyWire.Stop != want.stop || !floorCoreMatches(bodyWire.NewFloor, want.floor) || len(bodyWire.Trace) != 1 || bodyWire.Trace[0].Key != want.input.SnapshotKey || !bytes.Equal(bodyWire.Trace[0].CID, traceCID) || bodyWire.Trace[0].Sequence != traceRecord.PublicationSeq || !bytes.Equal(bodyWire.ObservationDigest, want.observationDigest[:]) || !bytes.Equal(bodyWire.SuppliedSetDigest, want.setDigest[:]) {
			return errors.New("mixed accepted event body wire differs")
		}
		if want.old == nil {
			if !cellIsNull(row, 4) || bodyWire.OldFloor != nil {
				return errors.New("mixed first-use old floor is not null")
			}
		} else {
			var oldFloorWire wireFloor
			if !oldOK || !decodeWire(oldRaw, &oldFloorWire) || !floorMatches(oldFloorWire, *want.old) || bodyWire.OldFloor == nil || !floorMatches(*bodyWire.OldFloor, *want.old) {
				return errors.New("mixed replacement old floor differs")
			}
		}
		publicEvent := history.Events[index]
		if publicEvent.Revision != uint64(revision) || publicEvent.Mode != want.mode || publicEvent.Reason != want.reason || publicEvent.Stop != want.stop || publicEvent.EventDigest != want.floor.AcceptedEventDigest || publicEvent.ObservationDigest != want.observationDigest || publicEvent.SuppliedSetDigest != want.setDigest || !reflect.DeepEqual(publicEvent.NewFloor, want.floor) || len(publicEvent.Trace) != 1 || publicEvent.Trace[0].Key != want.input.SnapshotKey || publicEvent.Trace[0].Sequence != traceRecord.PublicationSeq || !bytes.Equal(publicEvent.Trace[0].CID, traceCID) {
			return errors.New("mixed public and raw accepted event projections differ")
		}
		if logical != int64(len(body)+len(digest)+len(oldRaw)+len(newRaw)+len(mode)+len(reason)+len(stop)+8) || !bytes.Equal(digest, want.floor.AcceptedEventDigest[:]) {
			return errors.New("mixed accepted event logical bytes or digest differs")
		}
	}

	type attemptExpectation struct {
		id           [16]byte
		attempt      publicationstate.Attempt
		material     candidateData
		kind         string
		createdOrder int64
		mutation     int64
		context      publicationstate.SuppliedContext
		captured     *publicationstate.Floor
		predecessor  publicationstate.CandidateInput
	}
	genesisAttempt := state.Genesis.Attempt
	abandonedAttempt := state.RetiredAttempt
	activeAttempt := state.AbsentResolution.Attempt
	attempts := []attemptExpectation{
		{id: genesisID, attempt: genesisAttempt, material: genesis, kind: string(publicationstate.AttemptGenesis), createdOrder: 1, mutation: 5, context: state.EmptyGenesisView.SuppliedContext},
		{id: abandonedID, attempt: abandonedAttempt, material: abandoned, kind: string(publicationstate.AttemptSuccessor), createdOrder: 6, mutation: 13, context: state.PredecessorView.SuppliedContext, captured: &state.Genesis.Floor, predecessor: state.GenesisInput},
		{id: activeID, attempt: activeAttempt, material: active, kind: string(publicationstate.AttemptSuccessor), createdOrder: 14, mutation: 17, context: state.FinalFloor.SuppliedContext, captured: &state.FinalFloor, predecessor: state.ReplacementInput},
	}
	attemptByID := make(map[string]attemptExpectation, 3)
	attemptRows := make(map[string][]rawCell, 3)
	attemptCoreBytes := make(map[string][]byte, 3)
	attemptLogical := make(map[string]int64, 3)
	for _, expected := range attempts {
		idKey := string(expected.id[:])
		if _, exists := attemptByID[idKey]; exists || expected.attempt.ID != expected.id || expected.attempt.MutationRevision != uint64(expected.mutation) || allZero(expected.attempt.StateDigest[:]) || expected.attempt.Kind != publicationstate.AttemptKind(expected.kind) || expected.attempt.Sequence != expected.material.record.PublicationSeq || expected.attempt.SnapshotKey != expected.material.input.SnapshotKey || !bytes.Equal(expected.attempt.SnapshotRecordCID, expected.material.recordCID) || !bytes.Equal(expected.attempt.HeadRecordCID, expected.material.headCID) || !bytes.Equal(expected.attempt.BlobCID, expected.material.blobCID) || expected.attempt.BlobSize != uint64(len(expected.material.input.Payload)) {
			return errors.New("mixed public attempt identity or material differs")
		}
		if expected.captured == nil {
			if expected.attempt.CapturedFloor != nil || expected.attempt.CapturedRevision != 0 || expected.attempt.CapturedGeneration != 0 {
				return errors.New("mixed genesis public attempt capture differs")
			}
		} else if expected.attempt.CapturedFloor == nil || !reflect.DeepEqual(*expected.attempt.CapturedFloor, *expected.captured) || expected.attempt.CapturedRevision != expected.captured.Revision || expected.attempt.CapturedGeneration != expected.captured.Generation {
			return errors.New("mixed successor public attempt capture differs")
		}
		attemptByID[idKey] = expected
	}
	for _, row := range rowsFor("publication_attempts") {
		id, idOK := blobAt(row, 0)
		coreBytes, coreOK := blobAt(row, 1)
		lifecycle, lifecycleOK := textAt(row, 2)
		outcome, outcomeOK := textAt(row, 3)
		blocked, blockedOK := textAt(row, 4)
		stateDigest, digestOK := blobAt(row, 5)
		mutation, mutationOK := intAt(row, 6)
		createdOrder, orderOK := intAt(row, 7)
		logical, logicalOK := intAt(row, 8)
		if !idOK || !coreOK || !lifecycleOK || !outcomeOK || !blockedOK || !digestOK || !mutationOK || !orderOK || !logicalOK {
			return errors.New("mixed attempt row cell type differs")
		}
		expected, exists := attemptByID[string(id)]
		if !exists || len(attemptRows[string(id)]) != 0 || !bytes.Equal(stateDigest, expected.attempt.StateDigest[:]) || lifecycle != string(expected.attempt.Lifecycle) || outcome != string(expected.attempt.Outcome) || blocked != expected.attempt.Blocked || mutation != expected.mutation || createdOrder != expected.createdOrder {
			return errors.New("mixed attempt row state differs")
		}
		var core wireAttemptCore
		if !decodeWire(coreBytes, &core) || core.Version != 1 || !bytes.Equal(core.AttemptID, id) || !bytes.Equal(core.DatabaseID, state.FinalFloor.DatabaseID[:]) || !bindMatches(core.Binding, binding) || core.Kind != expected.kind || core.CapturedRevision != expected.attempt.CapturedRevision || core.CapturedGeneration != expected.attempt.CapturedGeneration || core.SnapshotKey != expected.material.input.SnapshotKey || !bytes.Equal(core.SnapshotRecord, expected.material.input.SnapshotRecord) || !bytes.Equal(core.SnapshotCID, expected.material.recordCID) || !bytes.Equal(core.HeadRecord, expected.material.input.HeadRecord) || !bytes.Equal(core.HeadCID, expected.material.headCID) || !bytes.Equal(core.BlobCID, expected.material.blobCID) || core.BlobSize != uint64(len(expected.material.input.Payload)) || !contextMatches(core.InitialContext, expected.context) || len(core.InitialViewDigest) != 32 || allZero(core.InitialViewDigest) || !bytes.Equal(core.Review.SelectionDigest, state.Review.SelectionDigest[:]) || core.Review.SelectionRevision != state.Review.SelectionRevision || !bytes.Equal(core.Review.ApprovalDigest, state.Review.ApprovalDigest[:]) || core.Review.ApprovalRevision != state.Review.ApprovalRevision || len(core.CandidateConfirmation) != 32 || allZero(core.CandidateConfirmation) || core.ReservedCompletionBytes != 512<<10 {
			return errors.New("mixed attempt core wire differs")
		}
		if expected.captured == nil {
			if core.CapturedFloor != nil || expected.attempt.CapturedFloor != nil || core.CapturedRevision != 0 || core.CapturedGeneration != 0 || core.PredecessorKey != "" || len(core.PredecessorRecord) != 0 || len(core.PredecessorCID) != 0 {
				return errors.New("mixed genesis attempt core has a predecessor")
			}
		} else {
			predecessorCID, err := publication.RecordCID(expected.predecessor.SnapshotRecord)
			if err != nil || core.CapturedFloor == nil || !floorMatches(*core.CapturedFloor, *expected.captured) || core.CapturedRevision != expected.captured.Revision || core.CapturedGeneration != expected.captured.Generation || expected.attempt.CapturedFloor == nil || !reflect.DeepEqual(*expected.attempt.CapturedFloor, *expected.captured) || expected.attempt.CapturedRevision != expected.captured.Revision || expected.attempt.CapturedGeneration != expected.captured.Generation || core.PredecessorKey != expected.predecessor.SnapshotKey || !bytes.Equal(core.PredecessorRecord, expected.predecessor.SnapshotRecord) || !bytes.Equal(core.PredecessorCID, predecessorCID) {
				return errors.New("mixed successor attempt core predecessor differs")
			}
		}
		if logical < int64(len(coreBytes)) {
			return errors.New("mixed attempt logical bytes are too small")
		}
		attemptRows[string(id)] = row
		attemptCoreBytes[string(id)] = coreBytes
		attemptLogical[string(id)] = logical
	}
	if len(attemptRows) != 3 {
		return errors.New("mixed attempt rows are incomplete")
	}

	expectedKinds := map[string][]string{
		string(genesisID[:]):   {"created", "upload-started", "may-have-submitted", "outcome-observed-current", "retired-success"},
		string(abandonedID[:]): {"created", "upload-started", "may-have-submitted", "outcome-lost-fence", "blocked-floor-replaced", "retired-abandoned"},
		string(activeID[:]):    {"created", "upload-started", "may-have-submitted", "outcome-observed-absent-unresolved"},
	}
	eventRowsByID := make(map[string][][]rawCell, 3)
	eventWiresByID := make(map[string][]wireAttemptEvent, 3)
	eventBodiesByID := make(map[string][][]byte, 3)
	eventDigestsByID := make(map[string][][]byte, 3)
	for _, row := range rowsFor("attempt_events") {
		id, idOK := blobAt(row, 0)
		ordinal, ordinalOK := intAt(row, 1)
		kind, kindOK := textAt(row, 2)
		body, bodyOK := blobAt(row, 3)
		digest, digestOK := blobAt(row, 4)
		if !idOK || !ordinalOK || !kindOK || !bodyOK || !digestOK || len(digest) != 32 {
			return errors.New("mixed attempt event cell type differs")
		}
		key := string(id)
		wantKinds, exists := expectedKinds[key]
		if !exists || len(eventRowsByID[key]) >= len(wantKinds) || ordinal != int64(len(eventRowsByID[key])+1) || kind != wantKinds[len(eventRowsByID[key])] || !bytes.Equal(digest, domainHash("systems.lamb.dottie.publication-attempt-event.v1", body)) {
			return errors.New("mixed attempt event chronology or digest differs")
		}
		var event wireAttemptEvent
		if !decodeWire(body, &event) || event.Version != 1 || event.Ordinal != uint32(ordinal) || event.Kind != kind || len(event.StateDigest) != 32 || allZero(event.StateDigest) {
			return errors.New("mixed attempt event wire differs")
		}
		priorDigests := eventDigestsByID[key]
		if len(priorDigests) == 0 {
			if len(event.PreviousDigest) != 0 {
				return errors.New("mixed first attempt event has previous digest")
			}
		} else if !bytes.Equal(event.PreviousDigest, priorDigests[len(priorDigests)-1]) {
			return errors.New("mixed attempt event digest chain differs")
		}
		if kind == "may-have-submitted" {
			var submission wireAttemptEvidence
			if !decodeWire(event.Evidence, &submission) || submission.Version != 1 || submission.Role != "submission" || submission.Outcome != string(publicationstate.OutcomeUnresolved) || submission.AttemptedKey != attemptByID[key].material.input.SnapshotKey || !bytes.Equal(submission.AttemptedRecord, attemptByID[key].material.input.SnapshotRecord) || !bytes.Equal(submission.PredecessorRecord, attemptByID[key].predecessor.SnapshotRecord) || !contextMatches(submission.Context, attemptByID[key].context) || !bindMatches(submission.Origin, binding) || submission.Scope != string(publicationstate.ViewScopeWholeRepository) || len(submission.ViewDigest) != 32 || allZero(submission.ViewDigest) || len(submission.Suffix) != 0 {
				return errors.New("mixed submission event evidence differs")
			}
			if key == string(genesisID[:]) {
				if len(submission.Head) != 0 || len(submission.PredecessorRecord) != 0 {
					return errors.New("mixed genesis submission event differs")
				}
			} else if key == string(abandonedID[:]) {
				if !bytes.Equal(submission.Head, state.PredecessorView.Head) || !bytes.Equal(submission.PredecessorRecord, state.GenesisInput.SnapshotRecord) {
					return errors.New("mixed old successor submission event differs")
				}
			} else if !bytes.Equal(submission.Head, state.ReplacementInput.HeadRecord) || !bytes.Equal(submission.PredecessorRecord, state.ReplacementInput.SnapshotRecord) {
				return errors.New("mixed active successor submission event differs")
			}
		} else if kind == "outcome-lost-fence" {
			if key != string(abandonedID[:]) || ordinal != 4 || len(event.Evidence) != 32 || !bytes.Equal(event.Evidence, state.FinalFirstConflict.ID[:]) {
				return errors.New("mixed first lost-fence event reference differs")
			}
		} else if len(event.Evidence) != 0 {
			return errors.New("mixed ordinary attempt event has evidence")
		}
		eventRowsByID[key] = append(eventRowsByID[key], row)
		eventWiresByID[key] = append(eventWiresByID[key], event)
		eventBodiesByID[key] = append(eventBodiesByID[key], body)
		eventDigestsByID[key] = append(eventDigestsByID[key], digest)
	}
	for _, expected := range attempts {
		idKey := string(expected.id[:])
		if len(eventRowsByID[idKey]) != len(expectedKinds[idKey]) || !bytes.Equal(eventWiresByID[idKey][len(eventWiresByID[idKey])-1].StateDigest, expected.attempt.StateDigest[:]) {
			return errors.New("mixed attempt final event state differs")
		}
		attemptRow := attemptRows[idKey]
		if attemptRow == nil {
			return errors.New("mixed attempt final row is missing")
		}
		if expected.id == genesisID && (expected.attempt.Lifecycle != publicationstate.AttemptRetiredSuccess || expected.attempt.Outcome != publicationstate.OutcomeCurrent || expected.attempt.Blocked != "") || expected.id == abandonedID && (expected.attempt.Lifecycle != publicationstate.AttemptRetiredAbandoned || expected.attempt.Outcome != publicationstate.OutcomeLostFence || expected.attempt.Blocked != "blocked-floor-replaced") || expected.id == activeID && (expected.attempt.Lifecycle != publicationstate.AttemptMayHaveSubmitted || expected.attempt.Outcome != publicationstate.OutcomeAbsentUnresolved || expected.attempt.Blocked != "") {
			return errors.New("mixed final attempt public roles differ")
		}
	}

	publicEvidence := make(map[string]map[string][]byte, 3)
	submissionCount := 0
	for _, evidence := range state.FinalPage.Evidence {
		key := string(evidence.AttemptID[:])
		if _, ok := attemptByID[key]; !ok || len(evidence.Evidence) == 0 {
			return errors.New("mixed public evidence identity differs")
		}
		if publicEvidence[key] == nil {
			publicEvidence[key] = make(map[string][]byte)
		}
		if _, exists := publicEvidence[key][evidence.Role]; exists {
			return errors.New("mixed public evidence role is duplicated")
		}
		publicEvidence[key][evidence.Role] = bytes.Clone(evidence.Evidence)
		if evidence.Role == "submission" {
			submissionCount++
		}
	}
	if len(state.FinalPage.Attempts) != 3 || len(state.FinalPage.Evidence) != 8 || state.FinalPage.HasMore || state.FinalPage.NextID != activeID || submissionCount != 3 || len(publicEvidence[string(genesisID[:])]) != 2 || len(publicEvidence[string(abandonedID[:])]) != 4 || len(publicEvidence[string(activeID[:])]) != 2 {
		return errors.New("mixed public attempt history projection counts differ")
	}
	publicAttemptMatches := func(actual, expected publicationstate.Attempt) bool {
		if actual.ID != expected.ID || actual.Kind != expected.Kind || actual.Lifecycle != expected.Lifecycle || actual.Outcome != expected.Outcome || actual.Blocked != expected.Blocked || actual.Sequence != expected.Sequence || actual.SnapshotKey != expected.SnapshotKey || !bytes.Equal(actual.SnapshotRecordCID, expected.SnapshotRecordCID) || !bytes.Equal(actual.HeadRecordCID, expected.HeadRecordCID) || !bytes.Equal(actual.BlobCID, expected.BlobCID) || actual.BlobSize != expected.BlobSize || actual.CapturedRevision != expected.CapturedRevision || actual.CapturedGeneration != expected.CapturedGeneration || actual.MutationRevision != expected.MutationRevision || actual.StateDigest != expected.StateDigest {
			return false
		}
		if actual.CapturedFloor == nil || expected.CapturedFloor == nil {
			return actual.CapturedFloor == nil && expected.CapturedFloor == nil
		}
		return reflect.DeepEqual(*actual.CapturedFloor, *expected.CapturedFloor)
	}
	for index, expected := range attempts {
		if !publicAttemptMatches(state.FinalPage.Attempts[index], expected.attempt) {
			return errors.New("mixed public attempt page does not join source row")
		}
	}
	for key, wireRows := range eventWiresByID {
		var submission []byte
		for _, event := range wireRows {
			if event.Kind == "may-have-submitted" {
				submission = bytes.Clone(event.Evidence)
			}
		}
		if len(submission) == 0 || !bytes.Equal(publicEvidence[key]["submission"], submission) {
			return errors.New("mixed public submission projection does not join event wire")
		}
	}

	expectedSQLRoles := map[string][]string{
		string(genesisID[:]):   {"outcome"},
		string(abandonedID[:]): {"first-conflict", "outcome", "retirement"},
		string(activeID[:]):    {"outcome"},
	}
	evidenceBodies := make(map[string]map[string][]byte, 3)
	evidenceDigests := make(map[string]map[string][]byte, 3)
	for _, row := range rowsFor("attempt_evidence") {
		id, idOK := blobAt(row, 0)
		role, roleOK := textAt(row, 1)
		body, bodyOK := blobAt(row, 2)
		digest, digestOK := blobAt(row, 3)
		key := string(id)
		if !idOK || !roleOK || !bodyOK || !digestOK || len(digest) != 32 || !bytes.Equal(digest, domainHash("systems.lamb.dottie.publication-attempt-evidence.v1", body)) {
			return errors.New("mixed SQL evidence cell or digest differs")
		}
		if evidenceBodies[key] == nil {
			evidenceBodies[key] = make(map[string][]byte)
			evidenceDigests[key] = make(map[string][]byte)
		}
		if _, exists := evidenceBodies[key][role]; exists {
			return errors.New("mixed SQL evidence role is duplicated")
		}
		roleExpected := false
		for _, expectedRole := range expectedSQLRoles[key] {
			if expectedRole == role {
				roleExpected = true
			}
		}
		if !roleExpected || !bytes.Equal(publicEvidence[key][role], body) {
			return errors.New("mixed SQL evidence role does not join public history")
		}
		evidenceBodies[key][role] = body
		evidenceDigests[key][role] = digest
	}
	for key, roles := range expectedSQLRoles {
		if len(evidenceBodies[key]) != len(roles) {
			return errors.New("mixed SQL evidence role set is incomplete")
		}
	}
	firstConflictBody := evidenceBodies[string(abandonedID[:])]["first-conflict"]
	var firstConflictWire wireFirstConflict
	coreDigest := domainHash("systems.lamb.dottie.publication-attempt-core.v1", attemptCoreBytes[string(abandonedID[:])])
	if !decodeWire(firstConflictBody, &firstConflictWire) || firstConflictWire.Version != 1 || !bytes.Equal(firstConflictWire.AttemptID, abandonedID[:]) || !bytes.Equal(firstConflictWire.CoreDigest, coreDigest) || firstConflictWire.EventOrdinal != 4 || firstConflictWire.MutationRevision != 9 || firstConflictWire.Blocked != "" || !bytes.Equal(firstConflictWire.EventStateDigest, eventWiresByID[string(abandonedID[:])][3].StateDigest) || !bytes.Equal(domainHash("systems.lamb.dottie.publication-attempt-first-conflict.v1", firstConflictBody), state.FinalFirstConflict.ID[:]) || !bytes.Equal(firstConflictBody, state.FinalFirstConflict.Evidence) {
		return errors.New("mixed first-conflict outer envelope differs")
	}
	firstProof := firstConflictWire.Proof
	if firstProof.Version != 1 || firstProof.Role != "outcome" || firstProof.Outcome != string(publicationstate.OutcomeLostFence) || !contextMatches(firstProof.Context, state.FirstConflictView.SuppliedContext) || !bindMatches(firstProof.Origin, binding) || firstProof.Scope != string(publicationstate.ViewScopeWholeRepository) || len(firstProof.ViewDigest) != 32 || allZero(firstProof.ViewDigest) || !bytes.Equal(firstProof.Head, state.FirstConflictView.Head) || firstProof.AttemptedKey != state.OwnSuccessorInput.SnapshotKey || !bytes.Equal(firstProof.AttemptedRecord, state.CompetingOccupantInput.SnapshotRecord) || !bytes.Equal(firstProof.PredecessorRecord, state.GenesisInput.SnapshotRecord) || len(firstProof.Suffix) != 1 || firstProof.Suffix[0].Key != state.CompetingOccupantInput.SnapshotKey || !bytes.Equal(firstProof.Suffix[0].Raw, state.CompetingOccupantInput.SnapshotRecord) {
		return errors.New("mixed first-conflict inner proof differs")
	}
	firstHeadRecord, err := publication.DecodeSnapshot(firstProof.Suffix[0].Raw)
	if err != nil || firstHeadRecord.PublicationSeq != 1 || publication.VerifyHeadBinding(firstProof.Head, firstProof.Suffix[0].Raw, firstProof.Suffix[0].Key) != nil {
		return errors.New("mixed first-conflict head record is invalid")
	}
	firstHead, err := publication.DecodeHead(firstProof.Head)
	firstHeadCID, cidErr := publication.RecordCID(firstProof.Suffix[0].Raw)
	if err != nil || cidErr != nil || firstHead.PublicationSeq != 1 || !bytes.Equal(firstHead.SnapshotCID, firstHeadCID) || !bytes.Equal(firstHead.BlobCID, firstHeadRecord.Blob.CID) {
		return errors.New("mixed first-conflict head binding differs")
	}
	for _, conflict := range []publicationstate.FirstConflictEvidence{state.FirstConflict, state.FinalFirstConflict} {
		if conflict.AttemptID != abandonedID || conflict.ID != state.FinalFirstConflict.ID || !bytes.Equal(conflict.Evidence, firstConflictBody) || !bytes.Equal(conflict.Head, firstProof.Head) || conflict.HeadKey != firstProof.Suffix[0].Key || !bytes.Equal(conflict.HeadRecord, firstProof.Suffix[0].Raw) || conflict.HeadSequence != firstHeadRecord.PublicationSeq {
			return errors.New("mixed public first-conflict projection differs")
		}
	}
	var priorProof wireAttemptEvidence
	if !decodeWire(state.PriorLatestEvidence, &priorProof) || !bytes.Equal(state.PriorLatestEvidence, state.PriorLatest.Evidence) || state.PriorLatest.Attempt.ID != abandonedID || state.PriorLatest.Outcome != publicationstate.OutcomeLostFence || priorProof.Version != 1 || priorProof.Role != "outcome" || priorProof.Outcome != string(publicationstate.OutcomeLostFence) || !bindMatches(priorProof.Origin, binding) || priorProof.Scope != string(publicationstate.ViewScopeWholeRepository) || len(priorProof.ViewDigest) != 32 || allZero(priorProof.ViewDigest) || !bytes.Equal(priorProof.ViewDigest, state.PriorLatest.ViewDigest[:]) || !contextMatches(priorProof.Context, state.ExtendedView.SuppliedContext) || !bytes.Equal(priorProof.Head, state.ExtendedView.Head) || priorProof.AttemptedKey != state.OwnSuccessorInput.SnapshotKey || !bytes.Equal(priorProof.AttemptedRecord, state.CompetingOccupantInput.SnapshotRecord) || !bytes.Equal(priorProof.PredecessorRecord, state.GenesisInput.SnapshotRecord) || len(priorProof.Suffix) != 2 || priorProof.Suffix[0].Key != state.CompetingOccupantInput.SnapshotKey || !bytes.Equal(priorProof.Suffix[0].Raw, state.CompetingOccupantInput.SnapshotRecord) || priorProof.Suffix[1].Key != state.CompetingExtensionInput.SnapshotKey || !bytes.Equal(priorProof.Suffix[1].Raw, state.CompetingExtensionInput.SnapshotRecord) || bytes.Equal(state.PriorLatestEvidence, evidenceBodies[string(abandonedID[:])]["outcome"]) {
		return errors.New("mixed detached seq2 proof is not distinct from final SQL outcome")
	}
	var genesisOutcome wireAttemptEvidence
	if !decodeWire(evidenceBodies[string(genesisID[:])]["outcome"], &genesisOutcome) || genesisOutcome.Version != 1 || genesisOutcome.Role != "outcome" || genesisOutcome.Outcome != string(publicationstate.OutcomeCurrent) || !bindMatches(genesisOutcome.Origin, binding) || genesisOutcome.Scope != string(publicationstate.ViewScopeWholeRepository) || len(genesisOutcome.ViewDigest) != 32 || allZero(genesisOutcome.ViewDigest) || !contextMatches(genesisOutcome.Context, state.GenesisCurrentView.SuppliedContext) || !bytes.Equal(genesisOutcome.Head, state.GenesisInput.HeadRecord) || genesisOutcome.AttemptedKey != state.GenesisInput.SnapshotKey || !bytes.Equal(genesisOutcome.AttemptedRecord, state.GenesisInput.SnapshotRecord) || len(genesisOutcome.PredecessorRecord) != 0 || len(genesisOutcome.Suffix) != 1 || genesisOutcome.Suffix[0].Key != state.GenesisInput.SnapshotKey || !bytes.Equal(genesisOutcome.Suffix[0].Raw, state.GenesisInput.SnapshotRecord) {
		return errors.New("mixed genesis outcome wire differs")
	}
	var abandonedOutcome wireAttemptEvidence
	var abandonedRetirement wireAttemptEvidence
	if !decodeWire(evidenceBodies[string(abandonedID[:])]["outcome"], &abandonedOutcome) || !decodeWire(evidenceBodies[string(abandonedID[:])]["retirement"], &abandonedRetirement) || !bytes.Equal(evidenceBodies[string(abandonedID[:])]["outcome"], evidenceBodies[string(abandonedID[:])]["retirement"]) || abandonedOutcome.Version != 1 || abandonedRetirement.Version != 1 || abandonedOutcome.Role != "outcome" || abandonedRetirement.Role != "outcome" || abandonedOutcome.Outcome != string(publicationstate.OutcomeLostFence) || !bindMatches(abandonedOutcome.Origin, binding) || abandonedOutcome.Scope != string(publicationstate.ViewScopeWholeRepository) || len(abandonedOutcome.ViewDigest) != 32 || allZero(abandonedOutcome.ViewDigest) || !contextMatches(abandonedOutcome.Context, state.RetirementView.SuppliedContext) || !bytes.Equal(abandonedOutcome.Head, state.RetirementView.Head) || abandonedOutcome.AttemptedKey != state.CompetingOccupantInput.SnapshotKey || !bytes.Equal(abandonedOutcome.AttemptedRecord, state.CompetingOccupantInput.SnapshotRecord) || !bytes.Equal(abandonedOutcome.PredecessorRecord, state.GenesisInput.SnapshotRecord) || len(abandonedOutcome.Suffix) != 3 || len(state.RetirementView.Snapshots) != 4 || len(state.ExtendedView.Snapshots) != 3 || state.RetirementView.Origin != binding || state.RetirementView.Scope != publicationstate.ViewScopeWholeRepository || len(state.RetirementView.Head) == 0 {
		return errors.New("mixed final outcome and retirement roles differ")
	}
	for index := 0; index < 3; index++ {
		want := state.RetirementView.Snapshots[index+1]
		if state.RetirementView.Snapshots[index].Key != state.ExtendedView.Snapshots[index].Key || !bytes.Equal(state.RetirementView.Snapshots[index].Raw, state.ExtendedView.Snapshots[index].Raw) || abandonedOutcome.Suffix[index].Key != want.Key || !bytes.Equal(abandonedOutcome.Suffix[index].Raw, want.Raw) {
			return errors.New("mixed final seq3 suffix differs")
		}
	}
	retirementRecord, err := publication.DecodeSnapshot(state.RetirementView.Snapshots[3].Raw)
	if err != nil || retirementRecord.PublicationSeq != 3 || !bytes.Equal(state.RetirementView.Snapshots[3].Raw, state.RetirementExtensionInput.SnapshotRecord) || state.RetirementView.Snapshots[3].Key != state.RetirementExtensionInput.SnapshotKey || publication.VerifySuccessor(state.RetirementView.Snapshots[2].Raw, state.RetirementView.Snapshots[3].Raw, state.RetirementView.Snapshots[3].Key) != nil || !bytes.Equal(state.RetirementView.Head, state.RetirementExtensionInput.HeadRecord) || publication.VerifyHeadBinding(state.RetirementView.Head, state.RetirementView.Snapshots[3].Raw, state.RetirementView.Snapshots[3].Key) != nil {
		return errors.New("mixed retirement view does not end at the retained seq3 input")
	}
	var activeOutcome wireAttemptEvidence
	if !decodeWire(evidenceBodies[string(activeID[:])]["outcome"], &activeOutcome) || !bytes.Equal(evidenceBodies[string(activeID[:])]["outcome"], state.AbsentResolution.Evidence) || state.AbsentResolution.Outcome != publicationstate.OutcomeAbsentUnresolved || state.AbsentResolution.Attempt.ID != activeID || activeOutcome.Version != 1 || activeOutcome.Role != "outcome" || activeOutcome.Outcome != string(publicationstate.OutcomeAbsentUnresolved) || !bindMatches(activeOutcome.Origin, binding) || activeOutcome.Scope != string(publicationstate.ViewScopeWholeRepository) || len(activeOutcome.ViewDigest) != 32 || allZero(activeOutcome.ViewDigest) || !bytes.Equal(activeOutcome.ViewDigest, state.AbsentResolution.ViewDigest[:]) || !contextMatches(activeOutcome.Context, state.AbsenceView.SuppliedContext) || !bytes.Equal(activeOutcome.Head, state.AbsenceView.Head) || activeOutcome.AttemptedKey != state.ActiveSuccessorInput.SnapshotKey || len(activeOutcome.AttemptedRecord) != 0 || !bytes.Equal(activeOutcome.PredecessorRecord, state.ReplacementInput.SnapshotRecord) || len(activeOutcome.Suffix) != 0 {
		return errors.New("mixed active absent-unresolved evidence differs")
	}
	for _, expected := range attempts {
		row := attemptRows[string(expected.id[:])]
		terminal, terminalOK := blobAt(row, 9)
		if !terminalOK || !bytes.Equal(terminal, evidenceBodies[string(expected.id[:])]["outcome"]) {
			return errors.New("mixed attempt terminal evidence column differs")
		}
		retirement, retirementOK := blobAt(row, 10)
		if expected.id == abandonedID {
			if !retirementOK || !bytes.Equal(retirement, evidenceBodies[string(abandonedID[:])]["retirement"]) {
				return errors.New("mixed abandoned retirement evidence column differs")
			}
		} else if !cellIsNull(row, 10) {
			return errors.New("mixed non-abandoned attempt has retirement evidence")
		}
		logical := int64(len(attemptCoreBytes[string(expected.id[:])]))
		for _, event := range eventRowsByID[string(expected.id[:])] {
			body, _ := blobAt(event, 3)
			digest, _ := blobAt(event, 4)
			logical += int64(len(body) + len(digest))
		}
		for _, body := range evidenceBodies[string(expected.id[:])] {
			logical += int64(len(body) + 32)
		}
		if logical != attemptLogical[string(expected.id[:])] {
			return errors.New("mixed attempt logical-byte accounting differs")
		}
	}

	activeRows := rowsFor("active_publication_attempt")
	if len(activeRows) != 1 || !cellIntegerIs(activeRows[0], 0, 1) || !cellEqualsBlob(activeRows[0], 1, activeID[:]) || len(rowsFor("pending_genesis")) != 0 {
		return errors.New("mixed active and pending-genesis roles differ")
	}
	reservation := rowsFor("attempt_reservations")
	expectedReservationBytes := uint64(attemptLimits.CoreBytes) + uint64(attemptLimits.LifecycleEvents)*attemptLimits.EventBytes + 3*(attemptLimits.EvidenceSlotBytes+32)
	if len(reservation) != 1 || !cellEqualsBlob(reservation[0], 0, activeID[:]) || expectedReservationBytes > math.MaxInt64 || !cellIntegerIs(reservation[0], 1, int64(expectedReservationBytes)) || !cellIntegerIs(reservation[0], 2, 512<<10) || !cellIntegerIs(reservation[0], 3, 2) || !cellIntegerIs(reservation[0], 4, 1) || !cellIntegerIs(reservation[0], 5, 1) {
		return errors.New("mixed active completion reservation differs")
	}
	retained := rowsFor("retained_publications")
	if len(retained) != 1 || !cellEqualsBlob(retained[0], 0, genesis.recordCID) || !cellEqualsBlob(retained[0], 1, genesisID[:]) || !cellIntegerIs(retained[0], 2, 0) || !cellEqualsBlob(retained[0], 3, genesis.blobCID) || !cellIntegerIs(retained[0], 4, int64(len(genesis.input.Payload))) || !cellIntegerIs(retained[0], 5, 1) {
		return errors.New("mixed finalized-owner join differs")
	}
	refs := rowsFor("attempt_payload_refs")
	if len(refs) != 1 || !cellEqualsBlob(refs[0], 0, activeID[:]) || !cellEqualsBlob(refs[0], 1, active.blobCID) {
		return errors.New("mixed active payload reference differs")
	}
	objects := rowsFor("payload_objects")
	objectExpected := map[string]candidateData{string(genesis.blobCID): genesis, string(abandoned.blobCID): abandoned, string(active.blobCID): active}
	for _, row := range objects {
		cid, ok := blobAt(row, 0)
		size, sizeOK := intAt(row, 1)
		name, nameOK := textAt(row, 2)
		logical, logicalOK := intAt(row, 3)
		want, exists := objectExpected[string(cid)]
		if !ok || !sizeOK || !nameOK || !logicalOK || !exists || size != int64(len(want.input.Payload)) || name != payloadBasename(want.input.Payload) || logical != size {
			return errors.New("mixed payload catalog role differs")
		}
		delete(objectExpected, string(cid))
	}
	if len(objectExpected) != 0 {
		return errors.New("mixed payload catalog joins are incomplete")
	}
	cacheRecordCID, err := publication.RecordCID(state.ReplacementInput.SnapshotRecord)
	if err != nil {
		return errors.New("mixed cache record CID is invalid")
	}
	cacheRows := rowsFor("cache_records")
	if len(cacheRows) != 1 || !cellEqualsBlob(cacheRows[0], 0, cacheRecordCID) || !cellEqualsText(cacheRows[0], 1, state.ReplacementInput.SnapshotKey) || !cellIntegerIs(cacheRows[0], 2, 0) || !cellEqualsBlob(cacheRows[0], 3, state.ReplacementInput.SnapshotRecord) || !cellIntegerIs(cacheRows[0], 4, int64(len(state.ReplacementInput.SnapshotRecord)+len(cacheRecordCID)+len(state.ReplacementInput.SnapshotKey)+8)) {
		return errors.New("mixed raw cache record join differs")
	}
	cacheObservationRows := rowsFor("cache_observations")
	if len(cacheObservationRows) != 1 || !cellEqualsBlob(cacheObservationRows[0], 0, state.CacheID[:]) {
		return errors.New("mixed returned cache ID has no raw observation row")
	}
	cacheMetadata, cacheMetadataOK := blobAt(cacheObservationRows[0], 1)
	cacheLogical, cacheLogicalOK := intAt(cacheObservationRows[0], 2)
	var cacheWire wireCacheObservation
	if !cacheMetadataOK || !cacheLogicalOK || cacheLogical != int64(len(cacheMetadata)+32+8) || !decodeWire(cacheMetadata, &cacheWire) || cacheWire.Version != 1 || !bytes.Equal(cacheWire.ObservationDigest, cacheObservationDigest[:]) || !bytes.Equal(cacheWire.SuppliedSetDigest, cacheSetDigest[:]) || !contextMatches(cacheWire.Context, state.CacheObservation.SuppliedContext) || !bytes.Equal(cacheWire.Head, state.CacheObservation.Head) || cacheWire.Candidate.Key != state.ReplacementInput.SnapshotKey || !bytes.Equal(cacheWire.Candidate.CID, cacheRecordCID) || cacheWire.Candidate.Sequence != 0 || !bytes.Equal(domainHash("systems.lamb.dottie.local-observation-id.v1", cacheWire.ObservationDigest), state.CacheID[:]) {
		return errors.New("mixed cache observation metadata wire differs")
	}
	return nil
}

func validatePendingRows(inventory rowInventory, binding publicationstate.Binding, attemptID [16]byte, stateDigest [32]byte, candidate candidateValue, payload []byte, basename string) error {
	if err := validateInventoryShape(inventory); err != nil {
		return err
	}
	wantedCounts := map[string]int64{
		"store_meta": 7, "cache_records": 0, "cache_observations": 0,
		"accepted_records": 0, "accepted_events": 0, "active_floor": 0,
		"publication_attempts": 1, "active_publication_attempt": 1,
		"pending_genesis": 1, "attempt_events": 1, "attempt_evidence": 0,
		"payload_objects": 1, "attempt_payload_refs": 1,
		"retained_publications": 0, "attempt_reservations": 1,
	}
	for _, table := range inventory.Tables {
		count, ok := wantedCounts[table.Name]
		if !ok || table.RowCount != count || int64(len(table.Rows)) != count {
			return errors.New("schema-2 table contents do not match pending genesis")
		}
	}
	attempts := tableByName(inventory, "publication_attempts")
	if len(attempts.Rows) != 1 {
		return errors.New("pending attempt row is missing")
	}
	attemptRow := attempts.Rows[0]
	if !cellEqualsBlob(attemptRow, 0, attemptID[:]) || len(mustCellBlob(attemptRow, 1)) == 0 || !cellEqualsText(attemptRow, 2, string(publicationstate.AttemptPrepared)) || !cellEqualsText(attemptRow, 3, string(publicationstate.OutcomeNotSubmitted)) || !cellEqualsText(attemptRow, 4, "") || !cellEqualsBlob(attemptRow, 5, stateDigest[:]) || !cellIntegerIs(attemptRow, 6, 1) || !cellIntegerIs(attemptRow, 7, 1) || !cellIsNull(attemptRow, 9) || !cellIsNull(attemptRow, 10) {
		return errors.New("pending attempt row has unexpected state or evidence")
	}
	active := tableByName(inventory, "active_publication_attempt")
	pending := tableByName(inventory, "pending_genesis")
	refs := tableByName(inventory, "attempt_payload_refs")
	objects := tableByName(inventory, "payload_objects")
	reservations := tableByName(inventory, "attempt_reservations")
	events := tableByName(inventory, "attempt_events")
	if len(active.Rows) != 1 || !cellIntegerIs(active.Rows[0], 0, 1) || !cellEqualsBlob(active.Rows[0], 1, attemptID[:]) {
		return errors.New("active genesis reference does not match")
	}
	if len(pending.Rows) != 1 || !cellIntegerIs(pending.Rows[0], 0, 1) || !cellEqualsBlob(pending.Rows[0], 1, attemptID[:]) || !cellEqualsBlob(pending.Rows[0], 2, binding.Vault[:]) {
		return errors.New("pending genesis reference does not match")
	}
	blobCID := mustDecodeBytes(candidate.BlobCID)
	if len(refs.Rows) != 1 || !cellEqualsBlob(refs.Rows[0], 0, attemptID[:]) || !cellEqualsBlob(refs.Rows[0], 1, blobCID) {
		return errors.New("candidate payload reference does not match")
	}
	if len(objects.Rows) != 1 || !cellEqualsBlob(objects.Rows[0], 0, blobCID) || !cellIntegerIs(objects.Rows[0], 1, int64(len(payload))) || !cellEqualsText(objects.Rows[0], 2, basename) || !cellIntegerIs(objects.Rows[0], 3, int64(len(payload))) {
		return errors.New("payload object catalog row does not match")
	}
	if len(events.Rows) != 1 || !cellEqualsBlob(events.Rows[0], 0, attemptID[:]) || !cellIntegerIs(events.Rows[0], 1, 1) || !cellEqualsText(events.Rows[0], 2, "created") || len(mustCellBlob(events.Rows[0], 3)) == 0 || len(mustCellBlob(events.Rows[0], 4)) != 32 {
		return errors.New("created event does not match pending genesis")
	}
	if len(reservations.Rows) != 1 || !cellEqualsBlob(reservations.Rows[0], 0, attemptID[:]) {
		return errors.New("completion reservation is missing")
	}
	attemptLimits := publicationstate.DefaultAttemptLimits()
	expectedMetadata := uint64(attemptLimits.CoreBytes) + uint64(attemptLimits.LifecycleEvents)*attemptLimits.EventBytes + 3*(attemptLimits.EvidenceSlotBytes+32)
	if expectedMetadata > math.MaxInt64 || !cellIntegerIs(reservations.Rows[0], 1, int64(expectedMetadata)) || !cellIntegerIs(reservations.Rows[0], 2, 512<<10) || !cellIntegerIs(reservations.Rows[0], 3, 2) || !cellIntegerIs(reservations.Rows[0], 4, 1) || !cellIntegerIs(reservations.Rows[0], 5, 1) {
		return errors.New("completion reservation values do not match defaults")
	}
	if len(tableByName(inventory, "attempt_evidence").Rows) != 0 || len(tableByName(inventory, "accepted_records").Rows) != 0 || len(tableByName(inventory, "accepted_events").Rows) != 0 || len(tableByName(inventory, "active_floor").Rows) != 0 || len(tableByName(inventory, "retained_publications").Rows) != 0 {
		return errors.New("pending genesis contains fabricated accepted or terminal evidence")
	}
	if len(mustDecodeBytes(candidate.SnapshotCID)) == 0 {
		return errors.New("candidate record CID is empty")
	}
	databaseID, ok := metadataBlob(inventory, "database_id")
	if !ok || len(databaseID) != 32 || allZero(databaseID) {
		return errors.New("database identifier is malformed")
	}
	storedBinding, ok := metadataBlob(inventory, "binding")
	if !ok {
		return errors.New("stored binding is missing")
	}
	var bindingWire struct {
		AccountDID string `json:"accountDid"`
		Backend    string `json:"backend"`
		Repository string `json:"repository"`
		Vault      []byte `json:"vault"`
		Profile    string `json:"profile"`
	}
	if json.Unmarshal(storedBinding, &bindingWire) != nil || bindingWire.AccountDID != binding.AccountDID || bindingWire.Backend != string(binding.Backend) || bindingWire.Repository != binding.Repository || !bytes.Equal(bindingWire.Vault, binding.Vault[:]) || bindingWire.Profile != storageProfile {
		return errors.New("stored binding metadata differs")
	}
	for _, key := range []string{"revision", "generation"} {
		value, ok := metadataBlob(inventory, key)
		if !ok || len(value) != 8 || binary.BigEndian.Uint64(value) != 0 {
			return errors.New("position metadata is not empty")
		}
	}
	mutation, ok := metadataBlob(inventory, "attempt_mutation_revision")
	if !ok || len(mutation) != 8 || binary.BigEndian.Uint64(mutation) != 1 {
		return errors.New("attempt mutation metadata differs")
	}
	return nil
}

func tableByName(inventory rowInventory, name string) rawTable {
	for _, table := range inventory.Tables {
		if table.Name == name {
			return table
		}
	}
	return rawTable{}
}

func cellIsNull(row []rawCell, index int) bool {
	return index >= 0 && index < len(row) && row[index].Type == "null"
}

func cellEqualsBlob(row []rawCell, index int, expected []byte) bool {
	if index < 0 || index >= len(row) || row[index].Type != "blob-base64" {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(row[index].Value)
	return err == nil && bytes.Equal(decoded, expected)
}

func cellEqualsText(row []rawCell, index int, expected string) bool {
	if index < 0 || index >= len(row) || row[index].Type != "text-base64" {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(row[index].Value)
	return err == nil && string(decoded) == expected
}

func cellIntegerIs(row []rawCell, index int, expected int64) bool {
	return index >= 0 && index < len(row) && row[index].Type == "integer" && row[index].Value == strconv.FormatInt(expected, 10)
}

func metadataBlob(inventory rowInventory, key string) ([]byte, bool) {
	for _, row := range tableByName(inventory, "store_meta").Rows {
		if len(row) != 2 || !cellEqualsText(row, 0, key) || row[1].Type != "blob-base64" {
			continue
		}
		value, err := base64.StdEncoding.DecodeString(row[1].Value)
		return value, err == nil
	}
	return nil, false
}

func mustDecodeBytes(value byteValue) []byte {
	decoded, _ := base64.StdEncoding.DecodeString(value.Base64)
	return decoded
}

func mustCellBlob(row []rawCell, index int) []byte {
	if index < 0 || index >= len(row) || row[index].Type != "blob-base64" {
		return nil
	}
	decoded, _ := base64.StdEncoding.DecodeString(row[index].Value)
	return decoded
}

func validatePhysicalPayload(imageDirectory, expectedName string, expected []byte, blob publication.BlobReference) error {
	payloadDirectory := filepath.Join(imageDirectory, payloadDirectoryName)
	if err := verifyPrivateDirectory(payloadDirectory); err != nil {
		return errors.New("payload directory is not private")
	}
	entries, err := os.ReadDir(payloadDirectory)
	if err != nil || len(entries) != 1 || entries[0].Name() != expectedName {
		return errors.New("physical payload inventory differs")
	}
	path := filepath.Join(payloadDirectory, expectedName)
	if err := verifyPrivateFile(path); err != nil {
		return errors.New("physical payload file is unsafe")
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, expected) {
		return errors.New("physical payload bytes differ")
	}
	if err := publication.VerifyPayload(actual, blob); err != nil {
		return errors.New("physical payload CID or size differs")
	}
	return nil
}

func makeReplayInputs(binding publicationstate.Binding, suppliedContext publicationstate.SuppliedContext, candidate candidateValue, view publicationstate.SuppliedRepositoryView, review publicationstate.LocalReviewContext, options publicationstate.OpenOptions) replayInputs {
	return replayInputs{
		FormatVersion: 1,
		Coverage:      "pending-genesis-only",
		Binding:       bindingValueFor(binding),
		Options:       optionsFor(options),
		Candidate:     candidate,
		EmptyView: emptyViewValue{
			Origin:          bindingValueFor(view.Origin),
			Scope:           string(view.Scope),
			SuppliedContext: contextValueFor(suppliedContext),
			Head:            encodeBytes(view.Head),
			Snapshots:       []snapshotValue{},
		},
		Review: reviewValue{
			SelectionDigest:   hex.EncodeToString(review.SelectionDigest[:]),
			SelectionRevision: review.SelectionRevision,
			ApprovalDigest:    hex.EncodeToString(review.ApprovalDigest[:]),
			ApprovalRevision:  review.ApprovalRevision,
		},
		APISequence: []string{
			"OpenWithOptions(default schema-2 options)",
			"Load(no accepted floor)",
			"PrepareAttempt(genesis)",
			"CreateAttempt(prepared; no dispatch or submission)",
			"Load; History; ActiveAttempt; LoadAttempt; AttemptHistory; ReadCandidate",
		},
	}
}

func bindingValueFor(binding publicationstate.Binding) bindingValue {
	return bindingValue{AccountDID: binding.AccountDID, Backend: string(binding.Backend), Repository: binding.Repository, Vault: encodeBytes(binding.Vault[:])}
}

func contextValueFor(value publicationstate.SuppliedContext) contextValue {
	result := contextValue{RepositoryRevision: value.RepositoryRevision, RepositoryDigest: encodeBytes(value.RepositoryDigest)}
	if value.Policy != nil {
		result.Policy = &policyValue{Revision: value.Policy.Revision, Identity: encodeBytes(value.Policy.Identity), OwnerOnly: value.Policy.OwnerOnly}
	}
	return result
}

func optionsFor(options publicationstate.OpenOptions) inputOptions {
	return inputOptions{PositionLimits: options.PositionLimits, AttemptLimits: options.AttemptLimits, UpgradeFromPositions: options.UpgradeFromPositions}
}

func encodeBytes(value []byte) byteValue {
	digest := sha256.Sum256(value)
	return byteValue{Length: len(value), Base64: base64.StdEncoding.EncodeToString(value), SHA256: hex.EncodeToString(digest[:])}
}

func marshalJSON(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil || len(encoded) > maxJSONBytes {
		return nil, errors.New("JSON artifact could not be encoded within its bound")
	}
	return append(encoded, '\n'), nil
}

func writeRootFile(rootFD int, name string, data []byte) error {
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, "/\\") || len(data) > maxJSONBytes {
		return errors.New("output file name or size is invalid")
	}
	fd, err := unix.Openat(rootFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return errors.New("exclusive output file creation failed")
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("output file descriptor is invalid")
	}
	written, writeErr := file.Write(data)
	if writeErr != nil || written != len(data) {
		_ = file.Close()
		return errors.New("output file write failed")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("output file sync failed")
	}
	if err := file.Close(); err != nil {
		return errors.New("output file close failed")
	}
	return nil
}

func createOutputRoot(path string) (string, int, int, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(os.PathSeparator) {
		return "", -1, -1, "", errors.New("output root must be a clean absolute path")
	}
	parent := filepath.Dir(path)
	rootName := filepath.Base(path)
	if rootName == "." || rootName == string(os.PathSeparator) || strings.ContainsAny(rootName, "/\\") {
		return "", -1, -1, "", errors.New("output root name is invalid")
	}
	if err := verifyNoSymlinkPath(parent); err != nil {
		return "", -1, -1, "", errors.New("output parent path is unsafe")
	}
	if err := verifyPrivateDirectory(parent); err != nil {
		return "", -1, -1, "", errors.New("output parent must be an owned private directory")
	}
	if _, err := os.Lstat(path); err == nil {
		return "", -1, -1, "", errors.New("output root already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", -1, -1, "", errors.New("output root cannot be checked")
	}
	oldMask := unix.Umask(0o077)
	defer func() { _ = unix.Umask(oldMask) }()
	if err := unix.Mkdir(path, 0o700); err != nil {
		return "", -1, -1, "", errors.New("fresh output root creation failed")
	}
	rootFD, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", -1, -1, "", errors.New("fresh output root open failed")
	}
	if err := verifyDirectoryFD(rootFD, 0o700); err != nil {
		_ = unix.Close(rootFD)
		return "", -1, -1, "", errors.New("fresh output root is not private")
	}
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		_ = unix.Close(rootFD)
		return "", -1, -1, "", errors.New("output parent open failed")
	}
	if err := verifyDirectoryFD(parentFD, 0o700); err != nil {
		_ = unix.Close(rootFD)
		_ = unix.Close(parentFD)
		return "", -1, -1, "", errors.New("output parent changed during setup")
	}
	return path, rootFD, parentFD, rootName, nil
}

func createPrivateChild(rootFD int, name string) error {
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, "/\\") {
		return errors.New("output directory name is invalid")
	}
	if err := unix.Mkdirat(rootFD, name, 0o700); err != nil {
		return errors.New("exclusive output directory creation failed")
	}
	fd, err := unix.Openat(rootFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return errors.New("output directory open failed")
	}
	if err := verifyDirectoryFD(fd, 0o700); err != nil {
		_ = unix.Close(fd)
		return errors.New("output directory is not private")
	}
	if err := unix.Close(fd); err != nil {
		return errors.New("output directory close failed")
	}
	return nil
}

func verifyNoSymlinkPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("path is not clean and absolute")
	}
	current := string(os.PathSeparator)
	for _, component := range strings.Split(strings.TrimPrefix(path, current), current) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("path component is missing or unsafe")
		}
	}
	return nil
}

func verifyPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("directory is not private")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("directory owner differs")
	}
	return nil
}

func verifyDirectoryFD(fd int, mode os.FileMode) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || os.FileMode(stat.Mode&0o777) != mode || stat.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != 0 {
		return errors.New("directory descriptor is unsafe")
	}
	return nil
}

func verifyPrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("file is not private")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return errors.New("file owner or link count differs")
	}
	return nil
}

func inventoryOutputFiles(root string, images []imageManifest, artifacts []outputArtifact) ([]fileEntry, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || len(images) != 2 || len(artifacts) != 4 {
		return nil, errors.New("output inventory inputs are invalid")
	}
	expectedDirectories := map[string]struct{}{
		".": {}, imageName: {}, imageName + "/" + payloadDirectoryName: {},
		mixedImageName: {}, mixedImageName + "/" + payloadDirectoryName: {},
	}
	seenDirectories := make(map[string]struct{}, len(expectedDirectories))
	type expectedFile struct {
		role   string
		length int64
		digest string
	}
	expectedFiles := make(map[string]expectedFile, 12)
	seenFiles := make(map[string]struct{}, 12)
	putExpectedFile := func(path string, expected expectedFile) error {
		if path == "" || filepath.ToSlash(path) != path || filepath.IsAbs(path) || strings.ContainsAny(path, "\\\x00") {
			return errors.New("expected output path is invalid")
		}
		if _, exists := expectedFiles[path]; exists {
			return errors.New("expected output path is duplicated")
		}
		expectedFiles[path] = expected
		return nil
	}
	validDigest := func(value string) bool {
		decoded, err := hex.DecodeString(value)
		return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
	}
	validByteValue := func(value byteValue, maximum int) bool {
		if value.Length <= 0 || value.Length > maximum || !validDigest(value.SHA256) {
			return false
		}
		decoded, err := base64.StdEncoding.DecodeString(value.Base64)
		if err != nil || len(decoded) != value.Length || base64.StdEncoding.EncodeToString(decoded) != value.Base64 {
			return false
		}
		digest := sha256.Sum256(decoded)
		return hex.EncodeToString(digest[:]) == value.SHA256
	}
	validAttemptID := func(value string) bool {
		decoded, err := hex.DecodeString(value)
		return err == nil && len(decoded) == 16 && !allZero(decoded) && hex.EncodeToString(decoded) == value
	}
	seenDatabaseIDs := make(map[string]struct{}, 2)
	for imageIndex, image := range images {
		wantName, wantRows, wantInputs, wantPayloads := imageName, rowsName, inputsName, 1
		if imageIndex == 1 {
			wantName, wantRows, wantInputs, wantPayloads = mixedImageName, mixedRowsName, mixedInputsName, 3
		}
		if image.Name != wantName || image.SchemaVersion != 2 || image.ApplicationID != sqliteApplicationID || len(image.Tables) != len(tableSpecs) || len(image.Payloads) != wantPayloads || image.RowsArtifact != wantRows || image.InputsArtifact != wantInputs {
			return nil, errors.New("output image summary shape differs")
		}
		id, err := hex.DecodeString(image.DatabaseID)
		if err != nil || len(id) != 32 || allZero(id) || hex.EncodeToString(id) != image.DatabaseID {
			return nil, errors.New("output image database identifier is invalid")
		}
		if _, exists := seenDatabaseIDs[image.DatabaseID]; exists {
			return nil, errors.New("output image database identifiers are not independent")
		}
		seenDatabaseIDs[image.DatabaseID] = struct{}{}
		if imageIndex == 0 {
			if image.AcceptedFloor || image.Floor != nil || image.Revision != 0 || image.Generation != 0 || image.AttemptMutationRevision != 1 || image.AcceptedEvents != 0 || !validAttemptID(image.ActiveAttemptID) || image.PendingGenesisAttemptID != image.ActiveAttemptID || image.CacheObservationID != nil || len(image.Attempts) != 1 {
				return nil, errors.New("pending image manifest state differs")
			}
		} else if !image.AcceptedFloor || image.Floor == nil || image.Revision != 2 || image.Generation != 2 || image.AttemptMutationRevision != 17 || image.AcceptedEvents != 2 || !validAttemptID(image.ActiveAttemptID) || image.PendingGenesisAttemptID != "" || image.CacheObservationID == nil || image.CacheObservationID.Length != sha256.Size || !validByteValue(*image.CacheObservationID, sha256.Size) || len(image.Attempts) != 3 {
			return nil, errors.New("mixed image manifest state differs")
		}
		if image.Floor != nil {
			if image.Floor.Revision != image.Revision || image.Floor.Generation != image.Generation || !validByteValue(image.Floor.DatabaseID, 32) || image.Floor.DatabaseID.Base64 != base64.StdEncoding.EncodeToString(id) {
				return nil, errors.New("output image floor metadata differs")
			}
		}
		attemptIDs := make(map[string]struct{}, len(image.Attempts))
		for _, attempt := range image.Attempts {
			if !validByteValue(attempt.ID, 16) || attempt.ID.Length != 16 || !validByteValue(attempt.StateDigest, sha256.Size) || attempt.StateDigest.Length != sha256.Size || attempt.Availability != string(publicationstate.AvailabilityUnchecked) {
				return nil, errors.New("output image attempt projection is invalid")
			}
			if _, exists := attemptIDs[attempt.ID.Base64]; exists {
				return nil, errors.New("output image attempt identity is duplicated")
			}
			attemptIDs[attempt.ID.Base64] = struct{}{}
		}
		if imageIndex == 0 {
			attemptID, err := base64.StdEncoding.DecodeString(image.Attempts[0].ID.Base64)
			if err != nil || hex.EncodeToString(attemptID) != image.ActiveAttemptID || image.Attempts[0].CapturedFloor != nil {
				return nil, errors.New("pending image attempt projection does not join")
			}
		} else if image.Floor.DatabaseID.Length != 32 {
			return nil, errors.New("mixed image floor database identifier is malformed")
		} else {
			activeID, err := hex.DecodeString(image.ActiveAttemptID)
			if err != nil {
				return nil, errors.New("mixed active attempt identifier is malformed")
			}
			activeBase64 := base64.StdEncoding.EncodeToString(activeID)
			if _, exists := attemptIDs[activeBase64]; !exists {
				return nil, errors.New("mixed active attempt is absent from its public page")
			}
		}
		for index, table := range image.Tables {
			if table.Name != tableSpecs[index].Name || table.RowCount < 0 || table.RowCount > maxTableRows {
				return nil, errors.New("output image table summary is invalid")
			}
		}
		if err := putExpectedFile(image.Name+"/publication.db", expectedFile{role: "database", length: -1}); err != nil {
			return nil, err
		}
		if err := putExpectedFile(image.Name+"/publication.db.lock", expectedFile{role: "lock", length: 0}); err != nil {
			return nil, err
		}
		roles := make(map[string]struct{}, wantPayloads)
		cids := make(map[string]struct{}, wantPayloads)
		recordCIDs := make(map[string]struct{}, wantPayloads)
		priorPath := ""
		for _, payload := range image.Payloads {
			prefix := image.Name + "/" + payloadDirectoryName + "/"
			if !strings.HasPrefix(payload.Path, prefix) || filepath.ToSlash(payload.Path) != payload.Path || len(payload.Path) != len(prefix)+72 || payload.Length == 0 || payload.Length > uint64(maxOutputBytes) || !validDigest(payload.SHA256) || !validByteValue(payload.RecordCID, publication.MaxCIDBytes) || !validByteValue(payload.BlobCID, publication.MaxCIDBytes) || !validAttemptID(payload.AttemptID) {
				return nil, errors.New("output payload summary is malformed")
			}
			basename := strings.TrimPrefix(payload.Path, prefix)
			if len(basename) != 72 || filepath.Base(basename) != basename || strings.ContainsAny(basename, "/\\\x00") || !strings.HasSuffix(basename, payloadFileSuffix) || basename != payload.SHA256+payloadFileSuffix {
				return nil, errors.New("output payload path does not match its digest")
			}
			for _, value := range basename[:64] {
				if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
					return nil, errors.New("output payload basename is not canonical")
				}
			}
			if payload.Path <= priorPath {
				return nil, errors.New("output payload paths are not strictly sorted")
			}
			priorPath = payload.Path
			if _, exists := roles[payload.Role]; exists {
				return nil, errors.New("output payload role is duplicated")
			}
			roles[payload.Role] = struct{}{}
			if _, exists := cids[payload.BlobCID.Base64]; exists {
				return nil, errors.New("output payload CID is duplicated")
			}
			cids[payload.BlobCID.Base64] = struct{}{}
			if _, exists := recordCIDs[payload.RecordCID.Base64]; exists {
				return nil, errors.New("output payload record CID is duplicated")
			}
			recordCIDs[payload.RecordCID.Base64] = struct{}{}
			if imageIndex == 0 {
				if payload.Role != "pending-genesis" || payload.Owner != "attempt" || payload.AcceptedRevision != nil || payload.AttemptID != image.ActiveAttemptID {
					return nil, errors.New("pending payload ownership summary differs")
				}
			} else {
				switch payload.Role {
				case "retained-genesis":
					if payload.Owner != "retained-publication" || payload.AcceptedRevision == nil || *payload.AcceptedRevision != 1 {
						return nil, errors.New("retained payload ownership summary differs")
					}
				case "abandoned-catalogued":
					if payload.Owner != "none" || payload.AcceptedRevision != nil {
						return nil, errors.New("abandoned payload ownership summary differs")
					}
				case "active-unresolved":
					if payload.Owner != "attempt" || payload.AcceptedRevision != nil || payload.AttemptID != image.ActiveAttemptID {
						return nil, errors.New("active payload ownership summary differs")
					}
				default:
					return nil, errors.New("mixed payload role is unexpected")
				}
			}
			if err := putExpectedFile(payload.Path, expectedFile{role: "payload", length: int64(payload.Length), digest: payload.SHA256}); err != nil {
				return nil, err
			}
		}
		if imageIndex == 0 {
			if _, ok := roles["pending-genesis"]; !ok {
				return nil, errors.New("pending payload role is missing")
			}
		} else if len(roles) != 3 {
			return nil, errors.New("mixed payload roles are incomplete")
		}
	}
	if len(seenDatabaseIDs) != 2 {
		return nil, errors.New("output image database identifiers are not independent")
	}
	artifactSpecs := map[string]string{
		rowsName: "raw-row-inventory", mixedRowsName: "raw-row-inventory",
		inputsName: "replay-inputs", mixedInputsName: "replay-inputs",
	}
	artifactByName := make(map[string]outputArtifact, len(artifacts))
	for _, artifact := range artifacts {
		role, expected := artifactSpecs[artifact.Name]
		if !expected || artifact.Role != role || len(artifact.Data) == 0 || len(artifact.Data) > maxJSONBytes {
			return nil, errors.New("output artifact name, role, or size is invalid")
		}
		if _, exists := artifactByName[artifact.Name]; exists {
			return nil, errors.New("output artifact is duplicated")
		}
		artifactByName[artifact.Name] = artifact
		digest := sha256.Sum256(artifact.Data)
		if err := putExpectedFile(artifact.Name, expectedFile{role: artifact.Role, length: int64(len(artifact.Data)), digest: hex.EncodeToString(digest[:])}); err != nil {
			return nil, err
		}
	}
	for name := range artifactSpecs {
		if _, exists := artifactByName[name]; !exists {
			return nil, errors.New("required output artifact is missing")
		}
	}
	if len(expectedFiles) != 12 {
		return nil, errors.New("expected output file set is incomplete")
	}
	var files []fileEntry
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("output inventory walk failed")
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("output inventory contains an unsafe path")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return errors.New("output inventory path escaped root")
		}
		relative = filepath.ToSlash(relative)
		if info.IsDir() {
			if _, expected := expectedDirectories[relative]; !expected || verifyPrivateDirectory(path) != nil {
				return errors.New("output inventory contains an unexpected directory")
			}
			if _, duplicate := seenDirectories[relative]; duplicate {
				return errors.New("output inventory directory is duplicated")
			}
			seenDirectories[relative] = struct{}{}
			return nil
		}
		expected, ok := expectedFiles[relative]
		if !ok || verifyPrivateFile(path) != nil || entry.IsDir() {
			return errors.New("output inventory contains an unexpected file")
		}
		if _, duplicate := seenFiles[relative]; duplicate {
			return errors.New("output inventory file is duplicated")
		}
		seenFiles[relative] = struct{}{}
		size := info.Size()
		if size < 0 || size > maxOutputBytes || (expected.length >= 0 && size != expected.length) || (expected.role == "database" && size == 0) || (expected.role == "lock" && size != 0) {
			return errors.New("output file size or shape differs")
		}
		if size > maxOutputBytes-total {
			return errors.New("output tree exceeds its bound")
		}
		total += size
		digest, length, err := hashFile(path, maxOutputBytes)
		if err != nil || length != size || (expected.digest != "" && digest != expected.digest) {
			return errors.New("output file hash or expected bytes differ")
		}
		files = append(files, fileEntry{Path: relative, Role: expected.role, Length: length, SHA256: digest})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(seenDirectories) != len(expectedDirectories) || len(seenFiles) != len(expectedFiles) {
		return nil, errors.New("output inventory is missing an expected path")
	}
	for directory := range expectedDirectories {
		if _, exists := seenDirectories[directory]; !exists {
			return nil, errors.New("output inventory is missing an expected directory")
		}
	}
	for file := range expectedFiles {
		if _, exists := seenFiles[file]; !exists {
			return nil, errors.New("output inventory is missing an expected file")
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	for index := 1; index < len(files); index++ {
		if files[index-1].Path >= files[index].Path {
			return nil, errors.New("output file paths are not strictly sorted")
		}
	}
	return files, nil
}

func containsFile(files []fileEntry, name string) bool {
	for _, file := range files {
		if file.Path == name {
			return true
		}
	}
	return false
}

func hashFile(path string, limit int64) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, errors.New("file open for hashing failed")
	}
	hash := sha256.New()
	length, copyErr := io.Copy(hash, io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || length > limit {
		return "", 0, errors.New("file hashing failed")
	}
	return hex.EncodeToString(hash.Sum(nil)), length, nil
}

func isZeroFloor(floor publicationstate.Floor) bool {
	return reflect.DeepEqual(floor, publicationstate.Floor{})
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func payloadBasename(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]) + payloadFileSuffix
}

func tableCounts(inventory rowInventory) []tableCount {
	counts := make([]tableCount, 0, len(inventory.Tables))
	for _, table := range inventory.Tables {
		counts = append(counts, tableCount{Name: table.Name, RowCount: table.RowCount})
	}
	return counts
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func readImageMetadata(inventory rowInventory) (databaseID [32]byte, revision uint64, generation uint64, mutation uint64, err error) {
	if err = validateInventoryShape(inventory); err != nil {
		return [32]byte{}, 0, 0, 0, errors.New("image metadata inventory shape is invalid")
	}
	id, ok := metadataBlob(inventory, "database_id")
	if !ok || len(id) != len(databaseID) || allZero(id) {
		return [32]byte{}, 0, 0, 0, errors.New("image database identifier is malformed")
	}
	revisionBytes, ok := metadataBlob(inventory, "revision")
	if !ok || len(revisionBytes) != 8 {
		return [32]byte{}, 0, 0, 0, errors.New("image revision metadata is malformed")
	}
	generationBytes, ok := metadataBlob(inventory, "generation")
	if !ok || len(generationBytes) != 8 {
		return [32]byte{}, 0, 0, 0, errors.New("image generation metadata is malformed")
	}
	mutationBytes, ok := metadataBlob(inventory, "attempt_mutation_revision")
	if !ok || len(mutationBytes) != 8 {
		return [32]byte{}, 0, 0, 0, errors.New("image attempt mutation metadata is malformed")
	}
	copy(databaseID[:], id)
	revision = binary.BigEndian.Uint64(revisionBytes)
	generation = binary.BigEndian.Uint64(generationBytes)
	mutation = binary.BigEndian.Uint64(mutationBytes)
	return databaseID, revision, generation, mutation, nil
}

func validateCombinedCoverage(pending, mixed rowInventory) error {
	if err := validateInventoryShape(pending); err != nil {
		return errors.New("pending inventory shape is invalid")
	}
	if err := validateInventoryShape(mixed); err != nil {
		return errors.New("mixed inventory shape is invalid")
	}
	var pendingTotal, mixedTotal int64
	for index, spec := range tableSpecs {
		pendingTable := pending.Tables[index]
		mixedTable := mixed.Tables[index]
		if pendingTable.Name != spec.Name || mixedTable.Name != spec.Name || (pendingTable.RowCount == 0 && mixedTable.RowCount == 0) {
			return errors.New("combined table coverage is incomplete")
		}
		if pendingTable.RowCount > math.MaxInt64-pendingTotal || mixedTable.RowCount > math.MaxInt64-mixedTotal {
			return errors.New("combined row count overflows")
		}
		pendingTotal += pendingTable.RowCount
		mixedTotal += mixedTable.RowCount
	}
	if pendingTotal != 14 || mixedTotal != 44 {
		return errors.New("combined image row totals differ")
	}
	return nil
}

type mixedPayloadExpectation struct {
	role      string
	attemptID [16]byte
	recordCID []byte
	blob      publication.BlobReference
	basename  string
	expected  []byte
}

type mixedReplayInputs struct {
	FormatVersion   int                     `json:"formatVersion"`
	Coverage        string                  `json:"coverage"`
	ResultCoverage  string                  `json:"resultCoverage"`
	APISequenceKind string                  `json:"apiSequenceKind"`
	Binding         bindingValue            `json:"binding"`
	Options         inputOptions            `json:"options"`
	Review          reviewValue             `json:"review"`
	Candidates      mixedReplayCandidates   `json:"candidates"`
	Views           mixedReplayViews        `json:"views"`
	Observations    mixedReplayObservations `json:"observations"`
	Results         mixedReplayResults      `json:"results"`
	APISequence     []string                `json:"apiSequence"`
}

type mixedReplayCandidates struct {
	Genesis             candidateValue `json:"genesis"`
	OwnSuccessor        candidateValue `json:"ownSuccessor"`
	CompetingOccupant   candidateValue `json:"competingOccupant"`
	CompetingExtension  candidateValue `json:"competingExtension"`
	Replacement         candidateValue `json:"replacement"`
	RetirementExtension candidateValue `json:"retirementExtension"`
	ActiveSuccessor     candidateValue `json:"activeSuccessor"`
}

type mixedReplayViews struct {
	EmptyGenesis                  mixedReplayView `json:"emptyGenesis"`
	GenesisCurrent                mixedReplayView `json:"genesisCurrent"`
	Predecessor                   mixedReplayView `json:"predecessor"`
	FirstConflict                 mixedReplayView `json:"firstConflict"`
	Extended                      mixedReplayView `json:"extended"`
	Retirement                    mixedReplayView `json:"retirement"`
	Absence                       mixedReplayView `json:"absence"`
	DerivedReplacementPredecessor mixedReplayView `json:"derivedReplacementPredecessor"`
}

type mixedReplayObservations struct {
	Replacement mixedReplayObservation `json:"replacement"`
	Cache       mixedReplayObservation `json:"cache"`
}

type mixedReplayResults struct {
	Genesis             mixedReplayFinalization  `json:"genesis"`
	PriorLatest         mixedReplayResolution    `json:"priorLatest"`
	PriorLatestEvidence byteValue                `json:"priorLatestEvidence"`
	FirstConflict       mixedReplayFirstConflict `json:"firstConflict"`
	ReplacementFloor    mixedReplayFloor         `json:"replacementFloor"`
	RetiredAttempt      mixedReplayAttempt       `json:"retiredAttempt"`
	RetirementPage      mixedReplayAttemptPage   `json:"retirementPage"`
	FinalFloor          mixedReplayFloor         `json:"finalFloor"`
	AbsentResolution    mixedReplayResolution    `json:"absentResolution"`
	CacheID             byteValue                `json:"cacheID"`
	ActiveMaterial      mixedReplayMaterial      `json:"activeMaterial"`
	FinalPage           mixedReplayAttemptPage   `json:"finalPage"`
	FinalHistory        mixedReplayHistoryPage   `json:"finalHistory"`
	FinalFirstConflict  mixedReplayFirstConflict `json:"finalFirstConflict"`
}

type mixedReplayView struct {
	Origin          bindingValue    `json:"origin"`
	Scope           string          `json:"scope"`
	SuppliedContext contextValue    `json:"suppliedContext"`
	Head            byteValue       `json:"head"`
	HeadCID         *byteValue      `json:"headCID"`
	Snapshots       []snapshotValue `json:"snapshots"`
}

type mixedReplayObservation struct {
	Origin          bindingValue    `json:"origin"`
	SuppliedContext contextValue    `json:"suppliedContext"`
	Head            byteValue       `json:"head"`
	HeadCID         *byteValue      `json:"headCID"`
	Snapshots       []snapshotValue `json:"snapshots"`
}

type mixedReplayFloor struct {
	DatabaseID          byteValue    `json:"databaseID"`
	Revision            uint64       `json:"revision"`
	Generation          uint64       `json:"generation"`
	Provenance          string       `json:"provenance"`
	AnchorCID           byteValue    `json:"anchorCID"`
	Binding             bindingValue `json:"binding"`
	SuppliedContext     contextValue `json:"suppliedContext"`
	Head                byteValue    `json:"head"`
	SnapshotKey         string       `json:"snapshotKey"`
	Sequence            uint64       `json:"sequence"`
	PublicationID       byteValue    `json:"publicationID"`
	RecordCID           byteValue    `json:"recordCID"`
	BlobCID             byteValue    `json:"blobCID"`
	BlobSize            uint64       `json:"blobSize"`
	ObservationDigest   byteValue    `json:"observationDigest"`
	AcceptedEventDigest byteValue    `json:"acceptedEventDigest"`
}

type mixedReplayAttempt struct {
	ID                 byteValue         `json:"id"`
	Kind               string            `json:"kind"`
	Lifecycle          string            `json:"lifecycle"`
	Outcome            string            `json:"outcome"`
	Blocked            string            `json:"blocked"`
	Sequence           uint64            `json:"sequence"`
	SnapshotKey        string            `json:"snapshotKey"`
	SnapshotRecordCID  byteValue         `json:"snapshotRecordCID"`
	HeadRecordCID      byteValue         `json:"headRecordCID"`
	BlobCID            byteValue         `json:"blobCID"`
	BlobSize           uint64            `json:"blobSize"`
	CapturedFloor      *mixedReplayFloor `json:"capturedFloor"`
	CapturedRevision   uint64            `json:"capturedRevision"`
	CapturedGeneration uint64            `json:"capturedGeneration"`
	MutationRevision   uint64            `json:"mutationRevision"`
	StateDigest        byteValue         `json:"stateDigest"`
	Availability       string            `json:"availability"`
}

type mixedReplayFinalization struct {
	Attempt mixedReplayAttempt `json:"attempt"`
	Floor   mixedReplayFloor   `json:"floor"`
}

type mixedReplayResolution struct {
	Attempt    mixedReplayAttempt `json:"attempt"`
	Outcome    string             `json:"outcome"`
	ViewDigest byteValue          `json:"viewDigest"`
	Evidence   byteValue          `json:"evidence"`
}

type mixedReplayFirstConflict struct {
	AttemptID    byteValue `json:"attemptID"`
	ID           byteValue `json:"id"`
	Envelope     byteValue `json:"envelope"`
	Head         byteValue `json:"head"`
	HeadKey      string    `json:"headKey"`
	HeadRecord   byteValue `json:"headRecord"`
	HeadSequence uint64    `json:"headSequence"`
}

type mixedReplayEvidence struct {
	AttemptID byteValue `json:"attemptID"`
	Role      string    `json:"role"`
	Evidence  byteValue `json:"evidence"`
}

type mixedReplayAttemptPage struct {
	Attempts []mixedReplayAttempt  `json:"attempts"`
	Evidence []mixedReplayEvidence `json:"evidence"`
	NextID   byteValue             `json:"nextID"`
	HasMore  bool                  `json:"hasMore"`
}

type mixedReplayRecordReference struct {
	Key      string    `json:"key"`
	CID      byteValue `json:"cid"`
	Sequence uint64    `json:"sequence"`
}

type mixedReplayHistoryEvent struct {
	Revision          uint64                       `json:"revision"`
	Mode              string                       `json:"mode"`
	Reason            string                       `json:"reason"`
	Stop              string                       `json:"stop"`
	OldFloor          *mixedReplayFloor            `json:"oldFloor"`
	NewFloor          mixedReplayFloor             `json:"newFloor"`
	Trace             []mixedReplayRecordReference `json:"trace"`
	ObservationDigest byteValue                    `json:"observationDigest"`
	SuppliedSetDigest byteValue                    `json:"suppliedSetDigest"`
	EventDigest       byteValue                    `json:"eventDigest"`
}

type mixedReplayRecordEvidence struct {
	Reference mixedReplayRecordReference `json:"reference"`
	Raw       byteValue                  `json:"raw"`
}

type mixedReplayHistoryPage struct {
	Events       []mixedReplayHistoryEvent   `json:"events"`
	Records      []mixedReplayRecordEvidence `json:"records"`
	NextRevision uint64                      `json:"nextRevision"`
	HasMore      bool                        `json:"hasMore"`
}

type mixedReplayMaterial struct {
	AttemptID      byteValue `json:"attemptID"`
	SnapshotKey    string    `json:"snapshotKey"`
	SnapshotRecord byteValue `json:"snapshotRecord"`
	HeadRecord     byteValue `json:"headRecord"`
	Payload        byteValue `json:"payload"`
	BlobCID        byteValue `json:"blobCID"`
	BlobSize       uint64    `json:"blobSize"`
}

func mixedPayloadExpectations(inventory rowInventory, state mixedLifecycleState) ([3]mixedPayloadExpectation, error) {
	var result [3]mixedPayloadExpectation
	if err := validateMixedRows(inventory, state); err != nil {
		return result, errors.New("mixed raw rows are not valid for physical inspection")
	}
	type roleInput struct {
		role      string
		attemptID [16]byte
		input     publicationstate.CandidateInput
		metadata  candidateValue
		sequence  uint64
	}
	roles := [3]roleInput{
		{role: "retained-genesis", attemptID: state.Genesis.Attempt.ID, input: state.GenesisInput, metadata: state.GenesisMetadata, sequence: 0},
		{role: "abandoned-catalogued", attemptID: state.RetiredAttempt.ID, input: state.OwnSuccessorInput, metadata: state.OwnSuccessorMetadata, sequence: 1},
		{role: "active-unresolved", attemptID: state.AbsentResolution.Attempt.ID, input: state.ActiveSuccessorInput, metadata: state.ActiveSuccessorMetadata, sequence: 1},
	}
	validName := func(name string) bool {
		if len(name) != 72 || !strings.HasSuffix(name, payloadFileSuffix) || filepath.Base(name) != name || strings.ContainsAny(name, "/\\\x00") || name == "." || name == ".." {
			return false
		}
		for _, value := range name[:64] {
			if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
				return false
			}
		}
		return true
	}
	byCID := make(map[string]int, len(roles))
	byName := make(map[string]int, len(roles))
	var total uint64
	for index, role := range roles {
		if allZero(role.attemptID[:]) || (index > 0 && role.attemptID == roles[0].attemptID) || (index > 1 && role.attemptID == roles[1].attemptID) || len(role.input.SnapshotRecord) == 0 || len(role.input.SnapshotRecord) > publication.MaxRecordBytes || len(role.input.HeadRecord) == 0 || len(role.input.HeadRecord) > publication.MaxRecordBytes || len(role.input.Payload) == 0 || uint64(len(role.input.Payload)) > publication.MaxBlobBytes || uint64(len(role.input.Payload)) > uint64(maxOutputBytes) {
			return result, errors.New("mixed payload role input exceeds its bound")
		}
		size := uint64(len(role.input.Payload))
		if total > uint64(maxOutputBytes)-size {
			return result, errors.New("mixed payload total exceeds its bound")
		}
		total += size
		record, err := publication.DecodeSnapshot(role.input.SnapshotRecord)
		key, keyErr := publication.SequenceKey(role.sequence)
		if err != nil || keyErr != nil || record.PublicationSeq != role.sequence || record.Vault != state.Binding.Vault || role.input.SnapshotKey != key {
			return result, errors.New("mixed payload snapshot role differs")
		}
		recordCID, err := publication.RecordCID(role.input.SnapshotRecord)
		if err != nil {
			return result, errors.New("mixed payload snapshot CID is invalid")
		}
		head, err := publication.DecodeHead(role.input.HeadRecord)
		if err != nil || head.SchemaVersion != publication.SchemaVersion || head.Vault != state.Binding.Vault || head.PublicationSeq != role.sequence || publication.VerifyHeadBinding(role.input.HeadRecord, role.input.SnapshotRecord, role.input.SnapshotKey) != nil {
			return result, errors.New("mixed payload head binding differs")
		}
		headCID, err := publication.RecordCID(role.input.HeadRecord)
		if err != nil {
			return result, errors.New("mixed payload head CID is invalid")
		}
		blobCID, err := publication.RawPayloadCID(role.input.Payload)
		if err != nil || !bytes.Equal(blobCID, record.Blob.CID) || record.Blob.Size != size {
			return result, errors.New("mixed payload bytes do not match snapshot reference")
		}
		if _, err := publication.DecodePayload(role.input.Payload, record.Blob); err != nil {
			return result, errors.New("mixed payload does not fully decode")
		}
		wantMetadata := candidateValue{
			AttemptID: "", PublicationID: hex.EncodeToString(record.PublicationID[:]), SnapshotKey: role.input.SnapshotKey,
			SnapshotCID: encodeBytes(recordCID), HeadCID: encodeBytes(headCID), BlobCID: encodeBytes(record.Blob.CID), BlobSize: record.Blob.Size,
			SnapshotRecord: encodeBytes(role.input.SnapshotRecord), HeadRecord: encodeBytes(role.input.HeadRecord), Payload: encodeBytes(role.input.Payload),
		}
		if !reflect.DeepEqual(role.metadata, wantMetadata) {
			return result, errors.New("mixed payload candidate metadata differs")
		}
		cidKey := string(record.Blob.CID)
		name := payloadBasename(role.input.Payload)
		if !validName(name) || byCID[cidKey] != 0 || byName[name] != 0 {
			return result, errors.New("mixed payload role identities are not distinct")
		}
		byCID[cidKey] = index + 1
		byName[name] = index + 1
		result[index] = mixedPayloadExpectation{role: role.role, attemptID: role.attemptID, recordCID: bytes.Clone(recordCID), blob: publication.BlobReference{CID: bytes.Clone(record.Blob.CID), Size: record.Blob.Size}, basename: name, expected: role.input.Payload}
		for prior := 0; prior < index; prior++ {
			if bytes.Equal(result[prior].expected, result[index].expected) || bytes.Equal(result[prior].blob.CID, result[index].blob.CID) || result[prior].basename == result[index].basename || bytes.Equal(result[prior].recordCID, result[index].recordCID) {
				return [3]mixedPayloadExpectation{}, errors.New("mixed payload roles are not distinct")
			}
		}
	}

	blobAt := func(row []rawCell, index int) ([]byte, bool) {
		if index < 0 || index >= len(row) || row[index].Type != "blob-base64" {
			return nil, false
		}
		value, err := base64.StdEncoding.DecodeString(row[index].Value)
		return value, err == nil
	}
	textAt := func(row []rawCell, index int) (string, bool) {
		if index < 0 || index >= len(row) || row[index].Type != "text-base64" {
			return "", false
		}
		value, err := base64.StdEncoding.DecodeString(row[index].Value)
		return string(value), err == nil
	}
	intAt := func(row []rawCell, index int) (int64, bool) {
		if index < 0 || index >= len(row) || row[index].Type != "integer" {
			return 0, false
		}
		value, err := strconv.ParseInt(row[index].Value, 10, 64)
		return value, err == nil && strconv.FormatInt(value, 10) == row[index].Value
	}
	catalog := tableByName(inventory, "payload_objects").Rows
	if len(catalog) != len(result) {
		return [3]mixedPayloadExpectation{}, errors.New("mixed payload catalog cardinality differs")
	}
	observedByCID := make(map[string]struct{}, len(catalog))
	observedByName := make(map[string]struct{}, len(catalog))
	for _, row := range catalog {
		cid, cidOK := blobAt(row, 0)
		size, sizeOK := intAt(row, 1)
		name, nameOK := textAt(row, 2)
		logical, logicalOK := intAt(row, 3)
		if !cidOK || !sizeOK || !nameOK || !logicalOK || len(cid) == 0 || size <= 0 || uint64(size) > uint64(maxOutputBytes) || !validName(name) || logical != size {
			return [3]mixedPayloadExpectation{}, errors.New("mixed payload catalog cell is invalid")
		}
		cidKey := string(cid)
		if _, exists := observedByCID[cidKey]; exists {
			return [3]mixedPayloadExpectation{}, errors.New("mixed payload catalog CID is duplicated")
		}
		if _, exists := observedByName[name]; exists {
			return [3]mixedPayloadExpectation{}, errors.New("mixed payload catalog basename is duplicated")
		}
		observedByCID[cidKey] = struct{}{}
		observedByName[name] = struct{}{}
		roleIndex := byCID[cidKey] - 1
		if roleIndex < 0 || roleIndex >= len(result) || uint64(size) != result[roleIndex].blob.Size || uint64(size) != uint64(len(result[roleIndex].expected)) || name != payloadBasename(result[roleIndex].expected) {
			return [3]mixedPayloadExpectation{}, errors.New("mixed payload catalog role join differs")
		}
		result[roleIndex].basename = name
	}
	for _, expected := range result {
		if expected.basename == "" {
			return [3]mixedPayloadExpectation{}, errors.New("mixed payload catalog role is missing")
		}
	}
	refs := tableByName(inventory, "attempt_payload_refs").Rows
	retained := tableByName(inventory, "retained_publications").Rows
	if len(refs) != 1 || len(retained) != 1 {
		return [3]mixedPayloadExpectation{}, errors.New("mixed payload ownership cardinality differs")
	}
	activeID, activeIDOK := blobAt(refs[0], 0)
	refCID, refCIDOK := blobAt(refs[0], 1)
	if !activeIDOK || len(activeID) != 16 || !refCIDOK || !bytes.Equal(activeID, result[2].attemptID[:]) || !bytes.Equal(refCID, result[2].blob.CID) {
		return [3]mixedPayloadExpectation{}, errors.New("mixed active payload ownership differs")
	}
	retainedCID, retainedCIDOK := blobAt(retained[0], 0)
	retainedID, retainedIDOK := blobAt(retained[0], 1)
	retainedSequence, sequenceOK := intAt(retained[0], 2)
	retainedBlob, retainedBlobOK := blobAt(retained[0], 3)
	retainedSize, retainedSizeOK := intAt(retained[0], 4)
	retainedRevision, revisionOK := intAt(retained[0], 5)
	if !retainedCIDOK || !retainedIDOK || !sequenceOK || !retainedBlobOK || !retainedSizeOK || !revisionOK || !bytes.Equal(retainedCID, result[0].recordCID) || !bytes.Equal(retainedID, result[0].attemptID[:]) || retainedSequence != 0 || !bytes.Equal(retainedBlob, result[0].blob.CID) || uint64(retainedSize) != result[0].blob.Size || retainedRevision != 1 {
		return [3]mixedPayloadExpectation{}, errors.New("mixed retained genesis payload ownership differs")
	}
	for _, role := range result {
		if role.role == "abandoned-catalogued" && (bytes.Equal(role.attemptID[:], activeID) || bytes.Equal(role.attemptID[:], retainedID)) {
			return [3]mixedPayloadExpectation{}, errors.New("abandoned payload unexpectedly has an owner")
		}
	}
	return result, nil
}

func openMixedImageDirectory(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(os.PathSeparator) || len(path) > 4096 || strings.ContainsRune(path, '\x00') {
		return -1, errors.New("mixed image path is invalid")
	}
	fd, err := unix.Open(string(os.PathSeparator), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, errors.New("mixed image root open failed")
	}
	components := strings.Split(strings.TrimPrefix(path, string(os.PathSeparator)), string(os.PathSeparator))
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			closeErr := unix.Close(fd)
			baseErr := errors.New("mixed image path component is invalid")
			if closeErr != nil {
				baseErr = errors.Join(baseErr, errors.New("owned directory close failed"))
			}
			return -1, baseErr
		}
		flags := unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if index == len(components)-1 {
			flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		}
		next, openErr := unix.Openat(fd, component, flags, 0)
		if openErr != nil {
			closeErr := unix.Close(fd)
			baseErr := errors.New("mixed image path component open failed")
			if closeErr != nil {
				baseErr = errors.Join(baseErr, errors.New("owned directory close failed"))
			}
			return -1, baseErr
		}
		var stat unix.Stat_t
		if statErr := unix.Fstat(next, &stat); statErr != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			closeNextErr := unix.Close(next)
			closeParentErr := unix.Close(fd)
			baseErr := errors.New("mixed image path component is not a directory")
			if statErr != nil {
				baseErr = errors.Join(baseErr, errors.New("directory stat failed"))
			}
			if closeNextErr != nil || closeParentErr != nil {
				baseErr = errors.Join(baseErr, errors.New("owned directory close failed"))
			}
			return -1, baseErr
		}
		if index == len(components)-1 && (stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != 0o700) {
			closeNextErr := unix.Close(next)
			closeParentErr := unix.Close(fd)
			baseErr := errors.New("mixed image directory is not private")
			if closeNextErr != nil || closeParentErr != nil {
				baseErr = errors.Join(baseErr, errors.New("owned directory close failed"))
			}
			return -1, baseErr
		}
		if closeErr := unix.Close(fd); closeErr != nil {
			nextCloseErr := unix.Close(next)
			baseErr := errors.New("owned parent directory close failed")
			if nextCloseErr != nil {
				baseErr = errors.Join(baseErr, errors.New("owned child directory close failed"))
			}
			return -1, baseErr
		}
		fd = next
	}
	return fd, nil
}

func mixedDirectoryNames(directoryFD int) (names []string, resultErr error) {
	if directoryFD < 0 {
		return nil, errors.New("mixed directory descriptor is invalid")
	}
	var borrowed unix.Stat_t
	if err := unix.Fstat(directoryFD, &borrowed); err != nil || borrowed.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errors.New("mixed directory descriptor is not a directory")
	}
	ownedFD, err := unix.Openat(directoryFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("mixed directory enumeration open failed")
	}
	var opened unix.Stat_t
	if err := unix.Fstat(ownedFD, &opened); err != nil || opened.Mode&unix.S_IFMT != unix.S_IFDIR || opened.Dev != borrowed.Dev || opened.Ino != borrowed.Ino {
		closeErr := unix.Close(ownedFD)
		baseErr := errors.New("mixed directory enumeration identity differs")
		if closeErr != nil {
			baseErr = errors.Join(baseErr, errors.New("owned enumeration close failed"))
		}
		return nil, baseErr
	}
	file := os.NewFile(uintptr(ownedFD), "mixed-directory-enumerator")
	if file == nil {
		closeErr := unix.Close(ownedFD)
		baseErr := errors.New("mixed directory enumerator adoption failed")
		if closeErr != nil {
			baseErr = errors.Join(baseErr, errors.New("owned enumeration close failed"))
		}
		return nil, baseErr
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			closeCategory := errors.New("owned enumeration close failed")
			if resultErr == nil {
				resultErr = closeCategory
			} else {
				resultErr = errors.Join(resultErr, closeCategory)
			}
		}
	}()
	names, err = file.Readdirnames(4)
	if err != nil && err != io.EOF {
		return nil, errors.New("mixed directory enumeration failed")
	}
	if len(names) >= 4 {
		return nil, errors.New("mixed directory contains extra entries")
	}
	if err == nil {
		extra, extraErr := file.Readdirnames(1)
		if len(extra) != 0 || (extraErr != nil && extraErr != io.EOF) || (len(extra) == 0 && extraErr != io.EOF) {
			return nil, errors.New("mixed directory EOF check failed")
		}
	}
	if len(names) != 3 {
		return nil, errors.New("mixed directory entry count differs")
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name == "" || name == "." || name == ".." {
			return nil, errors.New("mixed directory entry name is invalid")
		}
		if _, exists := seen[name]; exists {
			return nil, errors.New("mixed directory entry name is duplicated")
		}
		seen[name] = struct{}{}
	}
	return names, nil
}

func inspectMixedPayloadFD(payloadDirectoryFD int, expected mixedPayloadExpectation) (resultErr error) {
	if payloadDirectoryFD < 0 {
		return errors.New("mixed payload directory descriptor is invalid")
	}
	var directoryStat unix.Stat_t
	if err := unix.Fstat(payloadDirectoryFD, &directoryStat); err != nil || directoryStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("mixed payload directory descriptor is not a directory")
	}
	validName := func(name string) bool {
		if len(name) != 72 || !strings.HasSuffix(name, payloadFileSuffix) || filepath.Base(name) != name || strings.ContainsAny(name, "/\\\x00") || name == "." || name == ".." {
			return false
		}
		for _, value := range name[:64] {
			if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
				return false
			}
		}
		return true
	}
	if !validName(expected.basename) || len(expected.recordCID) == 0 || len(expected.recordCID) > publication.MaxCIDBytes || expected.blob.Size == 0 || expected.blob.Size > publication.MaxBlobBytes || expected.blob.Size > uint64(maxOutputBytes) || expected.blob.Size != uint64(len(expected.expected)) {
		return errors.New("mixed expected payload shape is invalid")
	}
	var namedBefore unix.Stat_t
	if err := unix.Fstatat(payloadDirectoryFD, expected.basename, &namedBefore, unix.AT_SYMLINK_NOFOLLOW); err != nil || namedBefore.Mode&unix.S_IFMT != unix.S_IFREG || namedBefore.Uid != uint32(os.Geteuid()) || namedBefore.Mode&0o7777 != 0o600 || namedBefore.Nlink != 1 || namedBefore.Size <= 0 || uint64(namedBefore.Size) != expected.blob.Size {
		return errors.New("mixed named payload is not a private regular file")
	}
	fd, err := unix.Openat(payloadDirectoryFD, expected.basename, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return errors.New("mixed payload file open failed")
	}
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uint32(os.Geteuid()) || before.Mode&0o7777 != 0o600 || before.Nlink != 1 || before.Size <= 0 || uint64(before.Size) != expected.blob.Size || before.Dev != namedBefore.Dev || before.Ino != namedBefore.Ino {
		closeErr := unix.Close(fd)
		baseErr := errors.New("mixed opened payload identity or shape differs")
		if closeErr != nil {
			baseErr = errors.Join(baseErr, errors.New("owned payload close failed"))
		}
		return baseErr
	}
	file := os.NewFile(uintptr(fd), "mixed-payload")
	if file == nil {
		closeErr := unix.Close(fd)
		baseErr := errors.New("mixed payload descriptor adoption failed")
		if closeErr != nil {
			baseErr = errors.Join(baseErr, errors.New("owned payload close failed"))
		}
		return baseErr
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			closeCategory := errors.New("owned payload close failed")
			if resultErr == nil {
				resultErr = closeCategory
			} else {
				resultErr = errors.Join(resultErr, closeCategory)
			}
		}
	}()
	actual, readErr := io.ReadAll(io.LimitReader(file, int64(expected.blob.Size)+1))
	if readErr != nil || uint64(len(actual)) != expected.blob.Size {
		return errors.New("mixed payload bounded read differs")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || after.Mode&unix.S_IFMT != unix.S_IFREG || after.Uid != uint32(os.Geteuid()) || after.Mode&0o7777 != 0o600 || after.Nlink != 1 || after.Size != before.Size || after.Dev != before.Dev || after.Ino != before.Ino || after.Mtim != before.Mtim || after.Ctim != before.Ctim {
		return errors.New("mixed payload changed during read")
	}
	var namedAfter unix.Stat_t
	if err := unix.Fstatat(payloadDirectoryFD, expected.basename, &namedAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil || namedAfter.Mode&unix.S_IFMT != unix.S_IFREG || namedAfter.Uid != uint32(os.Geteuid()) || namedAfter.Mode&0o7777 != 0o600 || namedAfter.Nlink != 1 || namedAfter.Size != after.Size || namedAfter.Dev != after.Dev || namedAfter.Ino != after.Ino || namedAfter.Mtim != after.Mtim || namedAfter.Ctim != after.Ctim {
		return errors.New("mixed payload name changed during read")
	}
	actualHash := sha256.Sum256(actual)
	expectedHash := sha256.Sum256(expected.expected)
	if !bytes.Equal(actual, expected.expected) || actualHash != expectedHash || payloadBasename(actual) != expected.basename {
		return errors.New("mixed payload bytes or basename differ")
	}
	actualCID, err := publication.RawPayloadCID(actual)
	if err != nil || !bytes.Equal(actualCID, expected.blob.CID) {
		return errors.New("mixed payload raw CID differs")
	}
	if _, err := publication.DecodePayload(actual, expected.blob); err != nil {
		return errors.New("mixed payload full decode failed")
	}
	return nil
}

func validateMixedPhysicalPayloads(imageDirectory string, inventory rowInventory, state mixedLifecycleState) (resultErr error) {
	expectations, err := mixedPayloadExpectations(inventory, state)
	if err != nil {
		return err
	}
	imageFD, err := openMixedImageDirectory(imageDirectory)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := unix.Close(imageFD); closeErr != nil {
			closeCategory := errors.New("owned image directory close failed")
			if resultErr == nil {
				resultErr = closeCategory
			} else {
				resultErr = errors.Join(resultErr, closeCategory)
			}
		}
	}()
	var imageBefore unix.Stat_t
	if err := unix.Fstat(imageFD, &imageBefore); err != nil || imageBefore.Mode&unix.S_IFMT != unix.S_IFDIR || imageBefore.Uid != uint32(os.Geteuid()) || imageBefore.Mode&0o7777 != 0o700 {
		return errors.New("mixed image descriptor changed")
	}
	payloadFD, err := unix.Openat(imageFD, payloadDirectoryName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return errors.New("mixed payload directory open failed")
	}
	defer func() {
		if closeErr := unix.Close(payloadFD); closeErr != nil {
			closeCategory := errors.New("owned payload directory close failed")
			if resultErr == nil {
				resultErr = closeCategory
			} else {
				resultErr = errors.Join(resultErr, closeCategory)
			}
		}
	}()
	var payloadBefore, payloadNamed unix.Stat_t
	if err := unix.Fstat(payloadFD, &payloadBefore); err != nil || payloadBefore.Mode&unix.S_IFMT != unix.S_IFDIR || payloadBefore.Uid != uint32(os.Geteuid()) || payloadBefore.Mode&0o7777 != 0o700 {
		return errors.New("mixed payload directory is not private")
	}
	if err := unix.Fstatat(imageFD, payloadDirectoryName, &payloadNamed, unix.AT_SYMLINK_NOFOLLOW); err != nil || payloadNamed.Mode&unix.S_IFMT != unix.S_IFDIR || payloadNamed.Dev != payloadBefore.Dev || payloadNamed.Ino != payloadBefore.Ino || payloadNamed.Uid != uint32(os.Geteuid()) || payloadNamed.Mode&0o7777 != 0o700 {
		return errors.New("mixed payload directory name identity differs")
	}

	type rootFileState struct {
		name string
		dev  uint64
		ino  uint64
		size int64
		mtim unix.Timespec
		ctim unix.Timespec
	}
	inspectRootFile := func(name string, lock bool) (rootFileState, error) {
		var stat unix.Stat_t
		if err := unix.Fstatat(imageFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != 0o600 || stat.Nlink != 1 || stat.Size < 0 || stat.Size > maxOutputBytes || (lock && stat.Size != 0) || (!lock && stat.Size == 0) {
			return rootFileState{}, errors.New("mixed image root file shape differs")
		}
		return rootFileState{name: name, dev: uint64(stat.Dev), ino: stat.Ino, size: stat.Size, mtim: stat.Mtim, ctim: stat.Ctim}, nil
	}
	checkSidecars := func() error {
		for _, name := range []string{"publication.db-wal", "publication.db-shm"} {
			var stat unix.Stat_t
			err := unix.Fstatat(imageFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
			if !errors.Is(err, unix.ENOENT) {
				return errors.New("mixed SQLite sidecar is present or cannot be checked")
			}
		}
		return nil
	}
	rootNames, err := mixedDirectoryNames(imageFD)
	if err != nil {
		return err
	}
	sort.Strings(rootNames)
	if !equalStrings(rootNames, []string{"payloads", "publication.db", "publication.db.lock"}) {
		return errors.New("mixed image root entry set differs")
	}
	databaseBefore, err := inspectRootFile("publication.db", false)
	if err != nil {
		return err
	}
	lockBefore, err := inspectRootFile("publication.db.lock", true)
	if err != nil {
		return err
	}
	if err := checkSidecars(); err != nil {
		return err
	}
	payloadNames, err := mixedDirectoryNames(payloadFD)
	if err != nil {
		return err
	}
	wantNames := []string{expectations[0].basename, expectations[1].basename, expectations[2].basename}
	sort.Strings(payloadNames)
	sort.Strings(wantNames)
	if !equalStrings(payloadNames, wantNames) {
		return errors.New("mixed payload entry set differs from observed catalog")
	}
	for _, expected := range expectations {
		if err := inspectMixedPayloadFD(payloadFD, expected); err != nil {
			return err
		}
	}
	rootNames, err = mixedDirectoryNames(imageFD)
	if err != nil {
		return err
	}
	sort.Strings(rootNames)
	if !equalStrings(rootNames, []string{"payloads", "publication.db", "publication.db.lock"}) {
		return errors.New("mixed image root entry set changed")
	}
	payloadNames, err = mixedDirectoryNames(payloadFD)
	if err != nil {
		return err
	}
	sort.Strings(payloadNames)
	if !equalStrings(payloadNames, wantNames) {
		return errors.New("mixed payload entry set changed")
	}
	databaseAfter, err := inspectRootFile("publication.db", false)
	if err != nil || databaseAfter != databaseBefore {
		return errors.New("mixed database file changed during sampled inspection")
	}
	lockAfter, err := inspectRootFile("publication.db.lock", true)
	if err != nil || lockAfter != lockBefore {
		return errors.New("mixed lock file changed during sampled inspection")
	}
	if err := checkSidecars(); err != nil {
		return err
	}
	var imageAfter, payloadAfter, payloadNamedAfter unix.Stat_t
	if err := unix.Fstat(imageFD, &imageAfter); err != nil || imageAfter.Dev != imageBefore.Dev || imageAfter.Ino != imageBefore.Ino || imageAfter.Uid != uint32(os.Geteuid()) || imageAfter.Mode&0o7777 != 0o700 {
		return errors.New("mixed image directory changed during sampled inspection")
	}
	if err := unix.Fstat(payloadFD, &payloadAfter); err != nil || payloadAfter.Dev != payloadBefore.Dev || payloadAfter.Ino != payloadBefore.Ino || payloadAfter.Uid != uint32(os.Geteuid()) || payloadAfter.Mode&0o7777 != 0o700 {
		return errors.New("mixed payload directory changed during sampled inspection")
	}
	if err := unix.Fstatat(imageFD, payloadDirectoryName, &payloadNamedAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil || payloadNamedAfter.Dev != payloadAfter.Dev || payloadNamedAfter.Ino != payloadAfter.Ino || payloadNamedAfter.Mode&unix.S_IFMT != unix.S_IFDIR || payloadNamedAfter.Uid != uint32(os.Geteuid()) || payloadNamedAfter.Mode&0o7777 != 0o700 {
		return errors.New("mixed payload directory name changed during sampled inspection")
	}
	return nil
}

func mixedReplayCandidateFor(binding publicationstate.Binding, input publicationstate.CandidateInput, metadata candidateValue) (candidateValue, error) {
	if len(input.SnapshotRecord) == 0 || len(input.SnapshotRecord) > publication.MaxRecordBytes || len(input.HeadRecord) == 0 || len(input.HeadRecord) > publication.MaxRecordBytes || len(input.Payload) == 0 || uint64(len(input.Payload)) > publication.MaxBlobBytes || uint64(len(input.Payload)) > uint64(maxOutputBytes) || len(input.SnapshotKey) > publication.MaxRecordBytes {
		return candidateValue{}, errors.New("mixed replay candidate exceeds its bound")
	}
	if metadata.AttemptID != "" || len(metadata.PublicationID) != 32 || len(metadata.SnapshotKey) > publication.MaxRecordBytes || len(metadata.SnapshotCID.Base64) > maxJSONBytes || len(metadata.HeadCID.Base64) > maxJSONBytes || len(metadata.BlobCID.Base64) > maxJSONBytes || len(metadata.SnapshotRecord.Base64) > maxJSONBytes || len(metadata.HeadRecord.Base64) > maxJSONBytes || len(metadata.Payload.Base64) > maxJSONBytes {
		return candidateValue{}, errors.New("mixed replay candidate metadata is invalid")
	}
	record, err := publication.DecodeSnapshot(input.SnapshotRecord)
	if err != nil || record.Vault != binding.Vault || allZero(record.PublicationID[:]) {
		return candidateValue{}, errors.New("mixed replay snapshot record is invalid")
	}
	sequence, err := publication.ParseSequenceKey(input.SnapshotKey)
	if err != nil || sequence != record.PublicationSeq {
		return candidateValue{}, errors.New("mixed replay snapshot key differs")
	}
	recordCID, err := publication.RecordCID(input.SnapshotRecord)
	if err != nil {
		return candidateValue{}, errors.New("mixed replay snapshot CID is invalid")
	}
	head, err := publication.DecodeHead(input.HeadRecord)
	if err != nil || head.SchemaVersion != publication.SchemaVersion || head.Vault != binding.Vault || head.PublicationSeq != sequence || publication.VerifyHeadBinding(input.HeadRecord, input.SnapshotRecord, input.SnapshotKey) != nil {
		return candidateValue{}, errors.New("mixed replay head binding differs")
	}
	headCID, err := publication.RecordCID(input.HeadRecord)
	if err != nil {
		return candidateValue{}, errors.New("mixed replay head CID is invalid")
	}
	blobCID, err := publication.RawPayloadCID(input.Payload)
	if err != nil || !bytes.Equal(blobCID, record.Blob.CID) || record.Blob.Size != uint64(len(input.Payload)) {
		return candidateValue{}, errors.New("mixed replay payload reference differs")
	}
	if _, err := publication.DecodePayload(input.Payload, record.Blob); err != nil {
		return candidateValue{}, errors.New("mixed replay payload does not fully decode")
	}
	computed := candidateValue{
		AttemptID: "", PublicationID: hex.EncodeToString(record.PublicationID[:]), SnapshotKey: input.SnapshotKey,
		SnapshotCID: encodeBytes(recordCID), HeadCID: encodeBytes(headCID), BlobCID: encodeBytes(record.Blob.CID), BlobSize: record.Blob.Size,
		SnapshotRecord: encodeBytes(input.SnapshotRecord), HeadRecord: encodeBytes(input.HeadRecord), Payload: encodeBytes(input.Payload),
	}
	if !reflect.DeepEqual(computed, metadata) {
		return candidateValue{}, errors.New("mixed replay candidate descriptors differ from inputs")
	}
	return computed, nil
}

func makeMixedReplayInputs(state mixedLifecycleState, options publicationstate.OpenOptions) (mixedReplayInputs, error) {
	var zero mixedReplayInputs
	if options.PositionLimits != publicationstate.DefaultLimits() || options.AttemptLimits != publicationstate.DefaultAttemptLimits() || options.UpgradeFromPositions {
		return zero, errors.New("mixed replay options are not the public defaults")
	}
	if state.Binding.AccountDID == "" || state.Binding.Backend != publicationstate.BackendPublicRepo || state.Binding.Repository == "" || allZero(state.Binding.Vault[:]) || state.Review.SelectionRevision == 0 || state.Review.ApprovalRevision == 0 {
		return zero, errors.New("mixed replay state binding or review is invalid")
	}
	chargeTotal := uint64(0)
	charge := func(data []byte) error {
		size := uint64(len(data))
		if size > uint64(maxJSONBytes) || chargeTotal > uint64(maxJSONBytes)-size {
			return errors.New("mixed replay source byte budget exceeded")
		}
		chargeTotal += size
		return nil
	}
	chargeString := func(value string, maximum int) error {
		if len(value) > maximum {
			return errors.New("mixed replay source string exceeds its bound")
		}
		size := uint64(len(value))
		if chargeTotal > uint64(maxJSONBytes)-size {
			return errors.New("mixed replay source byte budget exceeded")
		}
		chargeTotal += size
		return nil
	}
	chargeBinding := func(value publicationstate.Binding) error {
		for _, field := range []struct {
			value string
			limit int
		}{{value.AccountDID, 1024}, {string(value.Backend), 128}, {value.Repository, 2048}} {
			if err := chargeString(field.value, field.limit); err != nil {
				return err
			}
		}
		return charge(value.Vault[:])
	}
	chargeContext := func(value publicationstate.SuppliedContext) error {
		if err := chargeString(value.RepositoryRevision, 1024); err != nil {
			return err
		}
		if len(value.RepositoryDigest) == 0 || len(value.RepositoryDigest) > 128 {
			return errors.New("mixed replay context digest is invalid")
		}
		if err := charge(value.RepositoryDigest); err != nil {
			return err
		}
		if value.Policy != nil {
			if err := chargeString(value.Policy.Revision, 1024); err != nil {
				return err
			}
			if len(value.Policy.Identity) > 128 {
				return errors.New("mixed replay policy identity exceeds its bound")
			}
			return charge(value.Policy.Identity)
		}
		return nil
	}
	chargeCandidate := func(input publicationstate.CandidateInput, metadata candidateValue) error {
		if len(input.SnapshotRecord) == 0 || len(input.SnapshotRecord) > publication.MaxRecordBytes || len(input.HeadRecord) == 0 || len(input.HeadRecord) > publication.MaxRecordBytes || len(input.Payload) == 0 || uint64(len(input.Payload)) > publication.MaxBlobBytes || uint64(len(input.Payload)) > uint64(maxOutputBytes) {
			return errors.New("mixed replay candidate exceeds its source bound")
		}
		if err := chargeString(input.SnapshotKey, publication.MaxRecordBytes); err != nil {
			return err
		}
		for _, data := range [][]byte{input.SnapshotRecord, input.HeadRecord, input.Payload} {
			if err := charge(data); err != nil {
				return err
			}
		}
		for _, value := range []string{metadata.AttemptID, metadata.PublicationID, metadata.SnapshotKey, metadata.SnapshotCID.Base64, metadata.SnapshotCID.SHA256, metadata.HeadCID.Base64, metadata.HeadCID.SHA256, metadata.BlobCID.Base64, metadata.BlobCID.SHA256, metadata.SnapshotRecord.Base64, metadata.SnapshotRecord.SHA256, metadata.HeadRecord.Base64, metadata.HeadRecord.SHA256, metadata.Payload.Base64, metadata.Payload.SHA256} {
			if err := chargeString(value, maxJSONBytes); err != nil {
				return err
			}
		}
		return nil
	}
	chargeBlocks := func(head []byte, blocks []publicationstate.SnapshotBlock, supplied publicationstate.SuppliedContext) error {
		if len(head) > publication.MaxRecordBytes || len(blocks) > 4 {
			return errors.New("mixed replay view exceeds its source bound")
		}
		if err := charge(head); err != nil {
			return err
		}
		if err := chargeContext(supplied); err != nil {
			return err
		}
		for _, block := range blocks {
			if len(block.Raw) == 0 || len(block.Raw) > publication.MaxRecordBytes {
				return errors.New("mixed replay view record exceeds its source bound")
			}
			if err := chargeString(block.Key, publication.MaxRecordBytes); err != nil {
				return err
			}
			if err := charge(block.Raw); err != nil {
				return err
			}
		}
		return nil
	}
	chargeFloor := func(value publicationstate.Floor) error {
		if err := chargeBinding(value.Binding); err != nil {
			return err
		}
		if err := chargeString(value.SnapshotKey, publication.MaxRecordBytes); err != nil {
			return err
		}
		for _, data := range [][]byte{value.DatabaseID[:], value.AnchorCID, value.SuppliedContext.RepositoryDigest, value.Head, value.PublicationID[:], value.RecordCID, value.BlobCID, value.ObservationDigest[:], value.AcceptedEventDigest[:]} {
			if err := charge(data); err != nil {
				return err
			}
		}
		if err := chargeContext(value.SuppliedContext); err != nil {
			return err
		}
		return chargeString(string(value.Provenance), 128)
	}
	chargeOptionalFloor := func(value *publicationstate.Floor) error {
		if value != nil {
			return chargeFloor(*value)
		}
		return nil
	}
	chargeAttempt := func(value publicationstate.Attempt) error {
		for _, data := range [][]byte{value.ID[:], value.SnapshotRecordCID, value.HeadRecordCID, value.BlobCID, value.StateDigest[:]} {
			if err := charge(data); err != nil {
				return err
			}
		}
		if err := chargeOptionalFloor(value.CapturedFloor); err != nil {
			return err
		}
		for _, text := range []string{string(value.Kind), string(value.Lifecycle), string(value.Outcome), value.Blocked, value.SnapshotKey, string(value.Availability)} {
			if err := chargeString(text, 1024); err != nil {
				return err
			}
		}
		return nil
	}
	chargeResolution := func(value publicationstate.AttemptResolution) error {
		if err := chargeAttempt(value.Attempt); err != nil {
			return err
		}
		if len(value.Evidence) == 0 || uint64(len(value.Evidence)) > publicationstate.DefaultAttemptLimits().EvidenceSlotBytes {
			return errors.New("mixed replay resolution evidence exceeds its bound")
		}
		if err := charge(value.ViewDigest[:]); err != nil {
			return err
		}
		if err := charge(value.Evidence); err != nil {
			return err
		}
		return chargeString(string(value.Outcome), 128)
	}
	chargeConflict := func(value publicationstate.FirstConflictEvidence) error {
		for _, data := range [][]byte{value.AttemptID[:], value.ID[:], value.Evidence, value.Head, value.HeadRecord} {
			if len(data) > 0 && len(data) > int(publicationstate.DefaultAttemptLimits().EvidenceSlotBytes) {
				return errors.New("mixed replay conflict evidence exceeds its bound")
			}
			if err := charge(data); err != nil {
				return err
			}
		}
		return chargeString(value.HeadKey, publication.MaxRecordBytes)
	}
	chargePage := func(value publicationstate.AttemptPage, maxAttempts, maxEvidence int) error {
		if len(value.Attempts) > maxAttempts || len(value.Evidence) > maxEvidence {
			return errors.New("mixed replay attempt page exceeds its source bound")
		}
		if err := charge(value.NextID[:]); err != nil {
			return err
		}
		for _, item := range value.Attempts {
			if err := chargeAttempt(item); err != nil {
				return err
			}
		}
		for _, item := range value.Evidence {
			if len(item.Evidence) == 0 || uint64(len(item.Evidence)) > publicationstate.DefaultAttemptLimits().EvidenceSlotBytes {
				return errors.New("mixed replay page evidence exceeds its bound")
			}
			if err := charge(item.AttemptID[:]); err != nil {
				return err
			}
			if err := charge(item.Evidence); err != nil {
				return err
			}
			if err := chargeString(item.Role, 128); err != nil {
				return err
			}
		}
		return nil
	}
	chargeHistory := func(value publicationstate.HistoryPage) error {
		if len(value.Events) > 2 || len(value.Records) > 2 {
			return errors.New("mixed replay history page exceeds its source bound")
		}
		for _, event := range value.Events {
			if err := chargeOptionalFloor(event.OldFloor); err != nil {
				return err
			}
			if err := chargeFloor(event.NewFloor); err != nil {
				return err
			}
			if len(event.Trace) > 4 {
				return errors.New("mixed replay history trace exceeds its bound")
			}
			if err := charge(event.ObservationDigest[:]); err != nil {
				return err
			}
			if err := charge(event.SuppliedSetDigest[:]); err != nil {
				return err
			}
			if err := charge(event.EventDigest[:]); err != nil {
				return err
			}
			for _, ref := range event.Trace {
				if err := charge(ref.CID); err != nil {
					return err
				}
				if err := chargeString(ref.Key, publication.MaxRecordBytes); err != nil {
					return err
				}
			}
			for _, text := range []string{string(event.Mode), string(event.Reason), event.Stop} {
				if err := chargeString(text, 1024); err != nil {
					return err
				}
			}
		}
		for _, record := range value.Records {
			if len(record.Raw) == 0 || len(record.Raw) > publication.MaxRecordBytes {
				return errors.New("mixed replay history record exceeds its bound")
			}
			if err := charge(record.Reference.CID); err != nil {
				return err
			}
			if err := charge(record.Raw); err != nil {
				return err
			}
			if err := chargeString(record.Reference.Key, publication.MaxRecordBytes); err != nil {
				return err
			}
		}
		return nil
	}

	candidateInputs := [7]publicationstate.CandidateInput{state.GenesisInput, state.OwnSuccessorInput, state.CompetingOccupantInput, state.CompetingExtensionInput, state.ReplacementInput, state.RetirementExtensionInput, state.ActiveSuccessorInput}
	candidateMetadata := [7]candidateValue{state.GenesisMetadata, state.OwnSuccessorMetadata, state.CompetingOccupantMetadata, state.CompetingExtensionMetadata, state.ReplacementMetadata, state.RetirementExtensionMetadata, state.ActiveSuccessorMetadata}
	if err := chargeBinding(state.Binding); err != nil {
		return zero, err
	}
	for index := range candidateInputs {
		if err := chargeCandidate(candidateInputs[index], candidateMetadata[index]); err != nil {
			return zero, err
		}
	}
	viewsForCharge := []publicationstate.SuppliedRepositoryView{state.EmptyGenesisView, state.GenesisCurrentView, state.PredecessorView, state.FirstConflictView, state.ExtendedView, state.RetirementView, state.AbsenceView}
	for _, view := range viewsForCharge {
		if err := chargeBinding(view.Origin); err != nil {
			return zero, err
		}
		if err := chargeBlocks(view.Head, view.Snapshots, view.SuppliedContext); err != nil {
			return zero, err
		}
	}
	for _, observation := range []publicationstate.Observation{state.ReplacementObservation, state.CacheObservation, state.ReplacementObservation} {
		if err := chargeBinding(observation.Origin); err != nil {
			return zero, err
		}
		if err := chargeBlocks(observation.Head, observation.Snapshots, observation.SuppliedContext); err != nil {
			return zero, err
		}
	}
	for _, floor := range []publicationstate.Floor{state.Genesis.Floor, state.ReplacementFloor, state.FinalFloor} {
		if err := chargeFloor(floor); err != nil {
			return zero, err
		}
	}
	for _, attempt := range []publicationstate.Attempt{state.Genesis.Attempt, state.RetiredAttempt, state.PriorLatest.Attempt, state.AbsentResolution.Attempt} {
		if err := chargeAttempt(attempt); err != nil {
			return zero, err
		}
	}
	if err := chargeOptionalFloor(state.Genesis.Attempt.CapturedFloor); err != nil {
		return zero, err
	}
	if err := chargeResolution(state.PriorLatest); err != nil {
		return zero, err
	}
	if err := chargeResolution(state.AbsentResolution); err != nil {
		return zero, err
	}
	if err := chargeConflict(state.FirstConflict); err != nil {
		return zero, err
	}
	if err := chargeConflict(state.FinalFirstConflict); err != nil {
		return zero, err
	}
	if err := chargePage(state.RetirementPage, 2, 6); err != nil {
		return zero, err
	}
	if err := chargePage(state.FinalPage, 3, 8); err != nil {
		return zero, err
	}
	if err := chargeHistory(state.FinalHistory); err != nil {
		return zero, err
	}
	for _, data := range [][]byte{state.PriorLatestEvidence, state.ActiveMaterial.AttemptID[:], state.ActiveMaterial.SnapshotRecord, state.ActiveMaterial.HeadRecord, state.ActiveMaterial.Payload, state.ActiveMaterial.Blob.CID, state.CacheID[:]} {
		if err := charge(data); err != nil {
			return zero, err
		}
	}
	if err := chargeString(state.ActiveMaterial.SnapshotKey, publication.MaxRecordBytes); err != nil {
		return zero, err
	}

	candidates := make([]candidateValue, len(candidateInputs))
	for index := range candidateInputs {
		value, err := mixedReplayCandidateFor(state.Binding, candidateInputs[index], candidateMetadata[index])
		if err != nil {
			return zero, err
		}
		candidates[index] = value
		for prior := 0; prior < index; prior++ {
			if value.PublicationID == candidates[prior].PublicationID || value.SnapshotCID.Base64 == candidates[prior].SnapshotCID.Base64 || value.HeadCID.Base64 == candidates[prior].HeadCID.Base64 || value.BlobCID.Base64 == candidates[prior].BlobCID.Base64 || bytes.Equal(candidateInputs[index].Payload, candidateInputs[prior].Payload) {
				return zero, errors.New("mixed replay candidate roles are not distinct")
			}
		}
	}
	attemptMatchesCandidate := func(input publicationstate.CandidateInput, attempt publicationstate.Attempt, expectedKind publicationstate.AttemptKind) error {
		record, err := publication.DecodeSnapshot(input.SnapshotRecord)
		if err != nil || record.Vault != state.Binding.Vault || allZero(record.PublicationID[:]) {
			return errors.New("mixed replay attempted candidate record is invalid")
		}
		sequence := record.PublicationSeq
		key, keyErr := publication.SequenceKey(sequence)
		if keyErr != nil || input.SnapshotKey != key {
			return errors.New("mixed replay attempted candidate key differs")
		}
		if expectedKind == publicationstate.AttemptGenesis {
			if sequence != 0 || len(record.Parent) != 0 {
				return errors.New("mixed replay genesis candidate role differs")
			}
		} else if expectedKind == publicationstate.AttemptSuccessor {
			if sequence == 0 || len(record.Parent) == 0 {
				return errors.New("mixed replay successor candidate role differs")
			}
		} else {
			return errors.New("mixed replay attempted candidate kind is invalid")
		}
		snapshotCID, err := publication.RecordCID(input.SnapshotRecord)
		if err != nil {
			return errors.New("mixed replay attempted snapshot CID is invalid")
		}
		head, err := publication.DecodeHead(input.HeadRecord)
		if err != nil || head.SchemaVersion != publication.SchemaVersion || head.Vault != state.Binding.Vault || head.PublicationSeq != sequence || publication.VerifyHeadBinding(input.HeadRecord, input.SnapshotRecord, key) != nil {
			return errors.New("mixed replay attempted head binding differs")
		}
		headCID, err := publication.RecordCID(input.HeadRecord)
		if err != nil {
			return errors.New("mixed replay attempted head CID is invalid")
		}
		payloadCID, err := publication.RawPayloadCID(input.Payload)
		if err != nil || record.Blob.Size != uint64(len(input.Payload)) || !bytes.Equal(payloadCID, record.Blob.CID) || publication.VerifyPayload(input.Payload, record.Blob) != nil {
			return errors.New("mixed replay attempted payload reference differs")
		}
		if attempt.Kind != expectedKind || attempt.ID != record.PublicationID || attempt.Sequence != sequence || attempt.SnapshotKey != key || !bytes.Equal(attempt.SnapshotRecordCID, snapshotCID) || !bytes.Equal(attempt.HeadRecordCID, headCID) || !bytes.Equal(attempt.BlobCID, record.Blob.CID) || attempt.BlobSize != record.Blob.Size {
			return errors.New("mixed replay attempted candidate does not match retained attempt")
		}
		return nil
	}
	for _, binding := range []struct {
		input   publicationstate.CandidateInput
		attempt publicationstate.Attempt
		kind    publicationstate.AttemptKind
		role    string
	}{{state.GenesisInput, state.Genesis.Attempt, publicationstate.AttemptGenesis, "genesis"}, {state.OwnSuccessorInput, state.PriorLatest.Attempt, publicationstate.AttemptSuccessor, "prior latest"}, {state.OwnSuccessorInput, state.RetiredAttempt, publicationstate.AttemptSuccessor, "retired"}, {state.ActiveSuccessorInput, state.AbsentResolution.Attempt, publicationstate.AttemptSuccessor, "active"}} {
		if err := attemptMatchesCandidate(binding.input, binding.attempt, binding.kind); err != nil {
			return zero, errors.New("mixed replay " + binding.role + " candidate join failed")
		}
	}
	candidateForCID := make(map[string]publicationstate.CandidateInput, len(candidates))
	for index, value := range candidates {
		cid, err := base64.StdEncoding.DecodeString(value.SnapshotCID.Base64)
		if err != nil || len(cid) == 0 {
			return zero, errors.New("mixed replay candidate CID descriptor is invalid")
		}
		candidateForCID[string(cid)] = candidateInputs[index]
	}
	viewFor := func(view publicationstate.SuppliedRepositoryView) (mixedReplayView, error) {
		if view.Origin != state.Binding || view.Scope != publicationstate.ViewScopeWholeRepository || len(view.Snapshots) > 4 {
			return mixedReplayView{}, errors.New("mixed replay supplied view shape differs")
		}
		result := mixedReplayView{Origin: bindingValueFor(view.Origin), Scope: string(view.Scope), SuppliedContext: contextValueFor(view.SuppliedContext), Head: encodeBytes(view.Head), Snapshots: make([]snapshotValue, 0, len(view.Snapshots))}
		if len(view.Head) != 0 {
			cid, err := publication.RecordCID(view.Head)
			if err != nil {
				return mixedReplayView{}, errors.New("mixed replay view head CID is invalid")
			}
			descriptor := encodeBytes(cid)
			result.HeadCID = &descriptor
		}
		var priorRaw []byte
		for _, block := range view.Snapshots {
			if len(block.Raw) == 0 || len(block.Raw) > publication.MaxRecordBytes {
				return mixedReplayView{}, errors.New("mixed replay view record exceeds its bound")
			}
			record, err := publication.DecodeSnapshot(block.Raw)
			if err != nil || record.Vault != state.Binding.Vault {
				return mixedReplayView{}, errors.New("mixed replay view record is invalid")
			}
			cid, err := publication.RecordCID(block.Raw)
			if err != nil {
				return mixedReplayView{}, errors.New("mixed replay view record CID is invalid")
			}
			candidate, exists := candidateForCID[string(cid)]
			key, keyErr := publication.SequenceKey(record.PublicationSeq)
			if !exists || keyErr != nil || key != block.Key || candidate.SnapshotKey != block.Key || !bytes.Equal(candidate.SnapshotRecord, block.Raw) {
				return mixedReplayView{}, errors.New("mixed replay view record does not join to a candidate")
			}
			if len(priorRaw) == 0 {
				if record.PublicationSeq != 0 || len(record.Parent) != 0 {
					return mixedReplayView{}, errors.New("mixed replay view genesis ancestry differs")
				}
			} else if err := publication.VerifySuccessor(priorRaw, block.Raw, block.Key); err != nil {
				return mixedReplayView{}, errors.New("mixed replay view ancestry differs")
			}
			priorRaw = block.Raw
			result.Snapshots = append(result.Snapshots, snapshotValue{Key: block.Key, Raw: encodeBytes(block.Raw)})
		}
		if len(view.Snapshots) == 0 {
			if len(view.Head) != 0 {
				return mixedReplayView{}, errors.New("mixed replay empty view has a head")
			}
		} else if len(view.Head) == 0 || publication.VerifyHeadBinding(view.Head, view.Snapshots[len(view.Snapshots)-1].Raw, view.Snapshots[len(view.Snapshots)-1].Key) != nil {
			return mixedReplayView{}, errors.New("mixed replay view head does not bind its final record")
		}
		return result, nil
	}
	observationFor := func(observation publicationstate.Observation) (mixedReplayObservation, error) {
		if observation.Origin != state.Binding || len(observation.Snapshots) == 0 || len(observation.Snapshots) > 4 {
			return mixedReplayObservation{}, errors.New("mixed replay observation shape differs")
		}
		result := mixedReplayObservation{Origin: bindingValueFor(observation.Origin), SuppliedContext: contextValueFor(observation.SuppliedContext), Head: encodeBytes(observation.Head), Snapshots: make([]snapshotValue, 0, len(observation.Snapshots))}
		if len(observation.Head) != 0 {
			cid, err := publication.RecordCID(observation.Head)
			if err != nil {
				return mixedReplayObservation{}, errors.New("mixed replay observation head CID is invalid")
			}
			descriptor := encodeBytes(cid)
			result.HeadCID = &descriptor
		}
		for _, block := range observation.Snapshots {
			if len(block.Raw) == 0 || len(block.Raw) > publication.MaxRecordBytes {
				return mixedReplayObservation{}, errors.New("mixed replay observation record exceeds its bound")
			}
			record, err := publication.DecodeSnapshot(block.Raw)
			if err != nil || record.Vault != state.Binding.Vault {
				return mixedReplayObservation{}, errors.New("mixed replay observation record is invalid")
			}
			cid, err := publication.RecordCID(block.Raw)
			candidate, exists := candidateForCID[string(cid)]
			key, keyErr := publication.SequenceKey(record.PublicationSeq)
			if err != nil || !exists || keyErr != nil || key != block.Key || candidate.SnapshotKey != block.Key || !bytes.Equal(candidate.SnapshotRecord, block.Raw) {
				return mixedReplayObservation{}, errors.New("mixed replay observation record does not join to a candidate")
			}
			result.Snapshots = append(result.Snapshots, snapshotValue{Key: block.Key, Raw: encodeBytes(block.Raw)})
		}
		if len(observation.Head) == 0 || publication.VerifyHeadBinding(observation.Head, observation.Snapshots[len(observation.Snapshots)-1].Raw, observation.Snapshots[len(observation.Snapshots)-1].Key) != nil {
			return mixedReplayObservation{}, errors.New("mixed replay observation head does not bind its record")
		}
		return result, nil
	}

	views := make([]mixedReplayView, 0, 7)
	for _, view := range viewsForCharge {
		converted, err := viewFor(view)
		if err != nil {
			return zero, err
		}
		views = append(views, converted)
	}
	derivedContext := publicationstate.SuppliedContext{}
	if state.ReplacementFloor.SuppliedContext.Policy != nil {
		return zero, errors.New("mixed replacement floor unexpectedly has a policy")
	}
	derivedContext.RepositoryRevision = state.ReplacementFloor.SuppliedContext.RepositoryRevision
	derivedContext.RepositoryDigest = bytes.Clone(state.ReplacementFloor.SuppliedContext.RepositoryDigest)
	replacementRecordCID, replacementCIDErr := publication.RecordCID(state.ReplacementInput.SnapshotRecord)
	if len(state.ReplacementObservation.Snapshots) != 1 || replacementCIDErr != nil || !reflect.DeepEqual(derivedContext, state.ReplacementObservation.SuppliedContext) || !bytes.Equal(state.ReplacementFloor.Head, state.ReplacementObservation.Head) || state.ReplacementFloor.SnapshotKey != state.ReplacementObservation.Snapshots[0].Key || !bytes.Equal(state.ReplacementFloor.RecordCID, replacementRecordCID) {
		return zero, errors.New("mixed derived replacement predecessor differs from accepted context")
	}
	derivedView := publicationstate.SuppliedRepositoryView{Origin: state.Binding, Scope: publicationstate.ViewScopeWholeRepository, SuppliedContext: derivedContext, Head: bytes.Clone(state.ReplacementObservation.Head), Snapshots: append([]publicationstate.SnapshotBlock(nil), state.ReplacementObservation.Snapshots...)}
	derivedConverted, err := viewFor(derivedView)
	if err != nil {
		return zero, err
	}
	replacementObservation, err := observationFor(state.ReplacementObservation)
	if err != nil {
		return zero, err
	}
	cacheObservation, err := observationFor(state.CacheObservation)
	if err != nil {
		return zero, err
	}

	floorFor := func(value publicationstate.Floor) (mixedReplayFloor, error) {
		sequence, sequenceErr := publication.ParseSequenceKey(value.SnapshotKey)
		if allZero(value.DatabaseID[:]) || value.Revision == 0 || value.Generation == 0 || value.Binding != state.Binding || len(value.AnchorCID) > publication.MaxCIDBytes || len(value.Head) > publication.MaxRecordBytes || len(value.RecordCID) == 0 || len(value.RecordCID) > publication.MaxCIDBytes || len(value.BlobCID) == 0 || len(value.BlobCID) > publication.MaxCIDBytes || value.BlobSize == 0 || value.BlobSize > publication.MaxBlobBytes || value.BlobSize > uint64(maxOutputBytes) || sequenceErr != nil || sequence != value.Sequence {
			return mixedReplayFloor{}, errors.New("mixed replay floor is invalid")
		}
		return mixedReplayFloor{
			DatabaseID: encodeBytes(value.DatabaseID[:]), Revision: value.Revision, Generation: value.Generation, Provenance: string(value.Provenance),
			AnchorCID: encodeBytes(value.AnchorCID), Binding: bindingValueFor(value.Binding), SuppliedContext: contextValueFor(value.SuppliedContext), Head: encodeBytes(value.Head),
			SnapshotKey: value.SnapshotKey, Sequence: value.Sequence, PublicationID: encodeBytes(value.PublicationID[:]), RecordCID: encodeBytes(value.RecordCID),
			BlobCID: encodeBytes(value.BlobCID), BlobSize: value.BlobSize, ObservationDigest: encodeBytes(value.ObservationDigest[:]), AcceptedEventDigest: encodeBytes(value.AcceptedEventDigest[:]),
		}, nil
	}
	optionalFloorFor := func(value *publicationstate.Floor) (*mixedReplayFloor, error) {
		if value == nil {
			return nil, nil
		}
		converted, err := floorFor(*value)
		if err != nil {
			return nil, err
		}
		return &converted, nil
	}
	attemptFor := func(value publicationstate.Attempt) (mixedReplayAttempt, error) {
		sequence, sequenceErr := publication.ParseSequenceKey(value.SnapshotKey)
		if allZero(value.ID[:]) || value.Kind == "" || value.Lifecycle == "" || value.Outcome == "" || value.Sequence > publication.MaxSequence || sequenceErr != nil || sequence != value.Sequence || len(value.SnapshotRecordCID) == 0 || len(value.SnapshotRecordCID) > publication.MaxCIDBytes || len(value.HeadRecordCID) == 0 || len(value.HeadRecordCID) > publication.MaxCIDBytes || len(value.BlobCID) == 0 || len(value.BlobCID) > publication.MaxCIDBytes || value.BlobSize == 0 || value.BlobSize > publication.MaxBlobBytes || value.BlobSize > uint64(maxOutputBytes) {
			return mixedReplayAttempt{}, errors.New("mixed replay attempt is invalid")
		}
		captured, err := optionalFloorFor(value.CapturedFloor)
		if err != nil {
			return mixedReplayAttempt{}, err
		}
		return mixedReplayAttempt{
			ID: encodeBytes(value.ID[:]), Kind: string(value.Kind), Lifecycle: string(value.Lifecycle), Outcome: string(value.Outcome), Blocked: value.Blocked,
			Sequence: value.Sequence, SnapshotKey: value.SnapshotKey, SnapshotRecordCID: encodeBytes(value.SnapshotRecordCID), HeadRecordCID: encodeBytes(value.HeadRecordCID),
			BlobCID: encodeBytes(value.BlobCID), BlobSize: value.BlobSize, CapturedFloor: captured, CapturedRevision: value.CapturedRevision,
			CapturedGeneration: value.CapturedGeneration, MutationRevision: value.MutationRevision, StateDigest: encodeBytes(value.StateDigest[:]), Availability: string(value.Availability),
		}, nil
	}
	resolutionFor := func(value publicationstate.AttemptResolution) (mixedReplayResolution, error) {
		attempt, err := attemptFor(value.Attempt)
		if err != nil {
			return mixedReplayResolution{}, err
		}
		if len(value.Evidence) == 0 || uint64(len(value.Evidence)) > publicationstate.DefaultAttemptLimits().EvidenceSlotBytes {
			return mixedReplayResolution{}, errors.New("mixed replay result evidence exceeds its bound")
		}
		return mixedReplayResolution{Attempt: attempt, Outcome: string(value.Outcome), ViewDigest: encodeBytes(value.ViewDigest[:]), Evidence: encodeBytes(value.Evidence)}, nil
	}
	conflictFor := func(value publicationstate.FirstConflictEvidence) (mixedReplayFirstConflict, error) {
		headSequence, headSequenceErr := publication.ParseSequenceKey(value.HeadKey)
		if allZero(value.AttemptID[:]) || allZero(value.ID[:]) || len(value.Evidence) == 0 || uint64(len(value.Evidence)) > publicationstate.DefaultAttemptLimits().EvidenceSlotBytes || len(value.Head) == 0 || len(value.Head) > publication.MaxRecordBytes || len(value.HeadRecord) == 0 || len(value.HeadRecord) > publication.MaxRecordBytes || headSequenceErr != nil || headSequence != value.HeadSequence {
			return mixedReplayFirstConflict{}, errors.New("mixed replay first-conflict projection is invalid")
		}
		return mixedReplayFirstConflict{AttemptID: encodeBytes(value.AttemptID[:]), ID: encodeBytes(value.ID[:]), Envelope: encodeBytes(value.Evidence), Head: encodeBytes(value.Head), HeadKey: value.HeadKey, HeadRecord: encodeBytes(value.HeadRecord), HeadSequence: value.HeadSequence}, nil
	}
	evidenceFor := func(value publicationstate.AttemptEvidence) (mixedReplayEvidence, error) {
		if allZero(value.AttemptID[:]) || value.Role == "" || len(value.Evidence) == 0 || uint64(len(value.Evidence)) > publicationstate.DefaultAttemptLimits().EvidenceSlotBytes {
			return mixedReplayEvidence{}, errors.New("mixed replay evidence is invalid")
		}
		return mixedReplayEvidence{AttemptID: encodeBytes(value.AttemptID[:]), Role: value.Role, Evidence: encodeBytes(value.Evidence)}, nil
	}
	pageFor := func(value publicationstate.AttemptPage, maxAttempts, maxEvidence int) (mixedReplayAttemptPage, error) {
		if len(value.Attempts) > maxAttempts || len(value.Evidence) > maxEvidence {
			return mixedReplayAttemptPage{}, errors.New("mixed replay page exceeds its projection bound")
		}
		result := mixedReplayAttemptPage{Attempts: make([]mixedReplayAttempt, 0, len(value.Attempts)), Evidence: make([]mixedReplayEvidence, 0, len(value.Evidence)), NextID: encodeBytes(value.NextID[:]), HasMore: value.HasMore}
		seenAttempts := make(map[[16]byte]struct{}, len(value.Attempts))
		for _, item := range value.Attempts {
			if _, exists := seenAttempts[item.ID]; exists {
				return mixedReplayAttemptPage{}, errors.New("mixed replay page attempt is duplicated")
			}
			seenAttempts[item.ID] = struct{}{}
			converted, err := attemptFor(item)
			if err != nil {
				return mixedReplayAttemptPage{}, err
			}
			result.Attempts = append(result.Attempts, converted)
		}
		seenEvidence := make(map[string]struct{}, len(value.Evidence))
		for _, item := range value.Evidence {
			key := string(item.AttemptID[:]) + "\x00" + item.Role
			if _, exists := seenEvidence[key]; exists {
				return mixedReplayAttemptPage{}, errors.New("mixed replay page evidence role is duplicated")
			}
			converted, err := evidenceFor(item)
			if err != nil {
				return mixedReplayAttemptPage{}, err
			}
			seenEvidence[key] = struct{}{}
			result.Evidence = append(result.Evidence, converted)
		}
		return result, nil
	}
	referenceFor := func(value publicationstate.RecordReference) (mixedReplayRecordReference, error) {
		sequence, err := publication.ParseSequenceKey(value.Key)
		if err != nil || sequence != value.Sequence || len(value.CID) == 0 || len(value.CID) > publication.MaxCIDBytes {
			return mixedReplayRecordReference{}, errors.New("mixed replay history reference is invalid")
		}
		return mixedReplayRecordReference{Key: value.Key, CID: encodeBytes(value.CID), Sequence: value.Sequence}, nil
	}
	historyFor := func(value publicationstate.HistoryPage) (mixedReplayHistoryPage, error) {
		if len(value.Events) > 2 || len(value.Records) > 2 {
			return mixedReplayHistoryPage{}, errors.New("mixed replay history page exceeds its projection bound")
		}
		result := mixedReplayHistoryPage{Events: make([]mixedReplayHistoryEvent, 0, len(value.Events)), Records: make([]mixedReplayRecordEvidence, 0, len(value.Records)), NextRevision: value.NextRevision, HasMore: value.HasMore}
		seenRevision := make(map[uint64]struct{}, len(value.Events))
		for _, event := range value.Events {
			if event.Revision == 0 || len(event.Trace) > 4 {
				return mixedReplayHistoryPage{}, errors.New("mixed replay history event is invalid")
			}
			if _, exists := seenRevision[event.Revision]; exists {
				return mixedReplayHistoryPage{}, errors.New("mixed replay history revision is duplicated")
			}
			seenRevision[event.Revision] = struct{}{}
			newFloor, err := floorFor(event.NewFloor)
			if err != nil {
				return mixedReplayHistoryPage{}, err
			}
			oldFloor, err := optionalFloorFor(event.OldFloor)
			if err != nil {
				return mixedReplayHistoryPage{}, err
			}
			trace := make([]mixedReplayRecordReference, 0, len(event.Trace))
			for _, reference := range event.Trace {
				converted, err := referenceFor(reference)
				if err != nil {
					return mixedReplayHistoryPage{}, err
				}
				trace = append(trace, converted)
			}
			result.Events = append(result.Events, mixedReplayHistoryEvent{Revision: event.Revision, Mode: string(event.Mode), Reason: string(event.Reason), Stop: event.Stop, OldFloor: oldFloor, NewFloor: newFloor, Trace: trace, ObservationDigest: encodeBytes(event.ObservationDigest[:]), SuppliedSetDigest: encodeBytes(event.SuppliedSetDigest[:]), EventDigest: encodeBytes(event.EventDigest[:])})
		}
		seenRecord := make(map[string]struct{}, len(value.Records))
		for _, record := range value.Records {
			if len(record.Raw) == 0 || len(record.Raw) > publication.MaxRecordBytes {
				return mixedReplayHistoryPage{}, errors.New("mixed replay history record is invalid")
			}
			reference, err := referenceFor(record.Reference)
			if err != nil {
				return mixedReplayHistoryPage{}, err
			}
			cid, err := publication.RecordCID(record.Raw)
			decodedRecord, decodeErr := publication.DecodeSnapshot(record.Raw)
			if err != nil || decodeErr != nil || !bytes.Equal(cid, record.Reference.CID) || decodedRecord.PublicationSeq != record.Reference.Sequence {
				return mixedReplayHistoryPage{}, errors.New("mixed replay history record reference differs")
			}
			if _, exists := seenRecord[string(record.Reference.CID)]; exists {
				return mixedReplayHistoryPage{}, errors.New("mixed replay history record is duplicated")
			}
			seenRecord[string(record.Reference.CID)] = struct{}{}
			result.Records = append(result.Records, mixedReplayRecordEvidence{Reference: reference, Raw: encodeBytes(record.Raw)})
		}
		return result, nil
	}
	materialFor := func(value publicationstate.CandidateMaterial) (mixedReplayMaterial, error) {
		if allZero(value.AttemptID[:]) || len(value.SnapshotRecord) == 0 || len(value.SnapshotRecord) > publication.MaxRecordBytes || len(value.HeadRecord) == 0 || len(value.HeadRecord) > publication.MaxRecordBytes || len(value.Payload) == 0 || uint64(len(value.Payload)) > publication.MaxBlobBytes || uint64(len(value.Payload)) > uint64(maxOutputBytes) {
			return mixedReplayMaterial{}, errors.New("mixed replay active material exceeds its bound")
		}
		if err := publication.VerifyHeadBinding(value.HeadRecord, value.SnapshotRecord, value.SnapshotKey); err != nil {
			return mixedReplayMaterial{}, errors.New("mixed replay active material head differs")
		}
		record, err := publication.DecodeSnapshot(value.SnapshotRecord)
		if err != nil || record.Blob.Size != uint64(len(value.Payload)) || !bytes.Equal(record.Blob.CID, value.Blob.CID) || value.Blob.Size != record.Blob.Size {
			return mixedReplayMaterial{}, errors.New("mixed replay active material reference differs")
		}
		if _, err := publication.DecodePayload(value.Payload, value.Blob); err != nil {
			return mixedReplayMaterial{}, errors.New("mixed replay active material payload does not decode")
		}
		return mixedReplayMaterial{AttemptID: encodeBytes(value.AttemptID[:]), SnapshotKey: value.SnapshotKey, SnapshotRecord: encodeBytes(value.SnapshotRecord), HeadRecord: encodeBytes(value.HeadRecord), Payload: encodeBytes(value.Payload), BlobCID: encodeBytes(value.Blob.CID), BlobSize: value.Blob.Size}, nil
	}

	genesisID := state.Genesis.Attempt.ID
	oldID := state.RetiredAttempt.ID
	activeID := state.AbsentResolution.Attempt.ID
	if allZero(genesisID[:]) || allZero(oldID[:]) || allZero(activeID[:]) || genesisID == oldID || genesisID == activeID || oldID == activeID || state.Genesis.Floor.Revision != 1 || state.Genesis.Floor.Generation != 1 || state.ReplacementFloor.Revision != 2 || state.ReplacementFloor.Generation != 2 || !reflect.DeepEqual(state.FinalFloor, state.ReplacementFloor) || !reflect.DeepEqual(state.Genesis.Floor.SuppliedContext, state.GenesisCurrentView.SuppliedContext) || !reflect.DeepEqual(state.ReplacementFloor.SuppliedContext, state.ReplacementObservation.SuppliedContext) || !bytes.Equal(state.Genesis.Floor.Head, state.GenesisInput.HeadRecord) || !bytes.Equal(state.ReplacementFloor.Head, state.ReplacementInput.HeadRecord) || state.Genesis.Floor.SnapshotKey != state.GenesisInput.SnapshotKey || state.ReplacementFloor.SnapshotKey != state.ReplacementInput.SnapshotKey || !bytes.Equal(state.PriorLatestEvidence, state.PriorLatest.Evidence) || len(state.PriorLatestEvidence) == 0 || !reflect.DeepEqual(state.FirstConflict, state.FinalFirstConflict) {
		return zero, errors.New("mixed replay retained lifecycle identities differ")
	}
	if state.PriorLatest.Attempt.ID != oldID || state.PriorLatest.Outcome != publicationstate.OutcomeLostFence || state.RetiredAttempt.ID != oldID || state.RetiredAttempt.Lifecycle != publicationstate.AttemptRetiredAbandoned || state.RetiredAttempt.Outcome != publicationstate.OutcomeLostFence || state.AbsentResolution.Attempt.ID != activeID || state.AbsentResolution.Outcome != publicationstate.OutcomeAbsentUnresolved || state.AbsentResolution.Attempt.Lifecycle != publicationstate.AttemptMayHaveSubmitted || state.AbsentResolution.Attempt.Outcome != publicationstate.OutcomeAbsentUnresolved || state.CacheID == ([32]byte{}) {
		return zero, errors.New("mixed replay retained result roles differ")
	}
	if state.FirstConflict.AttemptID != oldID || state.FirstConflict.ID == ([32]byte{}) || len(state.FirstConflict.Evidence) == 0 || state.ActiveMaterial.AttemptID != activeID || state.ActiveMaterial.SnapshotKey != state.ActiveSuccessorInput.SnapshotKey || !bytes.Equal(state.ActiveMaterial.SnapshotRecord, state.ActiveSuccessorInput.SnapshotRecord) || !bytes.Equal(state.ActiveMaterial.HeadRecord, state.ActiveSuccessorInput.HeadRecord) || !bytes.Equal(state.ActiveMaterial.Payload, state.ActiveSuccessorInput.Payload) || state.ActiveMaterial.Blob.Size != uint64(len(state.ActiveSuccessorInput.Payload)) {
		return zero, errors.New("mixed replay conflict or active material joins differ")
	}
	if len(state.RetirementPage.Attempts) != 2 || len(state.RetirementPage.Evidence) != 6 || state.RetirementPage.HasMore || state.RetirementPage.NextID != oldID || len(state.FinalPage.Attempts) != 3 || len(state.FinalPage.Evidence) != 8 || state.FinalPage.HasMore || state.FinalPage.NextID != activeID || len(state.FinalHistory.Events) != 2 || len(state.FinalHistory.Records) != 2 || state.FinalHistory.HasMore || state.FinalHistory.NextRevision != 2 {
		return zero, errors.New("mixed replay retained page shape differs")
	}
	findEvidence := func(page publicationstate.AttemptPage, id [16]byte, role string) ([]byte, bool) {
		var found []byte
		count := 0
		for _, item := range page.Evidence {
			if item.AttemptID == id && item.Role == role {
				found = item.Evidence
				count++
			}
		}
		return found, count == 1
	}
	expectedRoles := func(page publicationstate.AttemptPage, ids [][16]byte) bool {
		want := make(map[string]struct{}, len(ids)*3)
		for _, id := range ids {
			want[string(id[:])+"\x00outcome"] = struct{}{}
			want[string(id[:])+"\x00submission"] = struct{}{}
		}
		if len(ids) >= 2 {
			want[string(ids[1][:])+"\x00first-conflict"] = struct{}{}
			want[string(ids[1][:])+"\x00retirement"] = struct{}{}
		}
		got := make(map[string]struct{}, len(page.Evidence))
		for _, item := range page.Evidence {
			key := string(item.AttemptID[:]) + "\x00" + item.Role
			if _, exists := want[key]; !exists {
				return false
			}
			if _, exists := got[key]; exists {
				return false
			}
			got[key] = struct{}{}
		}
		if len(got) != len(want) {
			return false
		}
		for key := range want {
			if _, exists := got[key]; !exists {
				return false
			}
		}
		return true
	}
	if !expectedRoles(state.RetirementPage, [][16]byte{genesisID, oldID}) || !expectedRoles(state.FinalPage, [][16]byte{genesisID, oldID, activeID}) {
		return zero, errors.New("mixed replay page evidence role inventory differs")
	}
	oldSeq3Outcome, outcomeOK := findEvidence(state.FinalPage, oldID, "outcome")
	oldSeq3Retirement, retirementOK := findEvidence(state.FinalPage, oldID, "retirement")
	activeEvidence, activeEvidenceOK := findEvidence(state.FinalPage, activeID, "outcome")
	if !outcomeOK || !retirementOK || !activeEvidenceOK || !bytes.Equal(oldSeq3Outcome, oldSeq3Retirement) || bytes.Equal(oldSeq3Outcome, state.PriorLatestEvidence) || bytes.Equal(oldSeq3Outcome, state.FirstConflict.Evidence) || !bytes.Equal(activeEvidence, state.AbsentResolution.Evidence) || bytes.Equal(state.FirstConflict.Evidence, state.PriorLatestEvidence) {
		return zero, errors.New("mixed replay proof chronology differs")
	}
	for _, page := range []publicationstate.AttemptPage{state.RetirementPage, state.FinalPage} {
		seen := make(map[[16]byte]struct{}, len(page.Attempts))
		for _, attempt := range page.Attempts {
			if _, exists := seen[attempt.ID]; exists {
				return zero, errors.New("mixed replay page attempt role is duplicated")
			}
			seen[attempt.ID] = struct{}{}
			if attempt.ID != genesisID && attempt.ID != oldID && attempt.ID != activeID {
				return zero, errors.New("mixed replay page has an unexpected attempt")
			}
		}
		for _, expectedID := range [][16]byte{genesisID, oldID, activeID} {
			if expectedID == activeID && len(page.Attempts) == 2 {
				continue
			}
			if _, exists := seen[expectedID]; !exists {
				return zero, errors.New("mixed replay page is missing an attempt")
			}
		}
	}

	attemptsEqualExceptAvailability := func(left, right publicationstate.Attempt) bool {
		return left.ID == right.ID && left.Kind == right.Kind && left.Lifecycle == right.Lifecycle && left.Outcome == right.Outcome && left.Blocked == right.Blocked && left.Sequence == right.Sequence && left.SnapshotKey == right.SnapshotKey && reflect.DeepEqual(left.SnapshotRecordCID, right.SnapshotRecordCID) && reflect.DeepEqual(left.HeadRecordCID, right.HeadRecordCID) && reflect.DeepEqual(left.BlobCID, right.BlobCID) && left.BlobSize == right.BlobSize && reflect.DeepEqual(left.CapturedFloor, right.CapturedFloor) && left.CapturedRevision == right.CapturedRevision && left.CapturedGeneration == right.CapturedGeneration && left.MutationRevision == right.MutationRevision && left.StateDigest == right.StateDigest
	}
	findAttempt := func(page publicationstate.AttemptPage, id [16]byte) (publicationstate.Attempt, bool) {
		var found publicationstate.Attempt
		count := 0
		for _, attempt := range page.Attempts {
			if attempt.ID == id {
				found = attempt
				count++
			}
		}
		return found, count == 1
	}
	for _, retiredItem := range state.RetirementPage.Evidence {
		finalBody, found := findEvidence(state.FinalPage, retiredItem.AttemptID, retiredItem.Role)
		if !found || !bytes.Equal(retiredItem.Evidence, finalBody) {
			return zero, errors.New("mixed replay retirement-page evidence differs from final page")
		}
	}
	retirementFirstConflict, retirementFirstConflictOK := findEvidence(state.RetirementPage, oldID, "first-conflict")
	finalFirstConflict, finalFirstConflictOK := findEvidence(state.FinalPage, oldID, "first-conflict")
	retirementOldOutcome, retirementOldOutcomeOK := findEvidence(state.RetirementPage, oldID, "outcome")
	retirementOldRetirement, retirementOldRetirementOK := findEvidence(state.RetirementPage, oldID, "retirement")
	if !retirementFirstConflictOK || !finalFirstConflictOK || !retirementOldOutcomeOK || !retirementOldRetirementOK || !bytes.Equal(retirementFirstConflict, state.FirstConflict.Evidence) || !bytes.Equal(retirementFirstConflict, state.FinalFirstConflict.Evidence) || !bytes.Equal(finalFirstConflict, state.FinalFirstConflict.Evidence) || !bytes.Equal(finalFirstConflict, state.FirstConflict.Evidence) || !bytes.Equal(retirementOldOutcome, retirementOldRetirement) || !bytes.Equal(retirementOldOutcome, oldSeq3Outcome) || bytes.Equal(retirementOldOutcome, state.PriorLatestEvidence) || bytes.Equal(retirementOldOutcome, state.FirstConflict.Evidence) {
		return zero, errors.New("mixed replay retirement-page proof chronology differs")
	}
	genesisRetirement, hasGenesisRetirement := findAttempt(state.RetirementPage, genesisID)
	genesisFinal, hasGenesisFinal := findAttempt(state.FinalPage, genesisID)
	retiredRetirement, hasRetiredRetirement := findAttempt(state.RetirementPage, oldID)
	retiredFinal, hasRetiredFinal := findAttempt(state.FinalPage, oldID)
	activeFinal, hasActiveFinal := findAttempt(state.FinalPage, activeID)
	if !hasGenesisRetirement || !hasGenesisFinal || !hasRetiredRetirement || !hasRetiredFinal || !hasActiveFinal || !attemptsEqualExceptAvailability(state.Genesis.Attempt, genesisRetirement) || !attemptsEqualExceptAvailability(state.Genesis.Attempt, genesisFinal) || !attemptsEqualExceptAvailability(state.RetiredAttempt, retiredRetirement) || !attemptsEqualExceptAvailability(state.RetiredAttempt, retiredFinal) || !attemptsEqualExceptAvailability(genesisRetirement, genesisFinal) || !attemptsEqualExceptAvailability(retiredRetirement, retiredFinal) || !attemptsEqualExceptAvailability(state.AbsentResolution.Attempt, activeFinal) {
		return zero, errors.New("mixed replay retained attempt projections differ")
	}
	if state.Genesis.Attempt.Availability != publicationstate.AvailabilityAvailable || state.RetiredAttempt.Availability != publicationstate.AvailabilityUnchecked || state.PriorLatest.Attempt.Availability != publicationstate.AvailabilityUnchecked || state.AbsentResolution.Attempt.Availability != publicationstate.AvailabilityUnchecked {
		return zero, errors.New("mixed replay retained result availability differs from API source")
	}
	for _, page := range []publicationstate.AttemptPage{state.RetirementPage, state.FinalPage} {
		for _, attempt := range page.Attempts {
			if attempt.Availability != publicationstate.AvailabilityUnchecked {
				return zero, errors.New("mixed replay page availability differs from API source")
			}
		}
	}

	convertedGenesisAttempt, err := attemptFor(state.Genesis.Attempt)
	if err != nil {
		return zero, err
	}
	convertedGenesisFloor, err := floorFor(state.Genesis.Floor)
	if err != nil {
		return zero, err
	}
	convertedPrior, err := resolutionFor(state.PriorLatest)
	if err != nil {
		return zero, err
	}
	convertedConflict, err := conflictFor(state.FirstConflict)
	if err != nil {
		return zero, err
	}
	convertedReplacementFloor, err := floorFor(state.ReplacementFloor)
	if err != nil {
		return zero, err
	}
	convertedRetired, err := attemptFor(state.RetiredAttempt)
	if err != nil {
		return zero, err
	}
	convertedRetirementPage, err := pageFor(state.RetirementPage, 2, 6)
	if err != nil {
		return zero, err
	}
	convertedFinalFloor, err := floorFor(state.FinalFloor)
	if err != nil {
		return zero, err
	}
	convertedAbsent, err := resolutionFor(state.AbsentResolution)
	if err != nil {
		return zero, err
	}
	convertedMaterial, err := materialFor(state.ActiveMaterial)
	if err != nil {
		return zero, err
	}
	convertedFinalPage, err := pageFor(state.FinalPage, 3, 8)
	if err != nil {
		return zero, err
	}
	convertedHistory, err := historyFor(state.FinalHistory)
	if err != nil {
		return zero, err
	}
	convertedFinalConflict, err := conflictFor(state.FinalFirstConflict)
	if err != nil {
		return zero, err
	}
	result := mixedReplayInputs{
		FormatVersion: 1, Coverage: "mixed-lifecycle", ResultCoverage: "retained-public-results-not-all-call-results", APISequenceKind: "source-order-not-runtime-transcript",
		Binding: bindingValueFor(state.Binding), Options: optionsFor(options),
		Review:       reviewValue{SelectionDigest: hex.EncodeToString(state.Review.SelectionDigest[:]), SelectionRevision: state.Review.SelectionRevision, ApprovalDigest: hex.EncodeToString(state.Review.ApprovalDigest[:]), ApprovalRevision: state.Review.ApprovalRevision},
		Candidates:   mixedReplayCandidates{Genesis: candidates[0], OwnSuccessor: candidates[1], CompetingOccupant: candidates[2], CompetingExtension: candidates[3], Replacement: candidates[4], RetirementExtension: candidates[5], ActiveSuccessor: candidates[6]},
		Views:        mixedReplayViews{EmptyGenesis: views[0], GenesisCurrent: views[1], Predecessor: views[2], FirstConflict: views[3], Extended: views[4], Retirement: views[5], Absence: views[6], DerivedReplacementPredecessor: derivedConverted},
		Observations: mixedReplayObservations{Replacement: replacementObservation, Cache: cacheObservation},
		Results: mixedReplayResults{
			Genesis: mixedReplayFinalization{Attempt: convertedGenesisAttempt, Floor: convertedGenesisFloor}, PriorLatest: convertedPrior, PriorLatestEvidence: encodeBytes(state.PriorLatestEvidence), FirstConflict: convertedConflict,
			ReplacementFloor: convertedReplacementFloor, RetiredAttempt: convertedRetired, RetirementPage: convertedRetirementPage, FinalFloor: convertedFinalFloor,
			AbsentResolution: convertedAbsent, CacheID: encodeBytes(state.CacheID[:]), ActiveMaterial: convertedMaterial, FinalPage: convertedFinalPage, FinalHistory: convertedHistory, FinalFirstConflict: convertedFinalConflict,
		},
		APISequence: []string{
			"Load(genesis initial)", "ActiveAttempt(genesis initial)", "History(genesis initial)", "AttemptHistory(genesis initial)",
			"Prepare(FirstUse, GenesisCurrent-as-Observation, Genesis.payload)", "PrepareAttempt(Genesis, EmptyGenesis, Review)", "CreateAttempt(Genesis fresh proposal)",
			"PrepareDispatch(upload, EmptyGenesis)", "BeginUpload(Genesis fresh upload proposal)", "LoadAttempt(Genesis)", "PrepareDispatch(submission, EmptyGenesis)", "BeginSubmission(Genesis fresh submission proposal)", "LoadAttempt(Genesis)",
			"ResolveAttempt(GenesisCurrent, loaded StateDigest)", "FinalizeAttempt(GenesisCurrent, resolution StateDigest)", "Load(genesis finalized)", "History(genesis finalized)", "LoadAttempt(Genesis)", "AttemptHistory(genesis finalized)", "ActiveAttempt(genesis finalized)", "ReadCandidate(Genesis)", "ReadAcceptedMaterial(Genesis floor)",
			"Load(old successor preparation)", "LoadAttempt(Genesis)", "History(old successor preparation)", "ActiveAttempt(old successor preparation)", "AttemptHistory(old successor preparation)", "ReadAcceptedMaterial(Genesis floor)", "ReadCandidate(Genesis)", "PrepareAttempt(OwnSuccessor, Predecessor, Review)", "CreateAttempt(OwnSuccessor)",
			"PrepareDispatch(upload, Predecessor)", "BeginUpload(OwnSuccessor fresh upload proposal)", "LoadAttempt(OwnSuccessor)", "PrepareDispatch(submission, Predecessor)", "BeginSubmission(OwnSuccessor fresh submission proposal)", "LoadAttempt(OwnSuccessor)", "ResolveAttempt(FirstConflict)", "ReadFirstConflict(OwnSuccessor)", "LoadAttempt(OwnSuccessor)",
			"ResolveAttempt(Extended, refreshed StateDigest)", "ReadFirstConflict(OwnSuccessor)", "LoadAttempt(OwnSuccessor)", "ActiveAttempt(old successor extended)", "AttemptHistory(old successor extended)", "ReadCandidate(OwnSuccessor)", "Load(old successor extended)", "History(old successor extended)", "ReadAcceptedMaterial(Genesis floor)",
			"Load(replacement before fork)", "History(replacement before fork)", "LoadAttempt(Genesis)", "ReadCandidate(Genesis)", "ReadAcceptedMaterial(Genesis floor)", "LoadAttempt(OwnSuccessor)", "ActiveAttempt(replacement before fork)", "AttemptHistory(replacement before fork)", "ReadFirstConflict(OwnSuccessor)", "ReadCandidate(OwnSuccessor)",
			"Prepare(ReplaceFloor, Replacement observation and payload)", "Accept(replacement proposal and confirmation)", "Load(replacement accepted)", "History(replacement accepted)", "LoadAttempt(OwnSuccessor)", "ActiveAttempt(replacement accepted)", "AttemptHistory(replacement accepted)", "ReadFirstConflict(OwnSuccessor)", "ReadCandidate(OwnSuccessor)",
			"PrepareAbandon(OwnSuccessor, Retirement view)", "AbandonAttempt(OwnSuccessor fresh abandon proposal)", "LoadAttempt(OwnSuccessor)", "ActiveAttempt(after abandonment)", "AttemptHistory(after abandonment)", "ReadFirstConflict(OwnSuccessor)", "Load(after abandonment)", "History(after abandonment)", "ReadCandidate(Genesis)", "ReadCandidate(OwnSuccessor, checked candidate_missing refusal)", "ReadAcceptedMaterial(replacement floor, checked material_not_retained refusal)",
			"Load(active successor preparation)", "History(active successor preparation)", "AttemptHistory(active successor preparation)", "LoadAttempt(Genesis)", "LoadAttempt(OwnSuccessor)", "ActiveAttempt(active successor preparation)", "ReadFirstConflict(OwnSuccessor)", "ReadCandidate(Genesis)", "ReadCandidate(OwnSuccessor, checked candidate_missing refusal)", "ReadAcceptedMaterial(replacement floor, checked material_not_retained refusal)",
			"PrepareAttempt(ActiveSuccessor, DerivedReplacementPredecessor, Review)", "CreateAttempt(ActiveSuccessor)", "PrepareDispatch(upload, DerivedReplacementPredecessor)", "BeginUpload(ActiveSuccessor fresh upload proposal)", "LoadAttempt(ActiveSuccessor)", "PrepareDispatch(submission, DerivedReplacementPredecessor)", "BeginSubmission(ActiveSuccessor fresh submission proposal)", "LoadAttempt(ActiveSuccessor)", "AttemptHistory(active submitted)", "ResolveAttempt(Absence, loaded StateDigest)", "LoadAttempt(ActiveSuccessor)", "ActiveAttempt(active absent-unresolved)", "ReadCandidate(ActiveSuccessor)", "AttemptHistory(active absent-unresolved)", "ReadFirstConflict(OwnSuccessor)", "Load(active absent-unresolved)", "History(active absent-unresolved)", "ReadCandidate(Genesis)", "ReadCandidate(OwnSuccessor, checked candidate_missing refusal)", "ReadAcceptedMaterial(replacement floor, checked material_not_retained refusal)",
			"RecordObservation(Cache)", "Load(cache first observation)", "History(cache first observation)", "AttemptHistory(cache first observation)", "ActiveAttempt(cache first observation)", "ReadCandidate(ActiveSuccessor)", "ReadFirstConflict(OwnSuccessor)",
			"RecordObservation(identical Cache)", "Load(cache repeated observation)", "History(cache repeated observation)", "AttemptHistory(cache repeated observation)", "ActiveAttempt(cache repeated observation)", "ReadCandidate(ActiveSuccessor)", "ReadFirstConflict(OwnSuccessor)", "ReadCandidate(Genesis)", "ReadCandidate(OwnSuccessor, checked candidate_missing refusal)", "ReadAcceptedMaterial(replacement floor, checked material_not_retained refusal)",
		},
	}
	encoded, err := marshalJSON(result)
	if err != nil {
		return zero, errors.New("mixed replay DTO exceeds its final serialized bound")
	}
	_ = encoded
	return result, nil
}
