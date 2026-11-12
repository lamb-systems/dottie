package publicationstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	incomingMaterialUpgradeFixtureRoot = "testdata/attempts-v2"
	incomingMaterialUpgradeFixtureDID  = "did:plc:abcdefghijklmnopqrstuvwx"
)

type incomingMaterialUpgradeFixtureSpec struct {
	relative string
	length   int64
	sha256   string
}

var incomingMaterialUpgradeFixtureSpecs = []incomingMaterialUpgradeFixtureSpec{
	{"manifest.json", 28705, "8a2691b039967fc2d980413bc7204b883199ac7853a5cfbb414bb6dd4a665103"},
	{"mixed-inputs.json", 195211, "b71f799e7f61408aa189e9a230fa9e4809b10c1f692dd67d702e540cfcfc32a6"},
	{"mixed-rows.json", 103211, "ed33147af1d8fec48d17e4006bb668fbd74d92698a605e974f21bf78e6367431"},
	{"mixed/payloads/30f2aa3a007e288f7be544ec498a8af23c00da7b97222e550e3d18ee7cd105be.payload", 3072, "30f2aa3a007e288f7be544ec498a8af23c00da7b97222e550e3d18ee7cd105be"},
	{"mixed/payloads/b18a43634e93d947bc5ac352d6332aca3036f921e21087a5ee1a4acdab9b72bb.payload", 3072, "b18a43634e93d947bc5ac352d6332aca3036f921e21087a5ee1a4acdab9b72bb"},
	{"mixed/payloads/dfaa8ec95e4c6ac302aa5baa54ceadb96a5610a34b4d121d8ddc0fc976457fdc.payload", 3072, "dfaa8ec95e4c6ac302aa5baa54ceadb96a5610a34b4d121d8ddc0fc976457fdc"},
	{"mixed/publication.db", 200704, "e956014827b1ec6bcb3b43ed4f425a29383ad0f14f20352de05c5a4a054a0939"},
	{"mixed/publication.db.lock", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	{"pending-genesis-inputs.json", 8739, "0fcacb20644ac01b8232c6235dd8dc5c576ac5c3ca773e56b4edc120d575d4ed"},
	{"pending-genesis-rows.json", 24589, "5061a24e521f27923557ada45ae7654919ee42c52ce6861581823c0f372dd857"},
	{"pending-genesis/payloads/f947699472cc0bb633cf07c9123d6e0c768d498a1853cf83afd43428803f3eea.payload", 3072, "f947699472cc0bb633cf07c9123d6e0c768d498a1853cf83afd43428803f3eea"},
	{"pending-genesis/publication.db", 139264, "d2e446ca0e728ac4af1835c2d4e65c4809fb17f19ef9729f0cc305b87b45f108"},
	{"pending-genesis/publication.db.lock", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
}

var incomingMaterialUpgradeFixtureDirectories = []string{
	"mixed",
	"mixed/payloads",
	"pending-genesis",
	"pending-genesis/payloads",
}

var incomingMaterialUpgradeFixturePayloadPaths = []string{
	"mixed/payloads/30f2aa3a007e288f7be544ec498a8af23c00da7b97222e550e3d18ee7cd105be.payload",
	"mixed/payloads/b18a43634e93d947bc5ac352d6332aca3036f921e21087a5ee1a4acdab9b72bb.payload",
	"mixed/payloads/dfaa8ec95e4c6ac302aa5baa54ceadb96a5610a34b4d121d8ddc0fc976457fdc.payload",
	"pending-genesis/payloads/f947699472cc0bb633cf07c9123d6e0c768d498a1853cf83afd43428803f3eea.payload",
}

var incomingMaterialUpgradeFixtureTableNames = []string{
	"store_meta",
	"cache_records",
	"cache_observations",
	"accepted_records",
	"accepted_events",
	"active_floor",
	"publication_attempts",
	"active_publication_attempt",
	"pending_genesis",
	"attempt_events",
	"attempt_evidence",
	"payload_objects",
	"attempt_payload_refs",
	"retained_publications",
	"attempt_reservations",
}

var incomingMaterialUpgradeFixtureTableKeys = map[string][]string{
	"store_meta":                 {"key"},
	"cache_records":              {"cid"},
	"cache_observations":         {"observation_id"},
	"accepted_records":           {"cid"},
	"accepted_events":            {"revision"},
	"active_floor":               {"singleton"},
	"publication_attempts":       {"attempt_id"},
	"active_publication_attempt": {"singleton"},
	"pending_genesis":            {"singleton"},
	"attempt_events":             {"attempt_id", "ordinal"},
	"attempt_evidence":           {"attempt_id", "role"},
	"payload_objects":            {"blob_cid"},
	"attempt_payload_refs":       {"attempt_id"},
	"retained_publications":      {"record_cid"},
	"attempt_reservations":       {"attempt_id"},
}

var incomingMaterialUpgradeFixtureAttemptTables = []string{
	"publication_attempts",
	"active_publication_attempt",
	"pending_genesis",
	"attempt_events",
	"attempt_evidence",
	"payload_objects",
	"attempt_payload_refs",
	"retained_publications",
	"attempt_reservations",
}

var incomingMaterialUpgradeFixtureAttemptIndexes = []string{
	"publication_attempts_order",
	"payload_objects_basename",
}

type incomingMaterialUpgradeFixtureDigest struct {
	Length int64  `json:"length"`
	Base64 string `json:"base64"`
	SHA256 string `json:"sha256"`
}

type incomingMaterialUpgradeFixtureObject struct {
	kind string
	sql  string
}

type incomingMaterialUpgradeFixtureSchemaCounts struct {
	tables       int
	namedIndexes int
	autoIndexes  int
}

type incomingMaterialUpgradeFixturePayload struct {
	bytes  []byte
	size   int64
	mode   uint32
	uid    uint32
	nlink  uint64
	sha256 string
}

type incomingMaterialUpgradeFixtureCell struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type incomingMaterialUpgradeFixtureCompanionColumn struct {
	Name         string `json:"name"`
	DeclaredType string `json:"declaredType"`
}

type incomingMaterialUpgradeFixtureCompanionObject struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	SQL  string `json:"sql"`
}

type incomingMaterialUpgradeFixtureCompanionTable struct {
	Name     string                                          `json:"name"`
	DDL      string                                          `json:"ddl"`
	Columns  []incomingMaterialUpgradeFixtureCompanionColumn `json:"columns"`
	RowCount int                                             `json:"rowCount"`
	Rows     [][]incomingMaterialUpgradeFixtureCell          `json:"rows"`
}

type incomingMaterialUpgradeFixtureCompanion struct {
	FormatVersion int                                             `json:"formatVersion"`
	Coverage      string                                          `json:"coverage"`
	ApplicationID int                                             `json:"applicationId"`
	UserVersion   int                                             `json:"userVersion"`
	MetadataKeys  []string                                        `json:"metadataKeys"`
	SchemaObjects []incomingMaterialUpgradeFixtureCompanionObject `json:"schemaObjects"`
	Tables        []incomingMaterialUpgradeFixtureCompanionTable  `json:"tables"`
}

type incomingMaterialUpgradeFixtureManifestAttempt struct {
	ID               incomingMaterialUpgradeFixtureDigest `json:"id"`
	Kind             string                               `json:"kind"`
	Lifecycle        string                               `json:"lifecycle"`
	Outcome          string                               `json:"outcome"`
	Blocked          string                               `json:"blocked"`
	MutationRevision int64                                `json:"mutationRevision"`
}

type incomingMaterialUpgradeFixtureManifestPayload struct {
	Role             string                               `json:"role"`
	Path             string                               `json:"path"`
	AttemptID        string                               `json:"attemptID"`
	Owner            string                               `json:"owner"`
	AcceptedRevision *int64                               `json:"acceptedRevision"`
	BlobCID          incomingMaterialUpgradeFixtureDigest `json:"blobCID"`
	Length           int64                                `json:"length"`
	SHA256           string                               `json:"sha256"`
}

type incomingMaterialUpgradeFixtureManifestImage struct {
	Name                    string                                          `json:"name"`
	SchemaVersion           int                                             `json:"schemaVersion"`
	ApplicationID           int                                             `json:"applicationId"`
	DatabaseID              string                                          `json:"databaseID"`
	Binding                 incomingMaterialUpgradeFixtureManifestBinding   `json:"binding"`
	Options                 incomingMaterialUpgradeFixtureManifestOptions   `json:"options"`
	Revision                uint64                                          `json:"revision"`
	Generation              uint64                                          `json:"generation"`
	AttemptMutationRevision uint64                                          `json:"attemptMutationRevision"`
	AcceptedFloorPresent    bool                                            `json:"acceptedFloorPresent"`
	AcceptedEventCount      int64                                           `json:"acceptedEventCount"`
	ActiveAttemptID         string                                          `json:"activeAttemptID"`
	PendingGenesisAttemptID string                                          `json:"pendingGenesisAttemptID"`
	Attempts                []incomingMaterialUpgradeFixtureManifestAttempt `json:"attempts"`
	Payloads                []incomingMaterialUpgradeFixtureManifestPayload `json:"payloads"`
}

type incomingMaterialUpgradeFixtureManifestBinding struct {
	AccountDID string                               `json:"accountDID"`
	Backend    string                               `json:"backend"`
	Repository string                               `json:"repository"`
	Vault      incomingMaterialUpgradeFixtureDigest `json:"vault"`
}

type incomingMaterialUpgradeFixtureManifestOptions struct {
	PositionLimits Limits        `json:"positionLimits"`
	AttemptLimits  AttemptLimits `json:"attemptLimits"`
}

type incomingMaterialUpgradeFixtureManifest struct {
	FormatVersion int                                           `json:"formatVersion"`
	Images        []incomingMaterialUpgradeFixtureManifestImage `json:"images"`
}

type incomingMaterialUpgradeFixtureConflict struct {
	AttemptID    incomingMaterialUpgradeFixtureDigest `json:"attemptID"`
	ID           incomingMaterialUpgradeFixtureDigest `json:"id"`
	Envelope     incomingMaterialUpgradeFixtureDigest `json:"envelope"`
	Head         incomingMaterialUpgradeFixtureDigest `json:"head"`
	HeadKey      string                               `json:"headKey"`
	HeadRecord   incomingMaterialUpgradeFixtureDigest `json:"headRecord"`
	HeadSequence int64                                `json:"headSequence"`
}

type incomingMaterialUpgradeFixtureInputs struct {
	Results struct {
		FirstConflict      incomingMaterialUpgradeFixtureConflict `json:"firstConflict"`
		FinalFirstConflict incomingMaterialUpgradeFixtureConflict `json:"finalFirstConflict"`
		PriorLatest        struct {
			Outcome    string                               `json:"outcome"`
			ViewDigest incomingMaterialUpgradeFixtureDigest `json:"viewDigest"`
			Evidence   incomingMaterialUpgradeFixtureDigest `json:"evidence"`
			Attempt    struct {
				ID        incomingMaterialUpgradeFixtureDigest `json:"id"`
				Lifecycle string                               `json:"lifecycle"`
			} `json:"attempt"`
		} `json:"priorLatest"`
		PriorLatestEvidence incomingMaterialUpgradeFixtureDigest `json:"priorLatestEvidence"`
		RetiredAttempt      struct {
			Lifecycle        string `json:"lifecycle"`
			Outcome          string `json:"outcome"`
			Blocked          string `json:"blocked"`
			MutationRevision int64  `json:"mutationRevision"`
		} `json:"retiredAttempt"`
		FinalFloor struct {
			Revision   uint64 `json:"revision"`
			Generation uint64 `json:"generation"`
			Provenance string `json:"provenance"`
		} `json:"finalFloor"`
	} `json:"results"`
	Views struct {
		Extended struct {
			Head incomingMaterialUpgradeFixtureDigest `json:"head"`
		} `json:"extended"`
		Retirement struct {
			Head incomingMaterialUpgradeFixtureDigest `json:"head"`
		} `json:"retirement"`
	} `json:"views"`
}

type incomingMaterialUpgradeFixtureAssets struct {
	root     string
	files    map[string][]byte
	manifest incomingMaterialUpgradeFixtureManifest
}

func TestIncomingMaterialUpgradeGenuineFixtures(t *testing.T) {
	fixture := incomingMaterialUpgradeFixtureCopy(t)
	t.Run("positions v1", incomingMaterialUpgradeFixturePositionsV1)
	t.Run("pending genesis", func(t *testing.T) {
		incomingMaterialUpgradeFixturePendingGenesis(t, fixture)
	})
	t.Run("mixed", func(t *testing.T) {
		incomingMaterialUpgradeFixtureMixed(t, fixture)
	})
}

func incomingMaterialUpgradeFixturePositionsV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	f, databasePath, companionRows := incomingMaterialUpgradeCopyV1(t)
	conn, closeOwned := incomingMaterialUpgradeFixtureOpenStore(t, ctx, databasePath)
	require.Equal(t, 1, incomingMaterialUpgradeUserVersion(t, ctx, conn))
	require.NoError(t, checkSchemaVersion(ctx, conn, 1))
	require.Equal(t, companionRows, readLogicalRows(t, conn))
	before := incomingMaterialUpgradeV1Rows(t, ctx, conn)
	require.Len(t, before["store_meta"], 5)
	require.Len(t, before["cache_records"], 3)
	require.Len(t, before["cache_observations"], 1)
	require.Len(t, before["accepted_records"], 2)
	require.Len(t, before["accepted_events"], 2)
	require.Len(t, before["active_floor"], 1)
	beforeMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, conn)
	require.Len(t, beforeMetadata, 5)
	baselineMetadata := schema1Metadata(t, companionRows["store_meta"])
	expectedDatabaseID, err := base64.StdEncoding.DecodeString(baselineMetadata["database_id"])
	require.NoError(t, err)
	require.Len(t, expectedDatabaseID, 32)
	require.Equal(t, expectedDatabaseID, beforeMetadata["database_id"])
	require.Equal(t, uint64Bytes(2), beforeMetadata["revision"])
	require.Equal(t, uint64Bytes(1), beforeMetadata["generation"])
	var databaseID [32]byte
	copy(databaseID[:], expectedDatabaseID)
	floorValue := incomingMaterialUpgradeFixtureScanValue(t, ctx, conn, "SELECT floor FROM active_floor WHERE singleton=1")
	floorRaw, ok := floorValue.([]byte)
	require.True(t, ok)
	floor, err := decodeFloor(floorRaw)
	require.NoError(t, err)
	require.Equal(t, uint64(2), floor.Revision)
	require.Equal(t, uint64(1), floor.Generation)
	require.Equal(t, uint64(1), floor.Sequence)
	require.Equal(t, databaseID, floor.DatabaseID)
	require.NoError(t, validatePersistedFloor(floor, f.binding, databaseID, DefaultLimits()))

	payloadPath := filepath.Join(filepath.Dir(databasePath), "schema1-baseline-payload.bin")
	payloadBefore := incomingMaterialUpgradeFixturePayloadState(t, payloadPath)
	require.Equal(t, payloadBefore.bytes, f.payload)
	payloadCID, err := publication.RawPayloadCID(payloadBefore.bytes)
	require.NoError(t, err)
	payloadReference := publication.BlobReference{CID: payloadCID, Size: uint64(len(payloadBefore.bytes))}
	require.NoError(t, publication.VerifyPayload(payloadBefore.bytes, payloadReference))
	_, err = publication.DecodePayload(payloadBefore.bytes, payloadReference)
	require.NoError(t, err)

	sourceObjects := incomingMaterialUpgradeFixtureObjects(t, ctx, conn)
	sourceCounts := incomingMaterialUpgradeFixtureObjectCounts(t, sourceObjects)
	require.Equal(t, 6, sourceCounts.tables)
	require.Equal(t, 0, sourceCounts.namedIndexes)
	require.Equal(t, 4, sourceCounts.autoIndexes)
	require.Len(t, sourceObjects, 10)

	source, err := readIncomingMaterialUpgradeSource(ctx, conn, 1, f.binding, DefaultLimits(), DefaultAttemptLimits())
	require.NoError(t, err)
	tx := incomingMaterialUpgradeTx(t, ctx, conn)
	var points []int
	require.NoError(t, migrateIncomingMaterialTx(ctx, tx, source, func(point int) error {
		points = append(points, point)
		return nil
	}))
	require.Equal(t, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, points)
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, tx))
	afterMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, tx)
	require.Len(t, afterMetadata, 7)
	for _, key := range []string{"binding", "database_id", "generation", "limits", "revision"} {
		assert.Equal(t, beforeMetadata[key], afterMetadata[key], key)
	}
	wantedAttemptLimits, err := encodeAttemptLimits(DefaultAttemptLimits())
	require.NoError(t, err)
	assert.Equal(t, wantedAttemptLimits, afterMetadata["attempt_limits"])
	assert.Equal(t, uint64Bytes(0), afterMetadata["attempt_mutation_revision"])
	after := incomingMaterialUpgradeV1Rows(t, ctx, tx)
	require.Len(t, after["store_meta"], 7)
	for _, table := range []string{"cache_records", "cache_observations", "accepted_records", "accepted_events", "active_floor"} {
		assert.Equal(t, before[table], after[table], table)
	}
	for _, table := range incomingMaterialUpgradeFixtureAttemptTables {
		require.Zero(t, incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM "+table), table)
	}
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
	destinationObjects := incomingMaterialUpgradeFixtureObjects(t, ctx, tx)
	destinationCounts := incomingMaterialUpgradeFixtureObjectCounts(t, destinationObjects)
	require.Equal(t, 16, destinationCounts.tables)
	require.Equal(t, 2, destinationCounts.namedIndexes)
	require.Equal(t, 14, destinationCounts.autoIndexes)
	require.Len(t, destinationObjects, 32)
	for _, statement := range attemptSchemaStatements {
		require.Equal(t, statement, destinationObjects[statementTableName(statement)].sql, statementTableName(statement))
	}
	require.Equal(t, incomingMaterialSchemaStatement, destinationObjects["accepted_material_refs"].sql)
	namedAdditions, autoIndexAdditions := incomingMaterialUpgradeFixtureObjectAdditions(t, sourceObjects, destinationObjects)
	expectedAdditions := append([]string{"accepted_material_refs"}, incomingMaterialUpgradeFixtureAttemptTables...)
	expectedAdditions = append(expectedAdditions, incomingMaterialUpgradeFixtureAttemptIndexes...)
	sort.Strings(expectedAdditions)
	require.Equal(t, expectedAdditions, namedAdditions)
	require.Equal(t, 10, autoIndexAdditions)
	require.NoError(t, checkIncomingMaterialUpgradeSchema(ctx, tx))
	require.NoError(t, checkIncomingMaterialUpgradeDestination(ctx, tx, source))
	require.Equal(t, payloadBefore, incomingMaterialUpgradeFixturePayloadState(t, payloadPath))
	require.NoError(t, tx.Rollback())
	require.Equal(t, 1, incomingMaterialUpgradeUserVersion(t, ctx, conn))
	require.NoError(t, checkSchemaVersion(ctx, conn, 1))
	assert.Equal(t, before, incomingMaterialUpgradeV1Rows(t, ctx, conn))
	require.Equal(t, companionRows, readLogicalRows(t, conn))
	assert.Equal(t, beforeMetadata, incomingMaterialUpgradeStoredMetadata(t, ctx, conn))
	assert.Equal(t, sourceObjects, incomingMaterialUpgradeFixtureObjects(t, ctx, conn))
	require.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, conn))
	assert.Equal(t, payloadBefore, incomingMaterialUpgradeFixturePayloadState(t, payloadPath))

	closeOwned(t)
	require.Equal(t, payloadBefore, incomingMaterialUpgradeFixturePayloadState(t, payloadPath))
	readOnly, closeReadOnly := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, databasePath)
	require.Equal(t, 1, incomingMaterialUpgradeUserVersion(t, ctx, readOnly))
	require.NoError(t, checkSchemaVersion(ctx, readOnly, 1))
	assert.Equal(t, before, incomingMaterialUpgradeV1Rows(t, ctx, readOnly))
	assert.Equal(t, sourceObjects, incomingMaterialUpgradeFixtureObjects(t, ctx, readOnly))
	require.Equal(t, companionRows, readLogicalRows(t, readOnly))
	closeReadOnly(t)
	require.Equal(t, payloadBefore, incomingMaterialUpgradeFixturePayloadState(t, payloadPath))
}

func incomingMaterialUpgradeFixturePendingGenesis(t *testing.T, fixture incomingMaterialUpgradeFixtureAssets) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	image := fixture.manifest.requireImage(t, "pending-genesis")
	binding, limits, attemptLimits := incomingMaterialUpgradeFixtureBindingOptions(t, image)
	databasePath := filepath.Join(fixture.root, "pending-genesis", "publication.db")
	conn, closeOwned := incomingMaterialUpgradeFixtureOpenStore(t, ctx, databasePath)
	require.Equal(t, 2, incomingMaterialUpgradeUserVersion(t, ctx, conn))
	require.NoError(t, checkSchemaVersion(ctx, conn, 2))
	source, err := readIncomingMaterialUpgradeSource(ctx, conn, 2, binding, limits, attemptLimits)
	require.NoError(t, err)
	require.Equal(t, binding, source.binding)
	require.Equal(t, limits, source.limits)
	require.Equal(t, attemptLimits, source.attemptLimits)
	require.Equal(t, incomingMaterialUpgradeFixtureHex(t, image.DatabaseID), source.metadata["database_id"])
	require.Equal(t, uint64Bytes(0), source.metadata["revision"])
	require.Equal(t, uint64Bytes(0), source.metadata["generation"])
	require.Equal(t, uint64Bytes(1), source.metadata["attempt_mutation_revision"])
	wantedBinding, err := encodeBinding(binding)
	require.NoError(t, err)
	assert.Equal(t, wantedBinding, source.metadata["binding"])
	wantedAttemptLimits, err := encodeAttemptLimits(attemptLimits)
	require.NoError(t, err)
	assert.Equal(t, wantedAttemptLimits, source.metadata["attempt_limits"])

	companion := incomingMaterialUpgradeFixtureCompanionData(t, fixture.files["pending-genesis-rows.json"])
	incomingMaterialUpgradeFixtureRequireCompanionHeader(t, ctx, conn, companion)
	before := incomingMaterialUpgradeFixtureRequireCompanionTables(t, ctx, conn, companion)
	require.Equal(t, 14, incomingMaterialUpgradeFixtureRowTotal(before))

	attemptID := incomingMaterialUpgradeFixtureHex(t, image.ActiveAttemptID)
	require.Equal(t, attemptID, incomingMaterialUpgradeFixtureHex(t, image.PendingGenesisAttemptID))
	require.Len(t, image.Attempts, 1)
	require.Equal(t, attemptID, incomingMaterialUpgradeFixtureDigestBytes(t, image.Attempts[0].ID))
	require.Equal(t, "genesis", image.Attempts[0].Kind)
	var lifecycle, outcome, blocked string
	var mutation int64
	require.NoError(t, conn.QueryRowContext(ctx, "SELECT lifecycle,outcome,blocked,mutation_revision FROM publication_attempts WHERE attempt_id=?", attemptID).Scan(&lifecycle, &outcome, &blocked, &mutation))
	require.Equal(t, image.Attempts[0].Lifecycle, lifecycle)
	require.Equal(t, image.Attempts[0].Outcome, outcome)
	require.Equal(t, image.Attempts[0].Blocked, blocked)
	require.Equal(t, image.Attempts[0].MutationRevision, mutation)
	require.Equal(t, "prepared", lifecycle)
	require.Equal(t, "not-submitted", outcome)
	require.Equal(t, "", blocked)
	require.Equal(t, int64(1), mutation)
	var activeID, pendingID []byte
	require.NoError(t, conn.QueryRowContext(ctx, "SELECT attempt_id FROM active_publication_attempt WHERE singleton=1").Scan(&activeID))
	require.Equal(t, attemptID, activeID)
	require.NoError(t, conn.QueryRowContext(ctx, "SELECT attempt_id FROM pending_genesis WHERE singleton=1").Scan(&pendingID))
	require.Equal(t, attemptID, pendingID)
	require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM attempt_events"))
	require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM payload_objects"))
	require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM attempt_payload_refs"))
	require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM attempt_reservations"))
	for _, table := range []string{"cache_records", "cache_observations", "accepted_records", "accepted_events", "active_floor", "attempt_evidence", "retained_publications"} {
		require.Zero(t, incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM "+table), table)
	}
	require.False(t, image.AcceptedFloorPresent)
	require.Zero(t, image.AcceptedEventCount)
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM accepted_events"))

	sourceObjects := incomingMaterialUpgradeFixtureObjects(t, ctx, conn)
	sourceCounts := incomingMaterialUpgradeFixtureObjectCounts(t, sourceObjects)
	require.Equal(t, 15, sourceCounts.tables)
	require.Equal(t, 2, sourceCounts.namedIndexes)
	require.Equal(t, 14, sourceCounts.autoIndexes)
	require.Len(t, sourceObjects, 31)
	payloadStatesBefore := incomingMaterialUpgradeFixturePayloadStates(t, fixture.root)
	require.Len(t, image.Payloads, 1)
	incomingMaterialUpgradeFixtureRequireImagePayloads(t, ctx, conn, image, payloadStatesBefore)

	sourceBytes := incomingMaterialUpgradeStoredMetadata(t, ctx, conn)
	tx := incomingMaterialUpgradeTx(t, ctx, conn)
	var points []int
	require.NoError(t, migrateIncomingMaterialTx(ctx, tx, source, func(point int) error {
		points = append(points, point)
		return nil
	}))
	require.Equal(t, []int{13, 14, 15}, points)
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, tx))
	require.Equal(t, before, incomingMaterialUpgradeFixtureTypedRows(t, ctx, tx))
	require.Equal(t, sourceBytes, incomingMaterialUpgradeStoredMetadata(t, ctx, tx))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
	require.NoError(t, checkIncomingMaterialUpgradeDestination(ctx, tx, source))
	destinationObjects := incomingMaterialUpgradeFixtureObjects(t, ctx, tx)
	destinationCounts := incomingMaterialUpgradeFixtureObjectCounts(t, destinationObjects)
	require.Equal(t, 16, destinationCounts.tables)
	require.Equal(t, 2, destinationCounts.namedIndexes)
	require.Equal(t, 14, destinationCounts.autoIndexes)
	require.Len(t, destinationObjects, 32)
	namedAdditions, autoIndexAdditions := incomingMaterialUpgradeFixtureObjectAdditions(t, sourceObjects, destinationObjects)
	require.Equal(t, []string{"accepted_material_refs"}, namedAdditions)
	require.Zero(t, autoIndexAdditions)
	require.Equal(t, incomingMaterialSchemaStatement, destinationObjects["accepted_material_refs"].sql)
	require.Equal(t, payloadStatesBefore, incomingMaterialUpgradeFixturePayloadStates(t, fixture.root))
	require.NoError(t, tx.Rollback())
	require.Equal(t, 2, incomingMaterialUpgradeUserVersion(t, ctx, conn))
	require.Equal(t, before, incomingMaterialUpgradeFixtureTypedRows(t, ctx, conn))
	assert.Equal(t, sourceBytes, incomingMaterialUpgradeStoredMetadata(t, ctx, conn))
	require.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, conn))
	assert.Equal(t, sourceObjects, incomingMaterialUpgradeFixtureObjects(t, ctx, conn))
	assert.Equal(t, payloadStatesBefore, incomingMaterialUpgradeFixturePayloadStates(t, fixture.root))

	closeOwned(t)
	require.Equal(t, payloadStatesBefore, incomingMaterialUpgradeFixturePayloadStates(t, fixture.root))
	readOnly, closeReadOnly := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, databasePath)
	require.Equal(t, 2, incomingMaterialUpgradeUserVersion(t, ctx, readOnly))
	require.NoError(t, checkSchemaVersion(ctx, readOnly, 2))
	assert.Equal(t, before, incomingMaterialUpgradeFixtureTypedRows(t, ctx, readOnly))
	assert.Equal(t, sourceObjects, incomingMaterialUpgradeFixtureObjects(t, ctx, readOnly))
	require.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, readOnly))
	closeReadOnly(t)
	require.Equal(t, payloadStatesBefore, incomingMaterialUpgradeFixturePayloadStates(t, fixture.root))
}

func incomingMaterialUpgradeFixtureMixed(t *testing.T, fixture incomingMaterialUpgradeFixtureAssets) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	image := fixture.manifest.requireImage(t, "mixed")
	binding, limits, attemptLimits := incomingMaterialUpgradeFixtureBindingOptions(t, image)
	databasePath := filepath.Join(fixture.root, "mixed", "publication.db")
	conn, closeOwned := incomingMaterialUpgradeFixtureOpenStore(t, ctx, databasePath)
	require.Equal(t, 2, incomingMaterialUpgradeUserVersion(t, ctx, conn))
	require.NoError(t, checkSchemaVersion(ctx, conn, 2))
	source, err := readIncomingMaterialUpgradeSource(ctx, conn, 2, binding, limits, attemptLimits)
	require.NoError(t, err)
	require.Equal(t, incomingMaterialUpgradeFixtureHex(t, image.DatabaseID), source.metadata["database_id"])
	require.Equal(t, uint64Bytes(2), source.metadata["revision"])
	require.Equal(t, uint64Bytes(2), source.metadata["generation"])
	require.Equal(t, uint64Bytes(17), source.metadata["attempt_mutation_revision"])
	require.Equal(t, uint64(2), image.Revision)
	require.Equal(t, uint64(2), image.Generation)
	require.Equal(t, uint64(17), image.AttemptMutationRevision)
	wantedBinding, err := encodeBinding(binding)
	require.NoError(t, err)
	assert.Equal(t, wantedBinding, source.metadata["binding"])

	companion := incomingMaterialUpgradeFixtureCompanionData(t, fixture.files["mixed-rows.json"])
	incomingMaterialUpgradeFixtureRequireCompanionHeader(t, ctx, conn, companion)
	before := incomingMaterialUpgradeFixtureRequireCompanionTables(t, ctx, conn, companion)
	require.Equal(t, 44, incomingMaterialUpgradeFixtureRowTotal(before))

	require.Len(t, image.Attempts, 3)
	activeID := incomingMaterialUpgradeFixtureHex(t, image.ActiveAttemptID)
	var genesisAttempt, abandonedAttempt, activeAttempt incomingMaterialUpgradeFixtureManifestAttempt
	for _, attempt := range image.Attempts {
		switch attempt.Lifecycle {
		case "retired-success":
			genesisAttempt = attempt
		case "retired-abandoned":
			abandonedAttempt = attempt
		case "may-have-submitted":
			activeAttempt = attempt
		default:
			require.FailNowf(t, "unsupported fixture attempt lifecycle", "%q", attempt.Lifecycle)
		}
		attemptID := incomingMaterialUpgradeFixtureDigestBytes(t, attempt.ID)
		require.NotEmpty(t, attemptID)
		var lifecycle, outcome, blocked string
		var mutation int64
		require.NoError(t, conn.QueryRowContext(ctx, "SELECT lifecycle,outcome,blocked,mutation_revision FROM publication_attempts WHERE attempt_id=?", attemptID).Scan(&lifecycle, &outcome, &blocked, &mutation))
		require.Equal(t, attempt.Lifecycle, lifecycle)
		require.Equal(t, attempt.Outcome, outcome)
		require.Equal(t, attempt.Blocked, blocked)
		require.Equal(t, attempt.MutationRevision, mutation)
	}
	require.Equal(t, "genesis", genesisAttempt.Kind)
	require.Equal(t, "observed-current", genesisAttempt.Outcome)
	require.Equal(t, "successor", abandonedAttempt.Kind)
	require.Equal(t, "lost-fence", abandonedAttempt.Outcome)
	require.Equal(t, "blocked-floor-replaced", abandonedAttempt.Blocked)
	require.Equal(t, "successor", activeAttempt.Kind)
	require.Equal(t, "observed-absent-unresolved", activeAttempt.Outcome)
	require.Equal(t, "", activeAttempt.Blocked)
	require.Equal(t, activeID, incomingMaterialUpgradeFixtureDigestBytes(t, activeAttempt.ID))
	var activeAttemptID []byte
	require.NoError(t, conn.QueryRowContext(ctx, "SELECT attempt_id FROM active_publication_attempt WHERE singleton=1").Scan(&activeAttemptID))
	require.Equal(t, activeID, activeAttemptID)
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM pending_genesis"))
	require.Equal(t, "", image.PendingGenesisAttemptID)
	require.Equal(t, int64(2), incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM accepted_events"))
	require.Equal(t, int64(2), incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM accepted_records"))
	require.Equal(t, int64(15), incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM attempt_events"))
	require.Equal(t, int64(5), incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM attempt_evidence"))
	require.Equal(t, int64(3), incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM payload_objects"))
	require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM attempt_payload_refs"))
	require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM attempt_reservations"))
	require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM retained_publications"))
	require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM cache_records"))
	require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM cache_observations"))
	require.True(t, image.AcceptedFloorPresent)
	require.Equal(t, int64(2), image.AcceptedEventCount)

	floorValue := incomingMaterialUpgradeFixtureScanValue(t, ctx, conn, "SELECT floor FROM active_floor WHERE singleton=1")
	floorRaw, ok := floorValue.([]byte)
	require.True(t, ok)
	floor, err := decodeFloor(floorRaw)
	require.NoError(t, err)
	require.Equal(t, uint64(2), floor.Revision)
	require.Equal(t, uint64(2), floor.Generation)
	require.Equal(t, uint64(0), floor.Sequence)
	require.Equal(t, ProvenanceReplace, floor.Provenance)
	var databaseID [32]byte
	copy(databaseID[:], incomingMaterialUpgradeFixtureHex(t, image.DatabaseID))
	require.Equal(t, databaseID, floor.DatabaseID)
	require.NoError(t, validatePersistedFloor(floor, binding, databaseID, limits))

	retainedRevisions := incomingMaterialUpgradeFixtureScanInt64s(t, ctx, conn, "SELECT accepted_revision FROM retained_publications")
	require.Equal(t, []int64{1}, retainedRevisions)
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM retained_publications WHERE accepted_revision=2"))

	var retainedAttempt, retainedRecord, retainedBlob []byte
	var retainedSequence, retainedSize, retainedRevision int64
	require.NoError(t, conn.QueryRowContext(ctx, "SELECT attempt_id,record_cid,blob_cid,sequence,size,accepted_revision FROM retained_publications").Scan(&retainedAttempt, &retainedRecord, &retainedBlob, &retainedSequence, &retainedSize, &retainedRevision))
	require.Equal(t, int64(1), retainedRevision)
	require.Equal(t, int64(0), retainedSequence)
	require.Equal(t, int64(3072), retainedSize)
	require.NotEmpty(t, retainedRecord)
	require.NotEmpty(t, retainedBlob)
	genesisAttemptID := incomingMaterialUpgradeFixtureDigestBytes(t, genesisAttempt.ID)
	require.Equal(t, genesisAttemptID, retainedAttempt)

	abandonedAttemptID := incomingMaterialUpgradeFixtureDigestBytes(t, abandonedAttempt.ID)
	require.NotEqual(t, abandonedAttemptID, activeID)
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM attempt_payload_refs WHERE attempt_id=?", abandonedAttemptID))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM attempt_reservations WHERE attempt_id=?", abandonedAttemptID))

	sourceObjects := incomingMaterialUpgradeFixtureObjects(t, ctx, conn)
	sourceCounts := incomingMaterialUpgradeFixtureObjectCounts(t, sourceObjects)
	require.Equal(t, 15, sourceCounts.tables)
	require.Equal(t, 2, sourceCounts.namedIndexes)
	require.Equal(t, 14, sourceCounts.autoIndexes)
	require.Len(t, sourceObjects, 31)
	payloadStatesBefore := incomingMaterialUpgradeFixturePayloadStates(t, fixture.root)
	require.Len(t, image.Payloads, 3)
	incomingMaterialUpgradeFixtureRequireImagePayloads(t, ctx, conn, image, payloadStatesBefore)

	inputs := incomingMaterialUpgradeFixtureInputsData(t, fixture.files["mixed-inputs.json"])
	incomingMaterialUpgradeFixtureRequireMixedProjections(t, ctx, conn, inputs, floor)

	sourceBytes := incomingMaterialUpgradeStoredMetadata(t, ctx, conn)
	tx := incomingMaterialUpgradeTx(t, ctx, conn)
	var points []int
	require.NoError(t, migrateIncomingMaterialTx(ctx, tx, source, func(point int) error {
		points = append(points, point)
		return nil
	}))
	require.Equal(t, []int{13, 14, 15}, points)
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, tx))
	require.Equal(t, before, incomingMaterialUpgradeFixtureTypedRows(t, ctx, tx))
	require.Equal(t, sourceBytes, incomingMaterialUpgradeStoredMetadata(t, ctx, tx))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
	require.NoError(t, checkIncomingMaterialUpgradeDestination(ctx, tx, source))
	destinationObjects := incomingMaterialUpgradeFixtureObjects(t, ctx, tx)
	destinationCounts := incomingMaterialUpgradeFixtureObjectCounts(t, destinationObjects)
	require.Equal(t, 16, destinationCounts.tables)
	require.Equal(t, 2, destinationCounts.namedIndexes)
	require.Equal(t, 14, destinationCounts.autoIndexes)
	require.Len(t, destinationObjects, 32)
	namedAdditions, autoIndexAdditions := incomingMaterialUpgradeFixtureObjectAdditions(t, sourceObjects, destinationObjects)
	require.Equal(t, []string{"accepted_material_refs"}, namedAdditions)
	require.Zero(t, autoIndexAdditions)
	require.Equal(t, incomingMaterialSchemaStatement, destinationObjects["accepted_material_refs"].sql)
	require.Equal(t, payloadStatesBefore, incomingMaterialUpgradeFixturePayloadStates(t, fixture.root))
	require.NoError(t, tx.Rollback())
	require.Equal(t, 2, incomingMaterialUpgradeUserVersion(t, ctx, conn))
	require.Equal(t, before, incomingMaterialUpgradeFixtureTypedRows(t, ctx, conn))
	assert.Equal(t, sourceBytes, incomingMaterialUpgradeStoredMetadata(t, ctx, conn))
	require.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, conn))
	assert.Equal(t, sourceObjects, incomingMaterialUpgradeFixtureObjects(t, ctx, conn))
	assert.Equal(t, payloadStatesBefore, incomingMaterialUpgradeFixturePayloadStates(t, fixture.root))

	closeOwned(t)
	require.Equal(t, payloadStatesBefore, incomingMaterialUpgradeFixturePayloadStates(t, fixture.root))
	readOnly, closeReadOnly := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, databasePath)
	require.Equal(t, 2, incomingMaterialUpgradeUserVersion(t, ctx, readOnly))
	require.NoError(t, checkSchemaVersion(ctx, readOnly, 2))
	assert.Equal(t, before, incomingMaterialUpgradeFixtureTypedRows(t, ctx, readOnly))
	assert.Equal(t, sourceObjects, incomingMaterialUpgradeFixtureObjects(t, ctx, readOnly))
	require.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, readOnly))
	closeReadOnly(t)
	require.Equal(t, payloadStatesBefore, incomingMaterialUpgradeFixturePayloadStates(t, fixture.root))
}

func incomingMaterialUpgradeFixtureCopy(t *testing.T) incomingMaterialUpgradeFixtureAssets {
	t.Helper()
	original := make(map[string][]byte, len(incomingMaterialUpgradeFixtureSpecs))
	available := make(map[string]bool, len(incomingMaterialUpgradeFixtureSpecs))
	t.Cleanup(func() {
		for _, spec := range incomingMaterialUpgradeFixtureSpecs {
			data, err := os.ReadFile(filepath.Join(incomingMaterialUpgradeFixtureRoot, spec.relative))
			if !assert.NoError(t, err, spec.relative) {
				continue
			}
			assert.Equal(t, spec.sha256, incomingMaterialUpgradeFixtureSHA256(data), spec.relative)
			if available[spec.relative] {
				assert.Equal(t, original[spec.relative], data, spec.relative)
			}
		}
	})
	for _, spec := range incomingMaterialUpgradeFixtureSpecs {
		data := incomingMaterialUpgradeReadPinned(t, filepath.Join(incomingMaterialUpgradeFixtureRoot, spec.relative), spec.length)
		require.Equal(t, spec.sha256, incomingMaterialUpgradeFixtureSHA256(data), spec.relative)
		original[spec.relative] = data
		available[spec.relative] = true
	}

	root := t.TempDir()
	require.NoError(t, os.Chmod(root, 0o700))
	var rootStat unix.Stat_t
	require.NoError(t, unix.Lstat(root, &rootStat))
	require.Equal(t, uint32(unix.S_IFDIR), rootStat.Mode&unix.S_IFMT)
	require.Equal(t, uint32(0o700), rootStat.Mode&0o777)
	require.Equal(t, uint32(os.Getuid()), rootStat.Uid)
	for _, relative := range incomingMaterialUpgradeFixtureDirectories {
		path := filepath.Join(root, relative)
		require.NoError(t, os.Mkdir(path, 0o700))
		var stat unix.Stat_t
		require.NoError(t, unix.Lstat(path, &stat))
		require.Equal(t, uint32(unix.S_IFDIR), stat.Mode&unix.S_IFMT)
		require.Equal(t, uint32(0o700), stat.Mode&0o777)
		require.Equal(t, uint32(os.Getuid()), stat.Uid)
	}
	for _, spec := range incomingMaterialUpgradeFixtureSpecs {
		incomingMaterialUpgradeWriteExclusive(t, filepath.Join(root, spec.relative), original[spec.relative])
	}
	for _, spec := range incomingMaterialUpgradeFixtureSpecs {
		path := filepath.Join(root, spec.relative)
		var stat unix.Stat_t
		require.NoError(t, unix.Lstat(path, &stat))
		require.Equal(t, uint32(unix.S_IFREG), stat.Mode&unix.S_IFMT)
		require.Equal(t, uint32(0o600), stat.Mode&0o777)
		require.Equal(t, uint32(os.Getuid()), stat.Uid)
		require.Equal(t, uint64(1), stat.Nlink)
		require.Equal(t, spec.length, stat.Size)
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, spec.sha256, incomingMaterialUpgradeFixtureSHA256(data), spec.relative)
		require.Equal(t, original[spec.relative], data, spec.relative)
	}
	return incomingMaterialUpgradeFixtureAssets{
		root:     root,
		files:    original,
		manifest: incomingMaterialUpgradeFixtureManifestData(t, original["manifest.json"]),
	}
}

func (m incomingMaterialUpgradeFixtureManifest) requireImage(t *testing.T, name string) incomingMaterialUpgradeFixtureManifestImage {
	t.Helper()
	require.Equal(t, 1, m.FormatVersion)
	require.Len(t, m.Images, 2)
	matches := make([]incomingMaterialUpgradeFixtureManifestImage, 0, 1)
	for _, image := range m.Images {
		if image.Name == name {
			matches = append(matches, image)
		}
	}
	require.Len(t, matches, 1, name)
	return matches[0]
}

func incomingMaterialUpgradeFixtureManifestData(t *testing.T, data []byte) incomingMaterialUpgradeFixtureManifest {
	t.Helper()
	var manifest incomingMaterialUpgradeFixtureManifest
	require.NoError(t, json.Unmarshal(data, &manifest))
	require.Equal(t, 1, manifest.FormatVersion)
	return manifest
}

func incomingMaterialUpgradeFixtureInputsData(t *testing.T, data []byte) incomingMaterialUpgradeFixtureInputs {
	t.Helper()
	var inputs incomingMaterialUpgradeFixtureInputs
	require.NoError(t, json.Unmarshal(data, &inputs))
	return inputs
}

func incomingMaterialUpgradeFixtureCompanionData(t *testing.T, data []byte) incomingMaterialUpgradeFixtureCompanion {
	t.Helper()
	var companion incomingMaterialUpgradeFixtureCompanion
	require.NoError(t, json.Unmarshal(data, &companion))
	require.Equal(t, 1, companion.FormatVersion)
	return companion
}

func incomingMaterialUpgradeFixtureBindingOptions(t *testing.T, image incomingMaterialUpgradeFixtureManifestImage) (Binding, Limits, AttemptLimits) {
	t.Helper()
	binding := Binding{AccountDID: incomingMaterialUpgradeFixtureDID, Backend: BackendPublicRepo, Repository: "at://" + incomingMaterialUpgradeFixtureDID}
	binding.Vault = [32]byte{9}
	require.Equal(t, binding.AccountDID, image.Binding.AccountDID)
	require.Equal(t, string(binding.Backend), image.Binding.Backend)
	require.Equal(t, binding.Repository, image.Binding.Repository)
	require.Equal(t, binding.Vault[:], incomingMaterialUpgradeFixtureDigestBytes(t, image.Binding.Vault))
	require.Equal(t, DefaultLimits(), image.Options.PositionLimits)
	require.Equal(t, DefaultAttemptLimits(), image.Options.AttemptLimits)
	return binding, image.Options.PositionLimits, image.Options.AttemptLimits
}

func incomingMaterialUpgradeFixtureRequireCompanionHeader(t *testing.T, ctx context.Context, q queryer, companion incomingMaterialUpgradeFixtureCompanion) {
	t.Helper()
	var applicationID, userVersion int
	require.NoError(t, q.QueryRowContext(ctx, "PRAGMA application_id").Scan(&applicationID))
	require.NoError(t, q.QueryRowContext(ctx, "PRAGMA user_version").Scan(&userVersion))
	require.Equal(t, companion.ApplicationID, applicationID)
	require.Equal(t, companion.UserVersion, userVersion)
	metadataKeys, err := readMetadataKeys(ctx, q)
	require.NoError(t, err)
	require.Equal(t, companion.MetadataKeys, metadataKeys)
	objects := incomingMaterialUpgradeFixtureObjects(t, ctx, q)
	named := make(map[string]incomingMaterialUpgradeFixtureObject, len(companion.SchemaObjects))
	for name, object := range objects {
		if strings.HasPrefix(name, "sqlite_autoindex_") {
			continue
		}
		named[name] = object
	}
	require.Len(t, named, len(companion.SchemaObjects))
	for _, expected := range companion.SchemaObjects {
		observed, present := named[expected.Name]
		require.True(t, present, expected.Name)
		require.Equal(t, expected.Kind, observed.kind, expected.Name)
		require.Equal(t, expected.SQL, observed.sql, expected.Name)
	}
}

func incomingMaterialUpgradeFixtureRequireCompanionTables(t *testing.T, ctx context.Context, q queryer, companion incomingMaterialUpgradeFixtureCompanion) map[string][][]any {
	t.Helper()
	observed := incomingMaterialUpgradeFixtureTypedRows(t, ctx, q)
	tables := make(map[string]incomingMaterialUpgradeFixtureCompanionTable, len(companion.Tables))
	for _, table := range companion.Tables {
		_, duplicate := tables[table.Name]
		require.False(t, duplicate, table.Name)
		tables[table.Name] = table
	}
	require.Len(t, tables, len(incomingMaterialUpgradeFixtureTableNames))
	for _, name := range incomingMaterialUpgradeFixtureTableNames {
		table, present := tables[name]
		require.True(t, present, name)
		observedRows, present := observed[name]
		require.True(t, present, name)
		columns := incomingMaterialUpgradeFixtureColumns(t, ctx, q, name)
		require.Len(t, columns, len(table.Columns), name)
		for index, column := range table.Columns {
			require.Equal(t, column.Name, columns[index], name)
		}
		expected := incomingMaterialUpgradeFixtureCompanionRows(t, table)
		require.Equal(t, table.RowCount, len(expected), name)
		require.Equal(t, table.RowCount, len(observedRows), name)
		require.Equal(t, incomingMaterialUpgradeFixtureKeyedRows(t, name, columns, expected), incomingMaterialUpgradeFixtureKeyedRows(t, name, columns, observedRows), name)
	}
	return observed
}

func incomingMaterialUpgradeFixtureCompanionRows(t *testing.T, table incomingMaterialUpgradeFixtureCompanionTable) [][]any {
	t.Helper()
	rows := make([][]any, 0, len(table.Rows))
	for _, row := range table.Rows {
		require.Len(t, row, len(table.Columns), table.Name)
		values := make([]any, len(row))
		for index, cell := range row {
			values[index] = incomingMaterialUpgradeFixtureCellValue(t, table.Name, table.Columns[index].Name, cell)
		}
		rows = append(rows, values)
	}
	return rows
}

func incomingMaterialUpgradeFixtureCellValue(t *testing.T, table, column string, cell incomingMaterialUpgradeFixtureCell) any {
	t.Helper()
	switch cell.Type {
	case "null":
		require.Empty(t, cell.Value, table+"."+column)
		return nil
	case "integer":
		value, err := strconv.ParseInt(cell.Value, 10, 64)
		require.NoError(t, err, table+"."+column)
		require.Equal(t, strconv.FormatInt(value, 10), cell.Value, table+"."+column)
		return value
	case "text-base64":
		data, err := base64.StdEncoding.DecodeString(cell.Value)
		require.NoError(t, err, table+"."+column)
		require.Equal(t, base64.StdEncoding.EncodeToString(data), cell.Value, table+"."+column)
		return string(data)
	case "blob-base64":
		data, err := base64.StdEncoding.DecodeString(cell.Value)
		require.NoError(t, err, table+"."+column)
		require.Equal(t, base64.StdEncoding.EncodeToString(data), cell.Value, table+"."+column)
		return data
	default:
		require.FailNowf(t, "unsupported fixture cell type", "%s.%s: %q", table, column, cell.Type)
		return nil
	}
}

func incomingMaterialUpgradeFixtureKeyedRows(t *testing.T, table string, columns []string, rows [][]any) map[string][]any {
	t.Helper()
	keyed := make(map[string][]any, len(rows))
	for _, row := range rows {
		require.Len(t, row, len(columns), table)
		key := incomingMaterialUpgradeFixtureRowKey(t, table, columns, row)
		_, duplicate := keyed[key]
		require.False(t, duplicate, table+" duplicate key "+key)
		keyed[key] = row
	}
	return keyed
}

func incomingMaterialUpgradeFixtureRowKey(t *testing.T, table string, columns []string, row []any) string {
	t.Helper()
	keyColumns, present := incomingMaterialUpgradeFixtureTableKeys[table]
	require.True(t, present, table)
	parts := make([]string, 0, len(keyColumns))
	for _, column := range keyColumns {
		index := -1
		for position, name := range columns {
			if name == column {
				index = position
				break
			}
		}
		require.NotEqual(t, -1, index, table+"."+column)
		parts = append(parts, incomingMaterialUpgradeFixtureKeyPart(t, table, column, row[index]))
	}
	return strings.Join(parts, "\x1f")
}

func incomingMaterialUpgradeFixtureKeyPart(t *testing.T, table, column string, value any) string {
	t.Helper()
	switch typed := value.(type) {
	case nil:
		return "null"
	case []byte:
		return "blob:" + hex.EncodeToString(typed)
	case string:
		return "text:" + typed
	case int64:
		return "integer:" + strconv.FormatInt(typed, 10)
	default:
		require.FailNowf(t, "unsupported fixture key type", "%s.%s: %T", table, column, value)
		return ""
	}
}

func incomingMaterialUpgradeFixtureColumns(t *testing.T, ctx context.Context, q queryer, table string) []string {
	t.Helper()
	rows, err := q.QueryContext(ctx, "SELECT * FROM "+table+" LIMIT 0")
	require.NoError(t, err)
	columns, columnsErr := rows.Columns()
	closeErr := rows.Close()
	require.NoError(t, columnsErr)
	require.NoError(t, closeErr)
	return columns
}

func incomingMaterialUpgradeFixtureTypedRows(t *testing.T, ctx context.Context, q queryer) map[string][][]any {
	t.Helper()
	rows, err := sharedCustodyLogicalRows(ctx, q)
	require.NoError(t, err)
	return rows
}

func incomingMaterialUpgradeFixtureRowTotal(rows map[string][][]any) int {
	total := 0
	for _, tableRows := range rows {
		total += len(tableRows)
	}
	return total
}

func incomingMaterialUpgradeFixtureObjects(t *testing.T, ctx context.Context, q queryer) map[string]incomingMaterialUpgradeFixtureObject {
	t.Helper()
	rows, err := q.QueryContext(ctx, "SELECT name,type,IFNULL(sql,'') FROM sqlite_master ORDER BY name")
	require.NoError(t, err)
	type entry struct {
		name       string
		kind       string
		definition string
	}
	entries := make([]entry, 0, 32)
	var scanErr error
	for rows.Next() {
		var name, kind, definition string
		if scanErr = rows.Scan(&name, &kind, &definition); scanErr != nil {
			break
		}
		entries = append(entries, entry{name: name, kind: kind, definition: definition})
	}
	rowsErr := rows.Err()
	closeErr := rows.Close()
	require.NoError(t, scanErr)
	require.NoError(t, rowsErr)
	require.NoError(t, closeErr)
	objects := make(map[string]incomingMaterialUpgradeFixtureObject, len(entries))
	for _, item := range entries {
		_, duplicate := objects[item.name]
		require.False(t, duplicate, item.name)
		objects[item.name] = incomingMaterialUpgradeFixtureObject{kind: item.kind, sql: item.definition}
	}
	return objects
}

func incomingMaterialUpgradeFixtureObjectCounts(t *testing.T, objects map[string]incomingMaterialUpgradeFixtureObject) incomingMaterialUpgradeFixtureSchemaCounts {
	t.Helper()
	var counts incomingMaterialUpgradeFixtureSchemaCounts
	for name, object := range objects {
		switch object.kind {
		case "table":
			counts.tables++
		case "index":
			if strings.HasPrefix(name, "sqlite_autoindex_") {
				counts.autoIndexes++
			} else {
				counts.namedIndexes++
			}
		default:
			require.FailNowf(t, "unsupported sqlite_master kind", "%s: %q", name, object.kind)
		}
	}
	return counts
}

func incomingMaterialUpgradeFixtureObjectAdditions(t *testing.T, source, destination map[string]incomingMaterialUpgradeFixtureObject) ([]string, int) {
	t.Helper()
	for name, sourceObject := range source {
		observed, present := destination[name]
		require.True(t, present, name)
		require.Equal(t, sourceObject, observed, name)
	}
	named := make([]string, 0)
	autoIndexes := 0
	for name, object := range destination {
		if _, present := source[name]; present {
			continue
		}
		if strings.HasPrefix(name, "sqlite_autoindex_") {
			require.Equal(t, "index", object.kind, name)
			require.Empty(t, object.sql, name)
			autoIndexes++
			continue
		}
		named = append(named, name)
	}
	sort.Strings(named)
	return named, autoIndexes
}

func incomingMaterialUpgradeFixtureOpenStore(t *testing.T, ctx context.Context, databasePath string) (*sql.Conn, func(*testing.T)) {
	t.Helper()
	var lock *platform.Lock
	var db *sql.DB
	var conn *sql.Conn
	closed := false
	closeOwned := func(t *testing.T) {
		t.Helper()
		if closed {
			return
		}
		closed = true
		connErr := conn.Close()
		dbErr := db.Close()
		lockErr := lock.Close()
		require.NoError(t, connErr)
		require.NoError(t, dbErr)
		require.NoError(t, lockErr)
	}
	t.Cleanup(func() {
		if closed {
			return
		}
		closed = true
		var connErr, dbErr, lockErr error
		if conn != nil {
			connErr = conn.Close()
		}
		if db != nil {
			dbErr = db.Close()
		}
		if lock != nil {
			lockErr = lock.Close()
		}
		assert.NoError(t, connErr)
		assert.NoError(t, dbErr)
		assert.NoError(t, lockErr)
	})
	var err error
	lock, err = platform.LockFile(databasePath + ".lock")
	require.NoError(t, err)
	db, err = sql.Open("sqlite", dbDSN(databasePath, false))
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	conn, err = db.Conn(ctx)
	require.NoError(t, err)
	require.NoError(t, configureConnection(ctx, conn))
	return conn, closeOwned
}

func incomingMaterialUpgradeFixtureOpenReadOnly(t *testing.T, ctx context.Context, databasePath string) (*sql.Conn, func(*testing.T)) {
	t.Helper()
	var db *sql.DB
	var conn *sql.Conn
	closed := false
	closeOwned := func(t *testing.T) {
		t.Helper()
		if closed {
			return
		}
		closed = true
		connErr := conn.Close()
		dbErr := db.Close()
		require.NoError(t, connErr)
		require.NoError(t, dbErr)
	}
	t.Cleanup(func() {
		if closed {
			return
		}
		closed = true
		var connErr, dbErr error
		if conn != nil {
			connErr = conn.Close()
		}
		if db != nil {
			dbErr = db.Close()
		}
		assert.NoError(t, connErr)
		assert.NoError(t, dbErr)
	})
	var err error
	db, err = sql.Open("sqlite", dbDSN(databasePath, true))
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	conn, err = db.Conn(ctx)
	require.NoError(t, err)
	return conn, closeOwned
}

func incomingMaterialUpgradeFixturePayloadStates(t *testing.T, root string) map[string]incomingMaterialUpgradeFixturePayload {
	t.Helper()
	states := make(map[string]incomingMaterialUpgradeFixturePayload, len(incomingMaterialUpgradeFixturePayloadPaths))
	for _, relative := range incomingMaterialUpgradeFixturePayloadPaths {
		states[relative] = incomingMaterialUpgradeFixturePayloadState(t, filepath.Join(root, relative))
	}
	return states
}

func incomingMaterialUpgradeFixturePayloadState(t *testing.T, path string) incomingMaterialUpgradeFixturePayload {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var stat unix.Stat_t
	require.NoError(t, unix.Lstat(path, &stat))
	require.Equal(t, uint32(unix.S_IFREG), stat.Mode&unix.S_IFMT, path)
	require.Equal(t, uint32(0o600), stat.Mode&0o777, path)
	require.Equal(t, uint32(os.Getuid()), stat.Uid, path)
	require.Equal(t, uint64(1), stat.Nlink, path)
	require.Equal(t, int64(len(data)), stat.Size, path)
	return incomingMaterialUpgradeFixturePayload{
		bytes:  data,
		size:   stat.Size,
		mode:   stat.Mode & 0o777,
		uid:    stat.Uid,
		nlink:  stat.Nlink,
		sha256: incomingMaterialUpgradeFixtureSHA256(data),
	}
}

func incomingMaterialUpgradeFixtureRequireImagePayloads(t *testing.T, ctx context.Context, q queryer, image incomingMaterialUpgradeFixtureManifestImage, states map[string]incomingMaterialUpgradeFixturePayload) {
	t.Helper()
	require.NotEmpty(t, image.Payloads)
	for _, entry := range image.Payloads {
		state, present := states[entry.Path]
		require.True(t, present, entry.Path)
		require.Equal(t, entry.Length, state.size, entry.Path)
		require.Equal(t, entry.SHA256, state.sha256, entry.Path)
		var blobCID []byte
		var size int64
		require.NoError(t, q.QueryRowContext(ctx, "SELECT blob_cid,size FROM payload_objects WHERE basename=?", filepath.Base(entry.Path)).Scan(&blobCID, &size))
		require.Equal(t, state.size, size, entry.Path)
		require.Equal(t, entry.BlobCID.Base64, base64.StdEncoding.EncodeToString(blobCID), entry.Path)
		require.Equal(t, entry.BlobCID.SHA256, incomingMaterialUpgradeFixtureSHA256(blobCID), entry.Path)
		reference := publication.BlobReference{CID: blobCID, Size: uint64(size)}
		require.NoError(t, publication.VerifyPayload(state.bytes, reference), entry.Path)
		_, err := publication.DecodePayload(state.bytes, reference)
		require.NoError(t, err, entry.Path)
		attemptID := incomingMaterialUpgradeFixtureHex(t, entry.AttemptID)
		switch entry.Owner {
		case "attempt":
			require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, q, "SELECT COUNT(*) FROM attempt_payload_refs WHERE attempt_id=? AND blob_cid=?", attemptID, blobCID), entry.Path)
		case "none":
			require.Zero(t, incomingMaterialUpgradeCount(t, ctx, q, "SELECT COUNT(*) FROM attempt_payload_refs WHERE attempt_id=? AND blob_cid=?", attemptID, blobCID), entry.Path)
			require.Zero(t, incomingMaterialUpgradeCount(t, ctx, q, "SELECT COUNT(*) FROM retained_publications WHERE blob_cid=?", blobCID), entry.Path)
		case "retained-publication":
			require.NotNil(t, entry.AcceptedRevision, entry.Path)
			var acceptedRevision int64
			require.NoError(t, q.QueryRowContext(ctx, "SELECT accepted_revision FROM retained_publications WHERE blob_cid=?", blobCID).Scan(&acceptedRevision))
			require.Equal(t, *entry.AcceptedRevision, acceptedRevision, entry.Path)
		default:
			require.FailNowf(t, "unsupported payload owner", "%s: %q", entry.Path, entry.Owner)
		}
	}
}

func incomingMaterialUpgradeFixtureRequireMixedProjections(t *testing.T, ctx context.Context, q queryer, inputs incomingMaterialUpgradeFixtureInputs, floor Floor) {
	t.Helper()
	firstConflict := inputs.Results.FirstConflict
	attemptID := incomingMaterialUpgradeFixtureDigestBytes(t, firstConflict.AttemptID)
	envelope := incomingMaterialUpgradeFixtureDigestBytes(t, firstConflict.Envelope)
	require.NotEmpty(t, envelope)
	require.NotEmpty(t, incomingMaterialUpgradeFixtureDigestBytes(t, firstConflict.ID))
	require.Equal(t, int64(1), firstConflict.HeadSequence)
	finalConflict := inputs.Results.FinalFirstConflict
	require.Equal(t, attemptID, incomingMaterialUpgradeFixtureDigestBytes(t, finalConflict.AttemptID))
	require.Equal(t, envelope, incomingMaterialUpgradeFixtureDigestBytes(t, finalConflict.Envelope))
	require.Equal(t, incomingMaterialUpgradeFixtureDigestBytes(t, firstConflict.ID), incomingMaterialUpgradeFixtureDigestBytes(t, finalConflict.ID))
	require.Equal(t, int64(1), finalConflict.HeadSequence)
	priorLatestEvidence := incomingMaterialUpgradeFixtureDigestBytes(t, inputs.Results.PriorLatestEvidence)
	require.NotEmpty(t, priorLatestEvidence)
	require.Equal(t, priorLatestEvidence, incomingMaterialUpgradeFixtureDigestBytes(t, inputs.Results.PriorLatest.Evidence))
	require.Equal(t, attemptID, incomingMaterialUpgradeFixtureDigestBytes(t, inputs.Results.PriorLatest.Attempt.ID))
	require.Equal(t, "may-have-submitted", inputs.Results.PriorLatest.Attempt.Lifecycle)
	require.Equal(t, "lost-fence", inputs.Results.PriorLatest.Outcome)
	priorViewDigest := incomingMaterialUpgradeFixtureDigestBytes(t, inputs.Results.PriorLatest.ViewDigest)
	require.Len(t, priorViewDigest, 32)

	var firstConflictBody, firstConflictDigest []byte
	require.NoError(t, q.QueryRowContext(ctx, "SELECT body,digest FROM attempt_evidence WHERE attempt_id=? AND role='first-conflict'", attemptID).Scan(&firstConflictBody, &firstConflictDigest))
	require.Equal(t, envelope, firstConflictBody)
	require.Len(t, firstConflictDigest, 32)
	require.NotEqual(t, make([]byte, 32), firstConflictDigest)
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, q, "SELECT COUNT(*) FROM attempt_evidence WHERE body=?", priorLatestEvidence))

	var outcomeBody, retirementBody []byte
	require.NoError(t, q.QueryRowContext(ctx, "SELECT body FROM attempt_evidence WHERE attempt_id=? AND role='outcome'", attemptID).Scan(&outcomeBody))
	require.NoError(t, q.QueryRowContext(ctx, "SELECT body FROM attempt_evidence WHERE attempt_id=? AND role='retirement'", attemptID).Scan(&retirementBody))
	require.NotEmpty(t, outcomeBody)
	require.Equal(t, outcomeBody, retirementBody)
	require.NotEqual(t, outcomeBody, firstConflictBody)
	var lifecycle, outcome, blocked string
	var mutation int64
	var terminal, retirement []byte
	require.NoError(t, q.QueryRowContext(ctx, "SELECT lifecycle,outcome,blocked,mutation_revision,terminal_evidence,retirement_evidence FROM publication_attempts WHERE attempt_id=?", attemptID).Scan(&lifecycle, &outcome, &blocked, &mutation, &terminal, &retirement))
	require.Equal(t, inputs.Results.RetiredAttempt.Lifecycle, lifecycle)
	require.Equal(t, inputs.Results.RetiredAttempt.Outcome, outcome)
	require.Equal(t, inputs.Results.RetiredAttempt.Blocked, blocked)
	require.Equal(t, inputs.Results.RetiredAttempt.MutationRevision, mutation)
	require.Equal(t, outcomeBody, terminal)
	require.Equal(t, retirementBody, retirement)

	var conflict firstConflictWire
	require.NoError(t, strictJSON(envelope, &conflict))
	require.Equal(t, uint32(1), conflict.Version)
	require.Equal(t, attemptID, conflict.AttemptID)
	require.Equal(t, "", conflict.Blocked)
	require.Len(t, conflict.Proof.Suffix, 1)
	incomingMaterialUpgradeFixtureRequireProof(t, "first conflict", conflict.Proof, 1)
	conflictHead := incomingMaterialUpgradeFixtureDigestBytes(t, firstConflict.Head)
	conflictHeadRecord := incomingMaterialUpgradeFixtureDigestBytes(t, firstConflict.HeadRecord)
	require.Equal(t, conflictHead, conflict.Proof.Head)
	require.Equal(t, firstConflict.HeadKey, conflict.Proof.Suffix[0].Key)
	require.Equal(t, conflictHeadRecord, conflict.Proof.Suffix[0].Raw)
	require.Equal(t, firstConflict.HeadKey, conflict.Proof.AttemptedKey)
	require.Equal(t, conflictHeadRecord, conflict.Proof.AttemptedRecord)

	var prior attemptEvidenceWire
	require.NoError(t, strictJSON(priorLatestEvidence, &prior))
	incomingMaterialUpgradeFixtureRequireProof(t, "prior latest", prior, 2)
	require.Equal(t, incomingMaterialUpgradeFixtureDigestBytes(t, inputs.Views.Extended.Head), prior.Head)
	require.Equal(t, priorViewDigest, prior.ViewDigest)

	var final attemptEvidenceWire
	require.NoError(t, strictJSON(outcomeBody, &final))
	incomingMaterialUpgradeFixtureRequireProof(t, "final outcome", final, 3)
	require.Equal(t, incomingMaterialUpgradeFixtureDigestBytes(t, inputs.Views.Retirement.Head), final.Head)

	require.NotEqual(t, envelope, priorLatestEvidence)
	require.NotEqual(t, priorLatestEvidence, outcomeBody)
	require.NotEqual(t, envelope, outcomeBody)
	require.NotEqual(t, conflict.Proof.Head, prior.Head)
	require.NotEqual(t, prior.Head, final.Head)
	for index := range conflict.Proof.Suffix {
		require.Equal(t, conflict.Proof.Suffix[index], prior.Suffix[index])
	}
	for index := range prior.Suffix {
		require.Equal(t, prior.Suffix[index], final.Suffix[index])
	}

	require.Equal(t, inputs.Results.FinalFloor.Revision, floor.Revision)
	require.Equal(t, inputs.Results.FinalFloor.Generation, floor.Generation)
	require.Equal(t, Provenance(inputs.Results.FinalFloor.Provenance), floor.Provenance)
}

func incomingMaterialUpgradeFixtureRequireProof(t *testing.T, name string, wire attemptEvidenceWire, expectedSequence uint64) {
	t.Helper()
	require.Equal(t, uint32(1), wire.Version, name)
	require.Equal(t, "outcome", wire.Role, name)
	require.Equal(t, "lost-fence", wire.Outcome, name)
	require.Equal(t, "whole-repository", wire.Scope, name)
	require.NotEmpty(t, wire.Head, name)
	require.Len(t, wire.Suffix, int(expectedSequence), name)
	last := wire.Suffix[len(wire.Suffix)-1]
	keySequence, err := publication.ParseSequenceKey(last.Key)
	require.NoError(t, err, name)
	require.Equal(t, expectedSequence, keySequence, name)
	snapshot, err := publication.DecodeSnapshot(last.Raw)
	require.NoError(t, err, name)
	require.Equal(t, expectedSequence, snapshot.PublicationSeq, name)
	require.Equal(t, [32]byte{9}, snapshot.Vault, name)
	head, err := publication.DecodeHead(wire.Head)
	require.NoError(t, err, name)
	require.Equal(t, expectedSequence, head.PublicationSeq, name)
	require.Equal(t, [32]byte{9}, head.Vault, name)
	require.NoError(t, publication.VerifyHeadBinding(wire.Head, last.Raw, last.Key), name)
}

func incomingMaterialUpgradeFixtureDigestBytes(t *testing.T, digest incomingMaterialUpgradeFixtureDigest) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(digest.Base64)
	require.NoError(t, err)
	require.Equal(t, base64.StdEncoding.EncodeToString(data), digest.Base64)
	require.Equal(t, digest.Length, int64(len(data)))
	require.Equal(t, digest.SHA256, incomingMaterialUpgradeFixtureSHA256(data))
	return data
}

func incomingMaterialUpgradeFixtureHex(t *testing.T, value string) []byte {
	t.Helper()
	data, err := hex.DecodeString(value)
	require.NoError(t, err)
	require.NotEmpty(t, data)
	return data
}

func incomingMaterialUpgradeFixtureSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func incomingMaterialUpgradeFixtureScanValue(t *testing.T, ctx context.Context, q queryer, query string, args ...any) any {
	t.Helper()
	var value any
	require.NoError(t, q.QueryRowContext(ctx, query, args...).Scan(&value))
	return value
}

func incomingMaterialUpgradeFixtureScanInt64s(t *testing.T, ctx context.Context, q queryer, query string, args ...any) []int64 {
	t.Helper()
	rows, err := q.QueryContext(ctx, query, args...)
	require.NoError(t, err)
	values := make([]int64, 0)
	var scanErr error
	for rows.Next() {
		var value int64
		if scanErr = rows.Scan(&value); scanErr != nil {
			break
		}
		values = append(values, value)
	}
	rowsErr := rows.Err()
	closeErr := rows.Close()
	require.NoError(t, scanErr)
	require.NoError(t, rowsErr)
	require.NoError(t, closeErr)
	sort.Slice(values, func(left, right int) bool { return values[left] < values[right] })
	return values
}
