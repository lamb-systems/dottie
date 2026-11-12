package publicationstate

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type incomingMaterialUpgradeOutcomeOwner struct {
	directory    string
	databasePath string
	rootFD       int
	lock         *platform.Lock
	db           *sql.DB
	conn         *sql.Conn
	sqlClosed    bool
	closed       bool
}

func incomingMaterialUpgradeOutcomeOpen(t *testing.T, ctx context.Context, directory string) *incomingMaterialUpgradeOutcomeOwner {
	t.Helper()
	owner := &incomingMaterialUpgradeOutcomeOwner{directory: directory, databasePath: filepath.Join(directory, "publication.db"), rootFD: -1}
	t.Cleanup(func() { owner.close(t) })
	require.NoError(t, checkPrivateDirectory(directory))
	for _, name := range []string{"publication.db.lock", "publication.db", "publication.db-wal", "publication.db-shm"} {
		require.NoError(t, preflightFile(filepath.Join(directory, name)), name)
	}
	rootFD, err := openStoreRoot(directory)
	require.NoError(t, err)
	owner.rootFD = rootFD
	lock, err := platform.LockFile(owner.databasePath + ".lock")
	require.NoError(t, err)
	owner.lock = lock
	db, err := sql.Open("sqlite", dbDSN(owner.databasePath, false))
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	owner.db = db
	conn, err := db.Conn(ctx)
	require.NoError(t, err)
	owner.conn = conn
	require.NoError(t, configureConnection(ctx, conn))
	return owner
}

func (o *incomingMaterialUpgradeOutcomeOwner) closeSQL(t *testing.T) {
	t.Helper()
	if o.sqlClosed {
		return
	}
	o.sqlClosed = true
	var connErr, dbErr, lockErr error
	if o.conn != nil {
		connErr = o.conn.Close()
	}
	if o.db != nil {
		dbErr = o.db.Close()
	}
	if o.lock != nil {
		lockErr = o.lock.Close()
	}
	require.NoError(t, connErr)
	require.NoError(t, dbErr)
	require.NoError(t, lockErr)
}

func (o *incomingMaterialUpgradeOutcomeOwner) close(t *testing.T) {
	t.Helper()
	if o.closed {
		return
	}
	o.closed = true
	var connErr, dbErr, lockErr, rootErr error
	if !o.sqlClosed {
		o.sqlClosed = true
		if o.conn != nil {
			connErr = o.conn.Close()
		}
		if o.db != nil {
			dbErr = o.db.Close()
		}
		if o.lock != nil {
			lockErr = o.lock.Close()
		}
	}
	if o.rootFD >= 0 {
		rootErr = unix.Close(o.rootFD)
		o.rootFD = -1
	}
	require.NoError(t, connErr)
	require.NoError(t, dbErr)
	require.NoError(t, lockErr)
	require.NoError(t, rootErr)
}

type incomingMaterialUpgradeCommitCounter struct {
	calls int
}

func (c *incomingMaterialUpgradeCommitCounter) hook(candidate *sql.Tx) error {
	c.calls++
	return candidate.Commit()
}

func incomingMaterialUpgradeOutcomeCleanupStore(t *testing.T, store *Store) {
	t.Helper()
	if store == nil {
		return
	}
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
}

type incomingMaterialUpgradeOutcomeCase struct {
	image         string
	version       int
	directory     string
	databasePath  string
	binding       Binding
	limits        Limits
	attemptLimits AttemptLimits
	owner         *incomingMaterialUpgradeOutcomeOwner
	source        incomingMaterialUpgradeSource
	rows          map[string][][]any
	metadata      map[string][]byte
	objects       map[string]incomingMaterialUpgradeFixtureObject
	payload       incomingMaterialUpgradeFixturePayload
	payloads      map[string]incomingMaterialUpgradeFixturePayload
}

func incomingMaterialUpgradeOutcomePrepare(t *testing.T, ctx context.Context, image string) *incomingMaterialUpgradeOutcomeCase {
	t.Helper()
	switch image {
	case "positions-v1":
		return incomingMaterialUpgradeOutcomePrepareV1(t, ctx)
	case "pending-genesis", "mixed":
		return incomingMaterialUpgradeOutcomePrepareImage(t, ctx, image)
	default:
		require.FailNowf(t, "unsupported fixture image", "%q", image)
		return nil
	}
}

func incomingMaterialUpgradeOutcomePrepareV1(t *testing.T, ctx context.Context) *incomingMaterialUpgradeOutcomeCase {
	t.Helper()
	f, databasePath, companionRows := incomingMaterialUpgradeCopyV1(t)
	directory := filepath.Dir(databasePath)
	owner := incomingMaterialUpgradeOutcomeOpen(t, ctx, directory)
	require.Equal(t, 1, incomingMaterialUpgradeUserVersion(t, ctx, owner.conn))
	require.NoError(t, checkSchemaVersion(ctx, owner.conn, 1))
	require.Equal(t, companionRows, readLogicalRows(t, owner.conn))
	source, err := readIncomingMaterialUpgradeSource(ctx, owner.conn, 1, f.binding, DefaultLimits(), DefaultAttemptLimits())
	require.NoError(t, err)
	rows := incomingMaterialUpgradeV1Rows(t, ctx, owner.conn)
	require.Len(t, rows["store_meta"], 5)
	require.Len(t, rows["cache_records"], 3)
	require.Len(t, rows["cache_observations"], 1)
	require.Len(t, rows["accepted_records"], 2)
	require.Len(t, rows["accepted_events"], 2)
	require.Len(t, rows["active_floor"], 1)
	metadata := incomingMaterialUpgradeStoredMetadata(t, ctx, owner.conn)
	require.Len(t, metadata, 5)
	objects := incomingMaterialUpgradeFixtureObjects(t, ctx, owner.conn)
	require.Len(t, objects, 10)
	payload := incomingMaterialUpgradeFixturePayloadState(t, filepath.Join(directory, "schema1-baseline-payload.bin"))
	require.Equal(t, payload.bytes, f.payload)
	payloadCID, err := publication.RawPayloadCID(payload.bytes)
	require.NoError(t, err)
	payloadReference := publication.BlobReference{CID: payloadCID, Size: uint64(len(payload.bytes))}
	require.NoError(t, publication.VerifyPayload(payload.bytes, payloadReference))
	_, err = publication.DecodePayload(payload.bytes, payloadReference)
	require.NoError(t, err)
	return &incomingMaterialUpgradeOutcomeCase{
		image:         "positions-v1",
		version:       1,
		directory:     directory,
		databasePath:  databasePath,
		binding:       f.binding,
		limits:        DefaultLimits(),
		attemptLimits: DefaultAttemptLimits(),
		owner:         owner,
		source:        source,
		rows:          rows,
		metadata:      metadata,
		objects:       objects,
		payload:       payload,
	}
}

func incomingMaterialUpgradeOutcomePrepareImage(t *testing.T, ctx context.Context, name string) *incomingMaterialUpgradeOutcomeCase {
	t.Helper()
	assets := incomingMaterialUpgradeFixtureCopy(t)
	image := assets.manifest.requireImage(t, name)
	binding, limits, attemptLimits := incomingMaterialUpgradeFixtureBindingOptions(t, image)
	directory := filepath.Join(assets.root, name)
	databasePath := filepath.Join(directory, "publication.db")
	owner := incomingMaterialUpgradeOutcomeOpen(t, ctx, directory)
	require.Equal(t, 2, incomingMaterialUpgradeUserVersion(t, ctx, owner.conn))
	require.NoError(t, checkSchemaVersion(ctx, owner.conn, 2))
	source, err := readIncomingMaterialUpgradeSource(ctx, owner.conn, 2, binding, limits, attemptLimits)
	require.NoError(t, err)
	companionFile := "pending-genesis-rows.json"
	if name == "mixed" {
		companionFile = "mixed-rows.json"
	}
	companion := incomingMaterialUpgradeFixtureCompanionData(t, assets.files[companionFile])
	incomingMaterialUpgradeFixtureRequireCompanionHeader(t, ctx, owner.conn, companion)
	rows := incomingMaterialUpgradeFixtureRequireCompanionTables(t, ctx, owner.conn, companion)
	if name == "mixed" {
		require.Equal(t, 44, incomingMaterialUpgradeFixtureRowTotal(rows))
		inputs := incomingMaterialUpgradeFixtureInputsData(t, assets.files["mixed-inputs.json"])
		floorValue := incomingMaterialUpgradeFixtureScanValue(t, ctx, owner.conn, "SELECT floor FROM active_floor WHERE singleton=1")
		floorRaw, ok := floorValue.([]byte)
		require.True(t, ok)
		floor, err := decodeFloor(floorRaw)
		require.NoError(t, err)
		incomingMaterialUpgradeFixtureRequireMixedProjections(t, ctx, owner.conn, inputs, floor)
	} else {
		require.Equal(t, 14, incomingMaterialUpgradeFixtureRowTotal(rows))
	}
	metadata := incomingMaterialUpgradeStoredMetadata(t, ctx, owner.conn)
	require.Len(t, metadata, 7)
	objects := incomingMaterialUpgradeFixtureObjects(t, ctx, owner.conn)
	require.Len(t, objects, 31)
	payloads := incomingMaterialUpgradeFixturePayloadStates(t, assets.root)
	incomingMaterialUpgradeFixtureRequireImagePayloads(t, ctx, owner.conn, image, payloads)
	return &incomingMaterialUpgradeOutcomeCase{
		image:         name,
		version:       2,
		directory:     directory,
		databasePath:  databasePath,
		binding:       binding,
		limits:        limits,
		attemptLimits: attemptLimits,
		owner:         owner,
		source:        source,
		rows:          rows,
		metadata:      metadata,
		objects:       objects,
		payloads:      payloads,
	}
}

func incomingMaterialUpgradeOutcomeRequirePayloads(t *testing.T, c *incomingMaterialUpgradeOutcomeCase) {
	t.Helper()
	if c.version == 1 {
		require.Equal(t, c.payload, incomingMaterialUpgradeFixturePayloadState(t, filepath.Join(c.directory, "schema1-baseline-payload.bin")))
		return
	}
	require.Equal(t, c.payloads, incomingMaterialUpgradeFixturePayloadStates(t, filepath.Dir(c.directory)))
}

func incomingMaterialUpgradeOutcomeRequireCommitted(t *testing.T, ctx context.Context, q queryer, c *incomingMaterialUpgradeOutcomeCase) {
	t.Helper()
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, q))
	objects := incomingMaterialUpgradeFixtureObjects(t, ctx, q)
	counts := incomingMaterialUpgradeFixtureObjectCounts(t, objects)
	require.Equal(t, 16, counts.tables)
	require.Equal(t, 2, counts.namedIndexes)
	require.Equal(t, 14, counts.autoIndexes)
	require.Len(t, objects, 32)
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, q, "SELECT COUNT(*) FROM accepted_material_refs"))
	if c.version == 1 {
		afterRows := incomingMaterialUpgradeV1Rows(t, ctx, q)
		require.Len(t, afterRows["store_meta"], 7)
		for _, table := range []string{"cache_records", "cache_observations", "accepted_records", "accepted_events", "active_floor"} {
			assert.Equal(t, c.rows[table], afterRows[table], table)
		}
		afterMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, q)
		require.Len(t, afterMetadata, 7)
		for _, key := range []string{"binding", "database_id", "generation", "limits", "revision"} {
			require.Equal(t, c.metadata[key], afterMetadata[key], key)
		}
		wantedAttemptLimits, err := encodeAttemptLimits(DefaultAttemptLimits())
		require.NoError(t, err)
		require.Equal(t, wantedAttemptLimits, afterMetadata["attempt_limits"])
		require.Equal(t, uint64Bytes(0), afterMetadata["attempt_mutation_revision"])
		for _, table := range incomingMaterialUpgradeFixtureAttemptTables {
			require.Zero(t, incomingMaterialUpgradeCount(t, ctx, q, "SELECT COUNT(*) FROM "+table), table)
		}
		namedAdditions, autoIndexAdditions := incomingMaterialUpgradeFixtureObjectAdditions(t, c.objects, objects)
		expectedAdditions := append([]string{"accepted_material_refs"}, incomingMaterialUpgradeFixtureAttemptTables...)
		expectedAdditions = append(expectedAdditions, incomingMaterialUpgradeFixtureAttemptIndexes...)
		sort.Strings(expectedAdditions)
		require.Equal(t, expectedAdditions, namedAdditions)
		require.Equal(t, 10, autoIndexAdditions)
	} else {
		require.Equal(t, c.metadata, incomingMaterialUpgradeStoredMetadata(t, ctx, q))
		require.Equal(t, c.rows, incomingMaterialUpgradeFixtureTypedRows(t, ctx, q))
		namedAdditions, autoIndexAdditions := incomingMaterialUpgradeFixtureObjectAdditions(t, c.objects, objects)
		require.Equal(t, []string{"accepted_material_refs"}, namedAdditions)
		require.Zero(t, autoIndexAdditions)
	}
	require.Equal(t, incomingMaterialSchemaStatement, objects["accepted_material_refs"].sql)
	require.NoError(t, checkIncomingMaterialUpgradeDestination(ctx, q, c.source))
}

func incomingMaterialUpgradeOutcomeRequireRestored(t *testing.T, ctx context.Context, q queryer, c *incomingMaterialUpgradeOutcomeCase) {
	t.Helper()
	require.Equal(t, c.version, incomingMaterialUpgradeUserVersion(t, ctx, q))
	require.NoError(t, checkSchemaVersion(ctx, q, c.version))
	if c.version == 1 {
		require.Equal(t, c.rows, incomingMaterialUpgradeV1Rows(t, ctx, q))
	} else {
		require.Equal(t, c.rows, incomingMaterialUpgradeFixtureTypedRows(t, ctx, q))
	}
	require.Equal(t, c.metadata, incomingMaterialUpgradeStoredMetadata(t, ctx, q))
	require.Equal(t, c.objects, incomingMaterialUpgradeFixtureObjects(t, ctx, q))
	require.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, q))
	restored, err := readIncomingMaterialUpgradeSource(ctx, q, c.version, c.binding, c.limits, c.attemptLimits)
	require.NoError(t, err)
	require.Equal(t, c.source, restored)
}

func incomingMaterialUpgradeOutcomeFinish(t *testing.T, ctx context.Context, c *incomingMaterialUpgradeOutcomeCase, committed bool) {
	t.Helper()
	var rootStat unix.Stat_t
	require.NoError(t, unix.Fstat(c.owner.rootFD, &rootStat))
	require.Equal(t, uint32(unix.S_IFDIR), rootStat.Mode&unix.S_IFMT)
	if committed {
		incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, c.owner.conn, c)
	} else {
		incomingMaterialUpgradeOutcomeRequireRestored(t, ctx, c.owner.conn, c)
	}
	incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
	c.owner.close(t)
	incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
	readOnly, closeReadOnly := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, c.databasePath)
	if committed {
		incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, readOnly, c)
	} else {
		incomingMaterialUpgradeOutcomeRequireRestored(t, ctx, readOnly, c)
	}
	closeReadOnly(t)
	incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
}

func TestIncomingMaterialUpgradeCommitOutcomes(t *testing.T) {
	for _, image := range []string{"positions-v1", "pending-genesis", "mixed"} {
		for _, mode := range []string{"default hook", "observed hook", "commit then error", "rollback then commit"} {
			t.Run(image+" "+mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				t.Cleanup(cancel)
				c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
				canary := errors.New("injected commit outcome canary")
				var points []int
				var hookCalls int
				var hookTx *sql.Tx
				var commitErr error
				var hook func(*sql.Tx) error
				switch mode {
				case "default hook":
					hook = nil
				case "observed hook":
					hook = func(candidate *sql.Tx) error {
						hookTx = candidate
						hookCalls++
						return candidate.Commit()
					}
				case "commit then error":
					hook = func(candidate *sql.Tx) error {
						hookTx = candidate
						hookCalls++
						require.NoError(t, candidate.Commit())
						return canary
					}
				case "rollback then commit":
					hook = func(candidate *sql.Tx) error {
						hookTx = candidate
						hookCalls++
						require.NoError(t, candidate.Rollback())
						commitErr = candidate.Commit()
						return commitErr
					}
				}
				outcome, err := upgradeIncomingMaterial(ctx, c.owner.conn, c.source, c.owner.rootFD, func(point int) error {
					points = append(points, point)
					return nil
				}, hook)
				if c.version == 1 {
					require.Equal(t, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, points)
				} else {
					require.Equal(t, []int{13, 14, 15, 16}, points)
				}
				switch mode {
				case "default hook", "observed hook":
					require.Equal(t, incomingMaterialUpgradeCommitted, outcome)
					require.NoError(t, err)
				case "commit then error":
					require.Equal(t, incomingMaterialUpgradeCommitUnknown, outcome)
					requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonCommitUnknown)
					require.NotErrorIs(t, err, canary)
					require.NotContains(t, err.Error(), canary.Error())
				case "rollback then commit":
					require.Equal(t, incomingMaterialUpgradeCommitUnknown, outcome)
					requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonCommitUnknown)
					require.ErrorIs(t, commitErr, sql.ErrTxDone)
				}
				if hook != nil {
					require.Equal(t, 1, hookCalls)
					require.NotNil(t, hookTx)
				}
				if mode == "observed hook" || mode == "commit then error" {
					require.ErrorIs(t, hookTx.Rollback(), sql.ErrTxDone)
				}
				committed := mode != "rollback then commit"
				if committed {
					require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, c.owner.conn))
				} else {
					require.Equal(t, c.version, incomingMaterialUpgradeUserVersion(t, ctx, c.owner.conn))
				}
				incomingMaterialUpgradeOutcomeFinish(t, ctx, c, committed)
			})
		}
	}
}

func TestIncomingMaterialUpgradeWrapperRollback(t *testing.T) {
	canary := errors.New("injected wrapper fault canary")
	for point := 1; point <= 16; point++ {
		t.Run(fmt.Sprintf("positions v1 point %d", point), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			t.Cleanup(cancel)
			c := incomingMaterialUpgradeOutcomePrepare(t, ctx, "positions-v1")
			counter := &incomingMaterialUpgradeCommitCounter{}
			var points []int
			outcome, err := upgradeIncomingMaterial(ctx, c.owner.conn, c.source, c.owner.rootFD, func(reached int) error {
				points = append(points, reached)
				if reached == point {
					return canary
				}
				return nil
			}, counter.hook)
			require.Zero(t, counter.calls)
			require.Equal(t, incomingMaterialUpgradeNotAttempted, outcome)
			requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonIO)
			require.NotErrorIs(t, err, canary)
			require.NotContains(t, err.Error(), canary.Error())
			expected := make([]int, 0, point)
			for reached := 1; reached <= point; reached++ {
				expected = append(expected, reached)
			}
			require.Equal(t, expected, points)
			incomingMaterialUpgradeOutcomeFinish(t, ctx, c, false)
		})
	}
	for _, image := range []string{"pending-genesis", "mixed"} {
		for point := 13; point <= 16; point++ {
			t.Run(fmt.Sprintf("%s point %d", image, point), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				t.Cleanup(cancel)
				c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
				counter := &incomingMaterialUpgradeCommitCounter{}
				var points []int
				outcome, err := upgradeIncomingMaterial(ctx, c.owner.conn, c.source, c.owner.rootFD, func(reached int) error {
					points = append(points, reached)
					if reached == point {
						return canary
					}
					return nil
				}, counter.hook)
				require.Zero(t, counter.calls)
				require.Equal(t, incomingMaterialUpgradeNotAttempted, outcome)
				requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonIO)
				require.NotErrorIs(t, err, canary)
				require.NotContains(t, err.Error(), canary.Error())
				expected := make([]int, 0, point-12)
				for reached := 13; reached <= point; reached++ {
					expected = append(expected, reached)
				}
				require.Equal(t, expected, points)
				incomingMaterialUpgradeOutcomeFinish(t, ctx, c, false)
			})
		}
	}
}

func TestIncomingMaterialUpgradeWrapperPrecommitRefusals(t *testing.T) {
	for _, image := range []string{"positions-v1", "mixed"} {
		pointsThrough := func(limit int) []int {
			expected := make([]int, 0, limit)
			start := 1
			if image != "positions-v1" {
				start = 13
			}
			for reached := start; reached <= limit; reached++ {
				expected = append(expected, reached)
			}
			return expected
		}
		t.Run(image+" nil context", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			t.Cleanup(cancel)
			c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
			counter := &incomingMaterialUpgradeCommitCounter{}
			var points []int
			var nilContext context.Context
			outcome, err := upgradeIncomingMaterial(nilContext, c.owner.conn, c.source, c.owner.rootFD, func(point int) error {
				points = append(points, point)
				return nil
			}, counter.hook)
			require.Zero(t, counter.calls)
			require.Equal(t, incomingMaterialUpgradeNotAttempted, outcome)
			requireErrorMetadata(t, err, ErrInvalid, StageOpen, ReasonContext)
			require.Empty(t, points)
			incomingMaterialUpgradeOutcomeFinish(t, ctx, c, false)
		})
		t.Run(image+" canceled context", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			t.Cleanup(cancel)
			c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
			canceledContext, cancelRun := context.WithCancel(ctx)
			cancelRun()
			counter := &incomingMaterialUpgradeCommitCounter{}
			var points []int
			outcome, err := upgradeIncomingMaterial(canceledContext, c.owner.conn, c.source, c.owner.rootFD, func(point int) error {
				points = append(points, point)
				return nil
			}, counter.hook)
			require.Zero(t, counter.calls)
			require.Equal(t, incomingMaterialUpgradeNotAttempted, outcome)
			require.ErrorIs(t, err, context.Canceled)
			requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonCanceled)
			require.Empty(t, points)
			incomingMaterialUpgradeOutcomeFinish(t, ctx, c, false)
		})
		t.Run(image+" mismatched snapshot", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			t.Cleanup(cancel)
			c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
			stale := incomingMaterialUpgradeCloneSource(c.source)
			stale.metadata["database_id"] = append([]byte(nil), c.source.metadata["database_id"]...)
			stale.metadata["database_id"][0] ^= 0xff
			require.NotEqual(t, c.source.metadata["database_id"], stale.metadata["database_id"])
			counter := &incomingMaterialUpgradeCommitCounter{}
			var points []int
			outcome, err := upgradeIncomingMaterial(ctx, c.owner.conn, stale, c.owner.rootFD, func(point int) error {
				points = append(points, point)
				return nil
			}, counter.hook)
			require.Zero(t, counter.calls)
			require.Equal(t, incomingMaterialUpgradeNotAttempted, outcome)
			requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
			require.Empty(t, points)
			incomingMaterialUpgradeOutcomeFinish(t, ctx, c, false)
		})
		t.Run(image+" closed connection", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			t.Cleanup(cancel)
			c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
			c.owner.closeSQL(t)
			counter := &incomingMaterialUpgradeCommitCounter{}
			var points []int
			outcome, err := upgradeIncomingMaterial(ctx, c.owner.conn, c.source, c.owner.rootFD, func(point int) error {
				points = append(points, point)
				return nil
			}, counter.hook)
			require.Zero(t, counter.calls)
			require.Equal(t, incomingMaterialUpgradeNotAttempted, outcome)
			requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonIO)
			require.Empty(t, points)
			c.owner.close(t)
			incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
			readOnly, closeReadOnly := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, c.databasePath)
			incomingMaterialUpgradeOutcomeRequireRestored(t, ctx, readOnly, c)
			closeReadOnly(t)
			incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
		})
		t.Run(image+" negative root descriptor", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			t.Cleanup(cancel)
			c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
			counter := &incomingMaterialUpgradeCommitCounter{}
			var points []int
			outcome, err := upgradeIncomingMaterial(ctx, c.owner.conn, c.source, -1, func(point int) error {
				points = append(points, point)
				return nil
			}, counter.hook)
			require.Zero(t, counter.calls)
			require.Equal(t, incomingMaterialUpgradeNotAttempted, outcome)
			requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonIO)
			require.Equal(t, pointsThrough(15), points)
			incomingMaterialUpgradeOutcomeFinish(t, ctx, c, false)
		})
		t.Run(image+" cancel at destination point", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			t.Cleanup(cancel)
			c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
			counter := &incomingMaterialUpgradeCommitCounter{}
			operationContext, operationCancel := context.WithCancel(ctx)
			t.Cleanup(operationCancel)
			var points []int
			outcome, err := upgradeIncomingMaterial(operationContext, c.owner.conn, c.source, c.owner.rootFD, func(point int) error {
				points = append(points, point)
				if point == 15 {
					operationCancel()
				}
				return nil
			}, counter.hook)
			require.Zero(t, counter.calls)
			require.Equal(t, incomingMaterialUpgradeNotAttempted, outcome)
			require.ErrorIs(t, err, context.Canceled)
			requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonCanceled)
			require.Equal(t, pointsThrough(15), points)
			incomingMaterialUpgradeCanceledFinish(t, ctx, c)
		})
		t.Run(image+" cancel at root sync point", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			t.Cleanup(cancel)
			c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
			counter := &incomingMaterialUpgradeCommitCounter{}
			operationContext, operationCancel := context.WithCancel(ctx)
			t.Cleanup(operationCancel)
			var points []int
			outcome, err := upgradeIncomingMaterial(operationContext, c.owner.conn, c.source, c.owner.rootFD, func(point int) error {
				points = append(points, point)
				if point == 16 {
					operationCancel()
				}
				return nil
			}, counter.hook)
			require.Zero(t, counter.calls)
			require.Equal(t, incomingMaterialUpgradeNotAttempted, outcome)
			require.ErrorIs(t, err, context.Canceled)
			requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonCanceled)
			require.Equal(t, pointsThrough(16), points)
			incomingMaterialUpgradeCanceledFinish(t, ctx, c)
		})
	}
}

func TestIncomingMaterialUpgradePublicSchema3Boundary(t *testing.T) {
	t.Run("private committed schema three opens ordinarily", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		t.Cleanup(cancel)
		c := incomingMaterialUpgradeOutcomePrepare(t, ctx, "mixed")
		incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
		outcome, err := upgradeIncomingMaterial(ctx, c.owner.conn, c.source, c.owner.rootFD, nil, nil)
		require.Equal(t, incomingMaterialUpgradeCommitted, outcome)
		require.NoError(t, err)
		c.owner.close(t)
		incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
		store, err := Open(c.directory, c.binding)
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		require.NoError(t, err)
		require.NotNil(t, store)
		require.False(t, store.closed)
		require.Equal(t, 3, store.schemaVersion)
		require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, store.conn))
		require.NoError(t, checkSchema(ctx, store.conn))
		incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, store.conn, c)
		incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
		require.NoError(t, store.Close())
		readOnly, closeReadOnly := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, c.databasePath)
		incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, readOnly, c)
		closeReadOnly(t)
		incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
	})
	t.Run("inventory three accepted", func(t *testing.T) {
		inventory, err := schemaInventoryForVersion(3)
		require.NoError(t, err)
		require.Len(t, inventory.statements, 18)
		require.Len(t, inventory.objects, 18)
		require.Equal(t, expectedSchemaV2MetadataKeys(), inventory.metadataKeys)
	})
	t.Run("inventory four unsupported", func(t *testing.T) {
		inventory, err := schemaInventoryForVersion(4)
		require.ErrorIs(t, err, errSchemaMismatch)
		require.Equal(t, schemaInventory{}, inventory)
	})
}

func TestIncomingMaterialUpgradeOpenErrorMapping(t *testing.T) {
	canary := errors.New("injected mapper canary")
	schemaErr := classified(ErrSchema, StageOpen, ReasonCorrupt)
	bindingErr := classified(ErrInvalid, StageOpen, ReasonBinding)
	ioErr := classified(ErrStorage, StageOpen, ReasonIO)
	cancelErr := canceled(StageOpen, context.Canceled)

	t.Run("not attempted", func(t *testing.T) {
		require.NoError(t, incomingMaterialOpenError(incomingMaterialUpgradeNotAttempted, nil))
		mapped := incomingMaterialOpenError(incomingMaterialUpgradeNotAttempted, schemaErr)
		require.True(t, mapped == error(schemaErr))
		mapped = incomingMaterialOpenError(incomingMaterialUpgradeNotAttempted, bindingErr)
		require.True(t, mapped == error(bindingErr))
		mapped = incomingMaterialOpenError(incomingMaterialUpgradeNotAttempted, ioErr)
		require.True(t, mapped == error(ioErr))
		mapped = incomingMaterialOpenError(incomingMaterialUpgradeNotAttempted, cancelErr)
		require.True(t, mapped == error(cancelErr))
		require.ErrorIs(t, mapped, context.Canceled)
		mapped = incomingMaterialOpenError(incomingMaterialUpgradeNotAttempted, canary)
		require.ErrorIs(t, mapped, canary)
	})

	t.Run("commit unknown", func(t *testing.T) {
		requireErrorMetadata(t, incomingMaterialOpenError(incomingMaterialUpgradeCommitUnknown, nil), ErrStorage, StageOpen, ReasonCommitUnknown)
		for _, entry := range []struct {
			name string
			err  error
		}{
			{"schema", schemaErr},
			{"binding", bindingErr},
			{"storage", ioErr},
			{"canceled", cancelErr},
			{"canary", canary},
		} {
			mapped := incomingMaterialOpenError(incomingMaterialUpgradeCommitUnknown, entry.err)
			requireErrorMetadata(t, mapped, ErrStorage, StageOpen, ReasonCommitUnknown)
			require.NotErrorIs(t, mapped, canary)
			require.NotErrorIs(t, mapped, context.Canceled)
			require.NotContains(t, mapped.Error(), canary.Error())
		}
	})

	t.Run("committed", func(t *testing.T) {
		require.NoError(t, incomingMaterialOpenError(incomingMaterialUpgradeCommitted, nil))
		for _, entry := range []struct {
			name string
			err  error
		}{
			{"schema", schemaErr},
			{"binding", bindingErr},
			{"storage", ioErr},
			{"canceled", cancelErr},
			{"canary", canary},
		} {
			mapped := incomingMaterialOpenError(incomingMaterialUpgradeCommitted, entry.err)
			requireErrorMetadata(t, mapped, ErrStorage, StageOpen, ReasonCommitUnknown)
			require.NotErrorIs(t, mapped, canary)
			require.NotErrorIs(t, mapped, context.Canceled)
			require.NotContains(t, mapped.Error(), canary.Error())
		}
	})

	t.Run("undefined outcomes", func(t *testing.T) {
		for _, input := range []struct {
			name    string
			outcome incomingMaterialUpgradeOutcome
		}{
			{"minus one", incomingMaterialUpgradeOutcome(-1)},
			{"three", incomingMaterialUpgradeOutcome(3)},
		} {
			t.Run(input.name, func(t *testing.T) {
				requireErrorMetadata(t, incomingMaterialOpenError(input.outcome, nil), ErrStorage, StageOpen, ReasonCommitUnknown)
				for _, entry := range []struct {
					name string
					err  error
				}{
					{"schema", schemaErr},
					{"binding", bindingErr},
					{"storage", ioErr},
					{"canceled", cancelErr},
					{"canary", canary},
				} {
					mapped := incomingMaterialOpenError(input.outcome, entry.err)
					requireErrorMetadata(t, mapped, ErrStorage, StageOpen, ReasonCommitUnknown)
					require.NotErrorIs(t, mapped, canary)
					require.NotErrorIs(t, mapped, context.Canceled)
					require.NotContains(t, mapped.Error(), canary.Error())
					require.NotContains(t, fmt.Sprintf("%+v", mapped), canary.Error())
				}
			})
		}
	})
}

func TestIncomingMaterialUpgradeOpenCompletion(t *testing.T) {
	images := []string{"positions-v1", "pending-genesis", "mixed"}
	t.Run("successful private completion", func(t *testing.T) {
		for _, image := range images {
			t.Run(image, func(t *testing.T) {
				incomingMaterialUpgradeOpenSuccess(t, image)
			})
		}
	})
	t.Run("synthetic interval faults", func(t *testing.T) {
		for _, image := range images {
			for point := 1; point <= 4; point++ {
				t.Run(fmt.Sprintf("%s point %d", image, point), func(t *testing.T) {
					incomingMaterialUpgradeOpenIntervalFault(t, image, point)
				})
			}
		}
	})
	t.Run("destination schema postguard refusal", func(t *testing.T) {
		for _, image := range images {
			t.Run(image, func(t *testing.T) {
				incomingMaterialUpgradeOpenSchemaPostguard(t, image)
			})
		}
	})
	t.Run("final preflight refusal", func(t *testing.T) {
		for _, image := range images {
			t.Run(image, func(t *testing.T) {
				incomingMaterialUpgradeOpenFinalPreflight(t, image)
			})
		}
	})
	t.Run("completion context refusal", func(t *testing.T) {
		for _, mode := range []string{"nil", "canceled"} {
			t.Run(mode, func(t *testing.T) {
				incomingMaterialUpgradeOpenContextRefusal(t, "mixed", mode == "canceled")
			})
		}
	})
	t.Run("non committed outcome refusal", func(t *testing.T) {
		for _, image := range images {
			for _, input := range []struct {
				name    string
				outcome incomingMaterialUpgradeOutcome
			}{
				{"commit unknown", incomingMaterialUpgradeCommitUnknown},
				{"not attempted", incomingMaterialUpgradeNotAttempted},
				{"undefined minus one", incomingMaterialUpgradeOutcome(-1)},
				{"undefined three", incomingMaterialUpgradeOutcome(3)},
			} {
				t.Run(image+" "+input.name, func(t *testing.T) {
					incomingMaterialUpgradeOpenNonCommitted(t, image, input.outcome)
				})
			}
		}
	})
	t.Run("cancellation contrast", func(t *testing.T) {
		for _, point := range []int{1, 2} {
			t.Run(fmt.Sprintf("point %d", point), func(t *testing.T) {
				incomingMaterialUpgradeOpenCancellationPoint(t, "mixed", point)
			})
		}
	})
}

func incomingMaterialUpgradeOpenCommit(t *testing.T, ctx context.Context, c *incomingMaterialUpgradeOutcomeCase) {
	t.Helper()
	counter := &incomingMaterialUpgradeCommitCounter{}
	outcome, err := upgradeIncomingMaterial(ctx, c.owner.conn, c.source, c.owner.rootFD, nil, counter.hook)
	require.Equal(t, 1, counter.calls)
	require.Equal(t, incomingMaterialUpgradeCommitted, outcome)
	require.NoError(t, err)
}

func incomingMaterialUpgradeOpenOwn(t *testing.T, c *incomingMaterialUpgradeOutcomeCase) *Store {
	t.Helper()
	store := &Store{
		db:                c.owner.db,
		conn:              c.owner.conn,
		lock:              c.owner.lock,
		directory:         c.owner.directory,
		binding:           c.binding,
		limits:            c.limits,
		attemptLimits:     c.attemptLimits,
		rootFD:            c.owner.rootFD,
		payloadFD:         -1,
		schemaVersion:     c.version,
		custodyOps:        defaultCustodyOperations(),
		commitTransaction: func(tx *sql.Tx) error { return tx.Commit() },
	}
	incomingMaterialUpgradeOutcomeCleanupStore(t, store)
	c.owner.sqlClosed = true
	c.owner.closed = true
	return store
}

func incomingMaterialUpgradeOpenClosedResources(t *testing.T, ctx context.Context, c *incomingMaterialUpgradeOutcomeCase, returned, provisional *Store) os.FileMode {
	t.Helper()
	var rootStat unix.Stat_t
	require.ErrorIs(t, unix.Fstat(c.owner.rootFD, &rootStat), unix.EBADF)
	require.Nil(t, returned)
	require.True(t, provisional.closed)
	require.NoError(t, ctx.Err())
	require.ErrorIs(t, c.owner.conn.PingContext(ctx), sql.ErrConnDone)
	poolErr := c.owner.db.PingContext(ctx)
	require.NoError(t, ctx.Err())
	require.Error(t, poolErr)
	lockPath := filepath.Join(c.directory, "publication.db.lock")
	info, err := os.Lstat(lockPath)
	require.NoError(t, err)
	mode := info.Mode().Perm()
	lock, err := platform.LockFile(lockPath)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, lock.Close()) })
	require.NoError(t, lock.Close())
	return mode
}

func incomingMaterialUpgradeOpenPayload(t *testing.T, c *incomingMaterialUpgradeOutcomeCase, prefix string) []byte {
	t.Helper()
	for relative, payload := range c.payloads {
		if strings.HasPrefix(relative, prefix) {
			return payload.bytes
		}
	}
	require.FailNowf(t, "missing fixture payload", "%q", prefix)
	return nil
}

func incomingMaterialUpgradeOpenExpectedAdditions(t *testing.T, c *incomingMaterialUpgradeOutcomeCase, extra ...string) ([]string, int) {
	t.Helper()
	expected := append([]string{"accepted_material_refs"}, extra...)
	autoIndexes := 0
	if c.version == 1 {
		expected = append(expected, incomingMaterialUpgradeFixtureAttemptTables...)
		expected = append(expected, incomingMaterialUpgradeFixtureAttemptIndexes...)
		autoIndexes = 10
	}
	sort.Strings(expected)
	return expected, autoIndexes
}

func incomingMaterialUpgradeOpenHealthyReadback(t *testing.T, ctx context.Context, c *incomingMaterialUpgradeOutcomeCase) {
	t.Helper()
	conn, closeReadOnly := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, c.databasePath)
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, conn))
	incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, conn, c)
	closeReadOnly(t)
	incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
}

func incomingMaterialUpgradeCanceledFinish(t *testing.T, ctx context.Context, c *incomingMaterialUpgradeOutcomeCase) {
	t.Helper()
	incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
	var rootStat unix.Stat_t
	require.NoError(t, unix.Fstat(c.owner.rootFD, &rootStat))
	require.Equal(t, uint32(unix.S_IFDIR), rootStat.Mode&unix.S_IFMT)
	require.False(t, c.owner.closed)
	require.False(t, c.owner.sqlClosed)
	var connErr, dbErr, lockErr, rootErr error
	if c.owner.conn != nil {
		connErr = c.owner.conn.Close()
	}
	if c.owner.db != nil {
		dbErr = c.owner.db.Close()
	}
	if c.owner.lock != nil {
		lockErr = c.owner.lock.Close()
	}
	if c.owner.rootFD >= 0 {
		rootErr = unix.Close(c.owner.rootFD)
	}
	c.owner.closed = true
	c.owner.sqlClosed = true
	c.owner.rootFD = -1
	if connErr != nil && !errors.Is(connErr, sql.ErrConnDone) {
		require.NoError(t, connErr)
	}
	require.NoError(t, dbErr)
	require.NoError(t, lockErr)
	require.NoError(t, rootErr)
	incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
	readOnly, closeReadOnly := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, c.databasePath)
	incomingMaterialUpgradeOutcomeRequireRestored(t, ctx, readOnly, c)
	closeReadOnly(t)
	incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
}

func incomingMaterialUpgradeOpenRequireReadAPIs(t *testing.T, ctx context.Context, store *Store, c *incomingMaterialUpgradeOutcomeCase) {
	t.Helper()
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.False(t, history.HasMore)
	attempts, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	require.False(t, attempts.HasMore)
	switch c.image {
	case "positions-v1":
		require.True(t, present)
		require.Equal(t, uint64(2), floor.Revision)
		require.Equal(t, uint64(1), floor.Generation)
		require.Equal(t, uint64(1), floor.Sequence)
		require.Len(t, history.Events, 2)
		require.Len(t, history.Records, 2)
		require.Equal(t, uint64(2), history.NextRevision)
		require.Empty(t, attempts.Attempts)
		material, err := store.ReadAcceptedMaterial(ctx, c.binding, floor)
		require.Equal(t, AcceptedMaterial{}, material)
		requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonMaterialNotRetained)
	case "pending-genesis":
		require.False(t, present)
		require.Equal(t, zeroFloor(), floor)
		require.Empty(t, history.Events)
		require.Empty(t, history.Records)
		require.Equal(t, uint64(0), history.NextRevision)
		require.Len(t, attempts.Attempts, 1)
		require.Equal(t, AttemptGenesis, attempts.Attempts[0].Kind)
		require.Equal(t, AttemptPrepared, attempts.Attempts[0].Lifecycle)
		require.Equal(t, OutcomeNotSubmitted, attempts.Attempts[0].Outcome)
		pendingID := attempts.Attempts[0].ID
		require.Equal(t, [16]byte{0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x17}, pendingID)
		candidate, err := store.ReadCandidate(ctx, pendingID)
		require.NoError(t, err)
		require.Equal(t, pendingID, candidate.AttemptID)
		require.Equal(t, incomingMaterialUpgradeOpenPayload(t, c, "pending-genesis/payloads/"), candidate.Payload)
		require.Equal(t, uint64(3072), candidate.Blob.Size)
		require.NoError(t, publication.VerifyPayload(candidate.Payload, candidate.Blob))
		require.NotEmpty(t, candidate.SnapshotRecord)
		require.NotEmpty(t, candidate.HeadRecord)
		material, err := store.ReadAcceptedMaterial(ctx, c.binding, Floor{})
		require.Equal(t, AcceptedMaterial{}, material)
		requireErrorMetadata(t, err, ErrContinuity, StageReadAcceptedMaterial, ReasonFirstUseRequired)
	case "mixed":
		require.True(t, present)
		require.Equal(t, uint64(2), floor.Revision)
		require.Equal(t, uint64(2), floor.Generation)
		require.Equal(t, uint64(0), floor.Sequence)
		require.Len(t, history.Events, 2)
		require.Len(t, history.Records, 2)
		require.Equal(t, uint64(2), history.NextRevision)
		require.Len(t, attempts.Attempts, 3)
		var genesisID, abandonedID, activeID [16]byte
		for _, attempt := range attempts.Attempts {
			switch attempt.Lifecycle {
			case AttemptRetiredSuccess:
				genesisID = attempt.ID
			case AttemptRetiredAbandoned:
				abandonedID = attempt.ID
			case AttemptMayHaveSubmitted:
				activeID = attempt.ID
			}
		}
		require.NotEqual(t, [16]byte{}, genesisID)
		require.NotEqual(t, [16]byte{}, abandonedID)
		require.NotEqual(t, [16]byte{}, activeID)
		require.Equal(t, [16]byte{0x43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x18}, genesisID)
		require.Equal(t, [16]byte{0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x19}, abandonedID)
		require.Equal(t, [16]byte{0x49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1e}, activeID)
		activeCandidate, err := store.ReadCandidate(ctx, activeID)
		require.NoError(t, err)
		require.Equal(t, activeID, activeCandidate.AttemptID)
		require.Equal(t, incomingMaterialUpgradeOpenPayload(t, c, "mixed/payloads/30f2"), activeCandidate.Payload)
		require.Equal(t, uint64(3072), activeCandidate.Blob.Size)
		require.NoError(t, publication.VerifyPayload(activeCandidate.Payload, activeCandidate.Blob))
		retainedCandidate, err := store.ReadCandidate(ctx, genesisID)
		require.NoError(t, err)
		require.Equal(t, genesisID, retainedCandidate.AttemptID)
		require.Equal(t, incomingMaterialUpgradeOpenPayload(t, c, "mixed/payloads/dfaa"), retainedCandidate.Payload)
		require.NoError(t, publication.VerifyPayload(retainedCandidate.Payload, retainedCandidate.Blob))
		abandoned, err := store.LoadAttempt(ctx, abandonedID)
		require.NoError(t, err)
		require.Equal(t, AttemptRetiredAbandoned, abandoned.Lifecycle)
		require.Equal(t, OutcomeLostFence, abandoned.Outcome)
		require.Equal(t, "blocked-floor-replaced", abandoned.Blocked)
		require.NotEqual(t, [32]byte{}, abandoned.StateDigest)
		conflict, presentConflict, err := store.ReadFirstConflict(ctx, abandonedID)
		require.NoError(t, err)
		require.True(t, presentConflict)
		inputsData, readErr := os.ReadFile(filepath.Join(filepath.Dir(c.directory), "mixed-inputs.json"))
		require.NoError(t, readErr)
		inputs := incomingMaterialUpgradeFixtureInputsData(t, inputsData)
		require.Equal(t, abandonedID, conflict.AttemptID)
		var expectedConflictID [32]byte
		copy(expectedConflictID[:], incomingMaterialUpgradeFixtureDigestBytes(t, inputs.Results.FirstConflict.ID))
		require.Equal(t, expectedConflictID, conflict.ID)
		require.Equal(t, incomingMaterialUpgradeFixtureDigestBytes(t, inputs.Results.FirstConflict.Envelope), conflict.Evidence)
		require.Equal(t, incomingMaterialUpgradeFixtureDigestBytes(t, inputs.Results.FirstConflict.Head), conflict.Head)
		require.Equal(t, inputs.Results.FirstConflict.HeadKey, conflict.HeadKey)
		require.Equal(t, incomingMaterialUpgradeFixtureDigestBytes(t, inputs.Results.FirstConflict.HeadRecord), conflict.HeadRecord)
		require.Equal(t, uint64(1), conflict.HeadSequence)
		material, err := store.ReadAcceptedMaterial(ctx, c.binding, floor)
		require.Equal(t, AcceptedMaterial{}, material)
		requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonMaterialNotRetained)
	default:
		require.FailNowf(t, "unsupported fixture image", "%q", c.image)
	}
}

func incomingMaterialUpgradeOpenSuccess(t *testing.T, image string) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
	incomingMaterialUpgradeOpenCommit(t, ctx, c)
	store := incomingMaterialUpgradeOpenOwn(t, c)
	var points []int
	completed, err := completeIncomingMaterialUpgradeOpen(ctx, store, c.source, incomingMaterialUpgradeCommitted, func(point int) error {
		points = append(points, point)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, []int{1, 2, 3, 4}, points)
	require.NotNil(t, completed)
	require.Same(t, store, completed)
	require.False(t, completed.closed)
	require.Equal(t, 3, completed.schemaVersion)
	var expectedDatabaseID [32]byte
	copy(expectedDatabaseID[:], c.source.metadata["database_id"])
	require.Equal(t, expectedDatabaseID, completed.databaseID)
	expectedMutation := uint64(0)
	switch image {
	case "pending-genesis":
		expectedMutation = 1
	case "mixed":
		expectedMutation = 17
	}
	if c.version == 2 {
		require.Len(t, c.source.metadata["attempt_mutation_revision"], 8)
		require.Equal(t, expectedMutation, binary.BigEndian.Uint64(c.source.metadata["attempt_mutation_revision"]))
	}
	require.Equal(t, expectedMutation, completed.attemptMutationRevision)
	require.Equal(t, c.binding, completed.binding)
	require.Equal(t, c.limits, completed.limits)
	require.Equal(t, c.attemptLimits, completed.attemptLimits)
	require.Same(t, c.owner.conn, completed.conn)
	require.Equal(t, c.owner.rootFD, completed.rootFD)
	var rootStat unix.Stat_t
	require.NoError(t, unix.Fstat(completed.rootFD, &rootStat))
	require.Equal(t, uint32(unix.S_IFDIR), rootStat.Mode&unix.S_IFMT)
	require.NoError(t, checkIncomingMaterialUpgradeDestination(ctx, completed.conn, c.source))
	incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, completed.conn, c)
	incomingMaterialUpgradeOpenRequireReadAPIs(t, ctx, completed, c)
	incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
	payloadFD := completed.payloadFD
	require.NoError(t, completed.Close())
	var closedStat unix.Stat_t
	require.ErrorIs(t, unix.Fstat(c.owner.rootFD, &closedStat), unix.EBADF)
	if payloadFD >= 0 {
		require.ErrorIs(t, unix.Fstat(payloadFD, &closedStat), unix.EBADF)
	}
	require.ErrorIs(t, c.owner.conn.PingContext(ctx), sql.ErrConnDone)
	poolErr := c.owner.db.PingContext(ctx)
	require.NoError(t, ctx.Err())
	require.Error(t, poolErr)
	lock, err := platform.LockFile(filepath.Join(c.directory, "publication.db.lock"))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, lock.Close()) })
	require.NoError(t, lock.Close())
	incomingMaterialUpgradeOpenHealthyReadback(t, ctx, c)
}

func incomingMaterialUpgradeOpenIntervalFault(t *testing.T, image string, point int) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
	incomingMaterialUpgradeOpenCommit(t, ctx, c)
	store := incomingMaterialUpgradeOpenOwn(t, c)
	canary := errors.New("injected completion interval canary")
	var points []int
	completed, err := completeIncomingMaterialUpgradeOpen(ctx, store, c.source, incomingMaterialUpgradeCommitted, func(reached int) error {
		points = append(points, reached)
		if reached == point {
			return canary
		}
		return nil
	})
	require.Error(t, err)
	expected := make([]int, 0, point)
	for reached := 1; reached <= point; reached++ {
		expected = append(expected, reached)
	}
	require.Equal(t, expected, points)
	incomingMaterialUpgradeOpenClosedResources(t, ctx, c, completed, store)
	requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonCommitUnknown)
	require.NotErrorIs(t, err, canary)
	require.NotContains(t, err.Error(), canary.Error())
	incomingMaterialUpgradeOpenHealthyReadback(t, ctx, c)
}

func incomingMaterialUpgradeOpenSchemaPostguard(t *testing.T, image string) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
	counter := &incomingMaterialUpgradeCommitCounter{}
	var indexErr error
	outcome, err := upgradeIncomingMaterial(ctx, c.owner.conn, c.source, c.owner.rootFD, nil, func(candidate *sql.Tx) error {
		counter.calls++
		if commitErr := candidate.Commit(); commitErr != nil {
			return commitErr
		}
		_, indexErr = c.owner.conn.ExecContext(ctx, "CREATE INDEX incoming_material_postguard_extra ON accepted_records(sequence)")
		return indexErr
	})
	require.Equal(t, 1, counter.calls)
	require.NoError(t, indexErr)
	require.Equal(t, incomingMaterialUpgradeCommitted, outcome)
	require.NoError(t, err)
	store := incomingMaterialUpgradeOpenOwn(t, c)
	var points []int
	completed, err := completeIncomingMaterialUpgradeOpen(ctx, store, c.source, incomingMaterialUpgradeCommitted, func(point int) error {
		points = append(points, point)
		return nil
	})
	require.Error(t, err)
	require.Equal(t, []int{1}, points)
	incomingMaterialUpgradeOpenClosedResources(t, ctx, c, completed, store)
	requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonCommitUnknown)
	incomingMaterialUpgradeOpenRequireExtraIndexReadback(t, ctx, c, "incoming_material_postguard_extra")
}

func incomingMaterialUpgradeOpenFinalPreflight(t *testing.T, image string) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
	incomingMaterialUpgradeOpenCommit(t, ctx, c)
	store := incomingMaterialUpgradeOpenOwn(t, c)
	var points []int
	completed, err := completeIncomingMaterialUpgradeOpen(ctx, store, c.source, incomingMaterialUpgradeCommitted, func(point int) error {
		points = append(points, point)
		if point == 4 {
			require.NoError(t, os.Chmod(filepath.Join(c.directory, "publication.db.lock"), 0o640))
		}
		return nil
	})
	require.Error(t, err)
	require.Equal(t, []int{1, 2, 3, 4}, points)
	mode := incomingMaterialUpgradeOpenClosedResources(t, ctx, c, completed, store)
	require.Equal(t, os.FileMode(0o640), mode)
	requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonCommitUnknown)
	incomingMaterialUpgradeOpenHealthyReadback(t, ctx, c)
}

func incomingMaterialUpgradeOpenContextRefusal(t *testing.T, image string, canceledContext bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
	incomingMaterialUpgradeOpenCommit(t, ctx, c)
	store := incomingMaterialUpgradeOpenOwn(t, c)
	var completionContext context.Context
	if canceledContext {
		operationContext, operationCancel := context.WithCancel(ctx)
		operationCancel()
		t.Cleanup(operationCancel)
		completionContext = operationContext
	}
	var points []int
	completed, err := completeIncomingMaterialUpgradeOpen(completionContext, store, c.source, incomingMaterialUpgradeCommitted, func(point int) error {
		points = append(points, point)
		return nil
	})
	require.Error(t, err)
	incomingMaterialUpgradeOpenClosedResources(t, ctx, c, completed, store)
	require.Empty(t, points)
	requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonCommitUnknown)
	incomingMaterialUpgradeOpenHealthyReadback(t, ctx, c)
}

func incomingMaterialUpgradeOpenRequireExtraIndexReadback(t *testing.T, ctx context.Context, c *incomingMaterialUpgradeOutcomeCase, indexName string) {
	t.Helper()
	conn, closeReadOnly := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, c.databasePath)
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, conn))
	metadata := incomingMaterialUpgradeStoredMetadata(t, ctx, conn)
	if c.version == 1 {
		require.Len(t, metadata, 7)
		for _, key := range []string{"binding", "database_id", "generation", "limits", "revision"} {
			require.Equal(t, c.metadata[key], metadata[key], key)
		}
		attemptLimits, err := encodeAttemptLimits(c.attemptLimits)
		require.NoError(t, err)
		require.Equal(t, attemptLimits, metadata["attempt_limits"])
		require.Equal(t, uint64Bytes(0), metadata["attempt_mutation_revision"])
		for _, table := range incomingMaterialUpgradeFixtureAttemptTables {
			require.Zero(t, incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM "+table), table)
		}
	} else {
		require.Equal(t, c.metadata, metadata)
	}
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, conn))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	objects := incomingMaterialUpgradeFixtureObjects(t, ctx, conn)
	for name, object := range c.objects {
		observed, present := objects[name]
		require.True(t, present, name)
		require.Equal(t, object, observed, name)
	}
	expectedNamed, expectedAuto := incomingMaterialUpgradeOpenExpectedAdditions(t, c, indexName)
	namedAdditions, autoIndexAdditions := incomingMaterialUpgradeFixtureObjectAdditions(t, c.objects, objects)
	require.Equal(t, expectedNamed, namedAdditions)
	require.Equal(t, expectedAuto, autoIndexAdditions)
	require.Equal(t, "index", objects[indexName].kind)
	require.Equal(t, "CREATE INDEX incoming_material_postguard_extra ON accepted_records(sequence)", objects[indexName].sql)
	require.Equal(t, incomingMaterialSchemaStatement, objects["accepted_material_refs"].sql)
	if c.version == 1 {
		for _, statement := range attemptSchemaStatements {
			name := statementTableName(statement)
			observed, present := objects[name]
			require.True(t, present, name)
			require.Equal(t, statement, observed.sql, name)
		}
	}
	if c.version == 1 {
		afterRows := incomingMaterialUpgradeV1Rows(t, ctx, conn)
		for _, table := range []string{"cache_records", "cache_observations", "accepted_records", "accepted_events", "active_floor"} {
			require.Equal(t, c.rows[table], afterRows[table], table)
		}
	} else {
		require.Equal(t, c.rows, incomingMaterialUpgradeFixtureTypedRows(t, ctx, conn))
	}
	closeReadOnly(t)
	incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
}

func incomingMaterialUpgradeOpenNonCommitted(t *testing.T, image string, input incomingMaterialUpgradeOutcome) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
	incomingMaterialUpgradeOpenCommit(t, ctx, c)
	store := incomingMaterialUpgradeOpenOwn(t, c)
	var points []int
	completed, err := completeIncomingMaterialUpgradeOpen(ctx, store, c.source, input, func(point int) error {
		points = append(points, point)
		return nil
	})
	if completed != nil {
		incomingMaterialUpgradeOutcomeCleanupStore(t, completed)
	}
	incomingMaterialUpgradeOpenClosedResources(t, ctx, c, completed, store)
	requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonCommitUnknown)
	require.Empty(t, points)
	require.NotErrorIs(t, err, context.Canceled)
	incomingMaterialUpgradeOpenHealthyReadback(t, ctx, c)
}

func incomingMaterialUpgradeOpenCancellationPoint(t *testing.T, image string, point int) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
	incomingMaterialUpgradeOpenCommit(t, ctx, c)
	completionContext, completionCancel := context.WithCancel(ctx)
	t.Cleanup(completionCancel)
	store := incomingMaterialUpgradeOpenOwn(t, c)
	var points []int
	completed, err := completeIncomingMaterialUpgradeOpen(completionContext, store, c.source, incomingMaterialUpgradeCommitted, func(reached int) error {
		points = append(points, reached)
		if reached == point {
			completionCancel()
		}
		return nil
	})
	if completed != nil {
		incomingMaterialUpgradeOutcomeCleanupStore(t, completed)
	}
	require.ErrorIs(t, completionContext.Err(), context.Canceled)
	if point == 1 {
		require.Equal(t, []int{1}, points)
		require.Nil(t, completed)
		incomingMaterialUpgradeOpenClosedResources(t, ctx, c, completed, store)
		requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonCommitUnknown)
		incomingMaterialUpgradeOpenHealthyReadback(t, ctx, c)
		return
	}
	require.Equal(t, []int{1, 2, 3, 4}, points)
	require.NoError(t, err)
	require.NotNil(t, completed)
	require.Same(t, store, completed)
	require.False(t, completed.closed)
	require.Equal(t, 3, completed.schemaVersion)
	var expectedDatabaseID [32]byte
	copy(expectedDatabaseID[:], c.source.metadata["database_id"])
	require.Equal(t, expectedDatabaseID, completed.databaseID)
	require.Len(t, c.source.metadata["attempt_mutation_revision"], 8)
	expectedMutation := binary.BigEndian.Uint64(c.source.metadata["attempt_mutation_revision"])
	require.Equal(t, uint64(17), expectedMutation)
	require.Equal(t, expectedMutation, completed.attemptMutationRevision)
	require.Equal(t, c.binding, completed.binding)
	require.Equal(t, c.limits, completed.limits)
	require.Equal(t, c.attemptLimits, completed.attemptLimits)
	require.Same(t, c.owner.conn, completed.conn)
	require.Equal(t, c.owner.rootFD, completed.rootFD)
	require.NoError(t, checkIncomingMaterialUpgradeDestination(ctx, completed.conn, c.source))
	incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, completed.conn, c)
	incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
	payloadFD := completed.payloadFD
	require.NoError(t, completed.Close())
	var closedStat unix.Stat_t
	require.ErrorIs(t, unix.Fstat(c.owner.rootFD, &closedStat), unix.EBADF)
	if payloadFD >= 0 {
		require.ErrorIs(t, unix.Fstat(payloadFD, &closedStat), unix.EBADF)
	}
	require.ErrorIs(t, c.owner.conn.PingContext(ctx), sql.ErrConnDone)
	poolErr := c.owner.db.PingContext(ctx)
	require.NoError(t, ctx.Err())
	require.Error(t, poolErr)
	lock, err := platform.LockFile(filepath.Join(c.directory, "publication.db.lock"))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, lock.Close()) })
	require.NoError(t, lock.Close())
	incomingMaterialUpgradeOpenHealthyReadback(t, ctx, c)
}
