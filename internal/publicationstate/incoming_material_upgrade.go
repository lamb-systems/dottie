package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"strings"

	"golang.org/x/sys/unix"
)

type incomingMaterialUpgradeSource struct {
	version       int
	binding       Binding
	limits        Limits
	attemptLimits AttemptLimits
	metadata      map[string][]byte
}

func readIncomingMaterialUpgradeSource(ctx context.Context, q queryer, version int, binding Binding, limits Limits, attemptLimits AttemptLimits) (incomingMaterialUpgradeSource, error) {
	if ctx == nil {
		return incomingMaterialUpgradeSource{}, classified(ErrInvalid, StageOpen, ReasonContext)
	}
	if err := ctx.Err(); err != nil {
		return incomingMaterialUpgradeSource{}, canceled(StageOpen, err)
	}
	if validateBinding(binding) != nil {
		return incomingMaterialUpgradeSource{}, classified(ErrInvalid, StageOpen, ReasonBinding)
	}
	if validateLimits(limits) != nil || validateAttemptLimits(attemptLimits) != nil {
		return incomingMaterialUpgradeSource{}, classified(ErrInvalid, StageOpen, ReasonLimits)
	}
	if version != 1 && version != 2 {
		return incomingMaterialUpgradeSource{}, classified(ErrSchema, StageOpen, ReasonSchema)
	}
	if err := checkSchemaVersion(ctx, q, version); err != nil {
		return incomingMaterialUpgradeSource{}, schemaOrStorageError(ctx, StageOpen, err)
	}
	if err := compareMetadata(ctx, q, binding, limits); err != nil {
		return incomingMaterialUpgradeSource{}, err
	}
	keys := []string{"binding", "database_id", "generation", "limits", "revision"}
	if version == 2 {
		keys = []string{"attempt_limits", "attempt_mutation_revision", "binding", "database_id", "generation", "limits", "revision"}
	}
	metadata := make(map[string][]byte, len(keys))
	for _, key := range keys {
		bound := int64(16384)
		switch key {
		case "database_id":
			bound = 32
		case "attempt_mutation_revision", "generation", "revision":
			bound = 8
		}
		value, err := readValueBounded(ctx, q, key, bound)
		if err != nil {
			return incomingMaterialUpgradeSource{}, storedOrQueryError(ctx, StageOpen, err)
		}
		metadata[key] = value
	}
	var databaseID [32]byte
	if len(metadata["database_id"]) != 32 || allZero(metadata["database_id"]) {
		return incomingMaterialUpgradeSource{}, classified(ErrSchema, StageOpen, ReasonCorrupt)
	}
	copy(databaseID[:], metadata["database_id"])
	for _, key := range []string{"generation", "revision"} {
		if len(metadata[key]) != 8 {
			return incomingMaterialUpgradeSource{}, classified(ErrSchema, StageOpen, ReasonCorrupt)
		}
	}
	if version == 1 {
		if _, err := readStateForUpgrade(ctx, q, binding, limits); err != nil {
			var stateError *Error
			if errors.As(err, &stateError) {
				return incomingMaterialUpgradeSource{}, err
			}
			return incomingMaterialUpgradeSource{}, storageFailure(ctx, StageOpen, err)
		}
	} else {
		if err := checkAttemptMetadata(ctx, q, attemptLimits); err != nil {
			return incomingMaterialUpgradeSource{}, err
		}
		if len(metadata["attempt_mutation_revision"]) != 8 {
			return incomingMaterialUpgradeSource{}, classified(ErrSchema, StageOpen, ReasonCorrupt)
		}
		source := &Store{binding: binding, limits: limits, attemptLimits: attemptLimits, databaseID: databaseID, schemaVersion: 2}
		source.attemptMutationRevision = binary.BigEndian.Uint64(metadata["attempt_mutation_revision"])
		if _, err := source.readState(ctx, q, StageOpen); err != nil {
			var stateError *Error
			if errors.As(err, &stateError) {
				return incomingMaterialUpgradeSource{}, err
			}
			return incomingMaterialUpgradeSource{}, storageFailure(ctx, StageOpen, err)
		}
	}
	return incomingMaterialUpgradeSource{version: version, binding: binding, limits: limits, attemptLimits: attemptLimits, metadata: metadata}, nil
}

const (
	incomingMaterialUpgradeAttemptMetadataFault = 12
	incomingMaterialUpgradeIncomingTableFault   = 13
	incomingMaterialUpgradeUserVersionFault     = 14
	incomingMaterialUpgradeDestinationFault     = 15
)

func checkIncomingMaterialUpgradeSchema(ctx context.Context, q queryer) error {
	if ctx == nil {
		return classified(ErrInvalid, StageOpen, ReasonContext)
	}
	if err := ctx.Err(); err != nil {
		return canceled(StageOpen, err)
	}
	var appID, actual int
	if err := q.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID); err != nil {
		return storageFailure(ctx, StageOpen, err)
	}
	if err := q.QueryRowContext(ctx, "PRAGMA user_version").Scan(&actual); err != nil {
		return storageFailure(ctx, StageOpen, err)
	}
	if appID != applicationID || actual != 3 {
		return classified(ErrSchema, StageOpen, ReasonSchema)
	}
	objects, definitions, err := readSchemaObjects(ctx, q)
	if err != nil {
		return storageFailure(ctx, StageOpen, err)
	}
	inventory, err := schemaInventoryForVersion(2)
	if err != nil {
		return schemaOrStorageError(ctx, StageOpen, err)
	}
	expected := make(map[string]string, len(inventory.objects)+1)
	for name, kind := range inventory.objects {
		expected[name] = kind
	}
	expected[statementTableName(incomingMaterialSchemaStatement)] = "table"
	if !sameObjects(objects, expected) {
		return classified(ErrSchema, StageOpen, ReasonSchema)
	}
	for _, statement := range inventory.statements {
		if strings.TrimSpace(definitions[statementTableName(statement)]) != statement {
			return classified(ErrSchema, StageOpen, ReasonSchema)
		}
	}
	if strings.TrimSpace(definitions[statementTableName(incomingMaterialSchemaStatement)]) != incomingMaterialSchemaStatement {
		return classified(ErrSchema, StageOpen, ReasonSchema)
	}
	keys, err := readMetadataKeys(ctx, q)
	if err != nil {
		return storageFailure(ctx, StageOpen, err)
	}
	if !equalStrings(keys, inventory.metadataKeys) {
		return classified(ErrSchema, StageOpen, ReasonSchema)
	}
	return nil
}

func checkIncomingMaterialUpgradeDestination(ctx context.Context, q queryer, source incomingMaterialUpgradeSource) error {
	if ctx == nil {
		return classified(ErrInvalid, StageOpen, ReasonContext)
	}
	if err := ctx.Err(); err != nil {
		return canceled(StageOpen, err)
	}
	if validateBinding(source.binding) != nil {
		return classified(ErrInvalid, StageOpen, ReasonBinding)
	}
	if validateLimits(source.limits) != nil || validateAttemptLimits(source.attemptLimits) != nil {
		return classified(ErrInvalid, StageOpen, ReasonLimits)
	}
	if source.version != 1 && source.version != 2 {
		return classified(ErrSchema, StageOpen, ReasonSchema)
	}
	sourceKeys := []string{"binding", "database_id", "generation", "limits", "revision"}
	if source.version == 2 {
		sourceKeys = append(sourceKeys, "attempt_limits", "attempt_mutation_revision")
	}
	if len(source.metadata) != len(sourceKeys) {
		return classified(ErrSchema, StageOpen, ReasonCorrupt)
	}
	for _, key := range sourceKeys {
		value, present := source.metadata[key]
		if !present || value == nil {
			return classified(ErrSchema, StageOpen, ReasonCorrupt)
		}
	}
	if len(source.metadata["database_id"]) != 32 || allZero(source.metadata["database_id"]) {
		return classified(ErrSchema, StageOpen, ReasonCorrupt)
	}
	for _, key := range []string{"generation", "revision"} {
		if len(source.metadata[key]) != 8 {
			return classified(ErrSchema, StageOpen, ReasonCorrupt)
		}
	}
	if source.version == 2 {
		if len(source.metadata["attempt_mutation_revision"]) != 8 || len(source.metadata["attempt_limits"]) == 0 || len(source.metadata["attempt_limits"]) > 16384 {
			return classified(ErrSchema, StageOpen, ReasonCorrupt)
		}
	}
	if err := checkIncomingMaterialUpgradeSchema(ctx, q); err != nil {
		return err
	}
	if err := compareMetadata(ctx, q, source.binding, source.limits); err != nil {
		return err
	}
	if err := checkAttemptMetadata(ctx, q, source.attemptLimits); err != nil {
		return err
	}
	metadata := make(map[string][]byte, 7)
	for _, key := range []string{"attempt_limits", "attempt_mutation_revision", "binding", "database_id", "generation", "limits", "revision"} {
		bound := int64(16384)
		switch key {
		case "database_id":
			bound = 32
		case "attempt_mutation_revision", "generation", "revision":
			bound = 8
		}
		value, err := readValueBounded(ctx, q, key, bound)
		if err != nil {
			return storedOrQueryError(ctx, StageOpen, err)
		}
		metadata[key] = value
	}
	var databaseID [32]byte
	if len(metadata["database_id"]) != 32 || allZero(metadata["database_id"]) {
		return classified(ErrSchema, StageOpen, ReasonCorrupt)
	}
	copy(databaseID[:], metadata["database_id"])
	for _, key := range []string{"generation", "revision"} {
		if len(metadata[key]) != 8 {
			return classified(ErrSchema, StageOpen, ReasonCorrupt)
		}
	}
	for key, value := range source.metadata {
		if !bytes.Equal(metadata[key], value) {
			return classified(ErrSchema, StageOpen, ReasonCorrupt)
		}
	}
	if source.version == 1 {
		wantedAttemptLimits, err := encodeAttemptLimits(source.attemptLimits)
		if err != nil {
			return classified(ErrInvalid, StageOpen, ReasonLimits)
		}
		if !bytes.Equal(metadata["attempt_limits"], wantedAttemptLimits) || !bytes.Equal(metadata["attempt_mutation_revision"], uint64Bytes(0)) {
			return classified(ErrSchema, StageOpen, ReasonCorrupt)
		}
	}
	mutation := metadata["attempt_mutation_revision"]
	if len(mutation) != 8 {
		return classified(ErrSchema, StageOpen, ReasonCorrupt)
	}
	store := &Store{binding: source.binding, limits: source.limits, attemptLimits: source.attemptLimits, databaseID: databaseID, schemaVersion: 3}
	store.attemptMutationRevision = binary.BigEndian.Uint64(mutation)
	if _, err := store.readState(ctx, q, StageOpen); err != nil {
		var stateError *Error
		if errors.As(err, &stateError) {
			return err
		}
		return storageFailure(ctx, StageOpen, err)
	}
	return store.checkIncomingMaterialRefs(ctx, q, StageOpen)
}

func migrateIncomingMaterialTx(ctx context.Context, tx *sql.Tx, source incomingMaterialUpgradeSource, fault func(int) error) error {
	if ctx == nil {
		return classified(ErrInvalid, StageOpen, ReasonContext)
	}
	if err := ctx.Err(); err != nil {
		return canceled(StageOpen, err)
	}
	actual, err := readIncomingMaterialUpgradeSource(ctx, tx, source.version, source.binding, source.limits, source.attemptLimits)
	if err != nil {
		return err
	}
	if actual.version != source.version || len(actual.metadata) != len(source.metadata) {
		return classified(ErrSchema, StageOpen, ReasonCorrupt)
	}
	for key, value := range source.metadata {
		actualValue, present := actual.metadata[key]
		if !present || value == nil || !bytes.Equal(actualValue, value) {
			return classified(ErrSchema, StageOpen, ReasonCorrupt)
		}
	}
	if source.version == 1 {
		encodedLimits, err := encodeAttemptLimits(source.attemptLimits)
		if err != nil {
			return classified(ErrInvalid, StageOpen, ReasonLimits)
		}
		for index, statement := range attemptSchemaStatements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return storageFailure(ctx, StageOpen, err)
			}
			if fault != nil {
				if err := fault(index + 1); err != nil {
					return storageFailure(ctx, StageOpen, err)
				}
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO store_meta(key,value) VALUES ('attempt_limits',?),('attempt_mutation_revision',?)", encodedLimits, uint64Bytes(0)); err != nil {
			return storageFailure(ctx, StageOpen, err)
		}
		if fault != nil {
			if err := fault(incomingMaterialUpgradeAttemptMetadataFault); err != nil {
				return storageFailure(ctx, StageOpen, err)
			}
		}
	}
	if _, err := tx.ExecContext(ctx, incomingMaterialSchemaStatement); err != nil {
		return storageFailure(ctx, StageOpen, err)
	}
	if fault != nil {
		if err := fault(incomingMaterialUpgradeIncomingTableFault); err != nil {
			return storageFailure(ctx, StageOpen, err)
		}
	}
	if _, err := tx.ExecContext(ctx, "PRAGMA user_version=3"); err != nil {
		return storageFailure(ctx, StageOpen, err)
	}
	if fault != nil {
		if err := fault(incomingMaterialUpgradeUserVersionFault); err != nil {
			return storageFailure(ctx, StageOpen, err)
		}
	}
	if err := checkIncomingMaterialUpgradeDestination(ctx, tx, source); err != nil {
		return err
	}
	if fault != nil {
		if err := fault(incomingMaterialUpgradeDestinationFault); err != nil {
			return storageFailure(ctx, StageOpen, err)
		}
	}
	return nil
}

type incomingMaterialUpgradeOutcome int

const (
	incomingMaterialUpgradeNotAttempted incomingMaterialUpgradeOutcome = iota
	incomingMaterialUpgradeCommitUnknown
	incomingMaterialUpgradeCommitted
)

const incomingMaterialUpgradeRootSyncFault = 16

func upgradeIncomingMaterial(ctx context.Context, conn *sql.Conn, source incomingMaterialUpgradeSource, rootFD int, fault func(int) error, commitHook func(*sql.Tx) error) (incomingMaterialUpgradeOutcome, error) {
	if ctx == nil {
		return incomingMaterialUpgradeNotAttempted, classified(ErrInvalid, StageOpen, ReasonContext)
	}
	if err := ctx.Err(); err != nil {
		return incomingMaterialUpgradeNotAttempted, canceled(StageOpen, err)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return incomingMaterialUpgradeNotAttempted, storageFailure(ctx, StageOpen, err)
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback()
		}
	}()
	if err := migrateIncomingMaterialTx(ctx, tx, source, fault); err != nil {
		return incomingMaterialUpgradeNotAttempted, err
	}
	if err := ctx.Err(); err != nil {
		return incomingMaterialUpgradeNotAttempted, canceled(StageOpen, err)
	}
	if err := unix.Fsync(rootFD); err != nil {
		return incomingMaterialUpgradeNotAttempted, storageFailure(ctx, StageOpen, err)
	}
	if fault != nil {
		if err := fault(incomingMaterialUpgradeRootSyncFault); err != nil {
			return incomingMaterialUpgradeNotAttempted, storageFailure(ctx, StageOpen, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return incomingMaterialUpgradeNotAttempted, canceled(StageOpen, err)
	}
	commit := commitHook
	if commit == nil {
		commit = func(tx *sql.Tx) error { return tx.Commit() }
	}
	outcome := incomingMaterialUpgradeCommitUnknown
	if err := commit(tx); err != nil {
		return outcome, classified(ErrStorage, StageOpen, ReasonCommitUnknown)
	}
	rollback = false
	return incomingMaterialUpgradeCommitted, nil
}
