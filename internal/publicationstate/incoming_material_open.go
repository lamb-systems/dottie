package publicationstate

import (
	"context"
	"encoding/binary"
	"math"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const (
	incomingMaterialOpenDestinationFault = 1
	incomingMaterialOpenSidecarsFault    = 2
	incomingMaterialOpenRootSyncFault    = 3
	incomingMaterialOpenPreflightFault   = 4
)

func incomingMaterialOpenError(outcome incomingMaterialUpgradeOutcome, err error) error {
	switch outcome {
	case incomingMaterialUpgradeNotAttempted:
		return err
	case incomingMaterialUpgradeCommitUnknown:
		return classified(ErrStorage, StageOpen, ReasonCommitUnknown)
	case incomingMaterialUpgradeCommitted:
		if err == nil {
			return nil
		}
		return classified(ErrStorage, StageOpen, ReasonCommitUnknown)
	}
	return classified(ErrStorage, StageOpen, ReasonCommitUnknown)
}

func completeIncomingMaterialUpgradeOpen(ctx context.Context, owned *Store, source incomingMaterialUpgradeSource, outcome incomingMaterialUpgradeOutcome, fault func(int) error) (*Store, error) {
	transferred := false
	defer func() {
		if !transferred && owned != nil {
			_ = owned.Close()
		}
	}()
	if outcome != incomingMaterialUpgradeCommitted {
		return nil, classified(ErrStorage, StageOpen, ReasonCommitUnknown)
	}
	if ctx == nil {
		return nil, incomingMaterialOpenError(outcome, classified(ErrInvalid, StageOpen, ReasonContext))
	}
	if err := ctx.Err(); err != nil {
		return nil, incomingMaterialOpenError(outcome, canceled(StageOpen, err))
	}
	if fault != nil {
		if err := fault(incomingMaterialOpenDestinationFault); err != nil {
			return nil, incomingMaterialOpenError(outcome, storageFailure(ctx, StageOpen, err))
		}
	}
	if err := checkIncomingMaterialUpgradeDestination(ctx, owned.conn, source); err != nil {
		return nil, incomingMaterialOpenError(outcome, err)
	}
	databaseID, err := readValueBounded(ctx, owned.conn, "database_id", 32)
	if err != nil || len(databaseID) != 32 || allZero(databaseID) {
		return nil, incomingMaterialOpenError(outcome, classified(ErrSchema, StageOpen, ReasonCorrupt))
	}
	mutation, err := readValueBounded(ctx, owned.conn, "attempt_mutation_revision", 8)
	if err != nil || len(mutation) != 8 || binary.BigEndian.Uint64(mutation) > math.MaxInt64 {
		return nil, incomingMaterialOpenError(outcome, classified(ErrSchema, StageOpen, ReasonCorrupt))
	}
	copy(owned.databaseID[:], databaseID)
	owned.attemptMutationRevision = binary.BigEndian.Uint64(mutation)
	owned.schemaVersion = 3
	if fault != nil {
		if err := fault(incomingMaterialOpenSidecarsFault); err != nil {
			return nil, incomingMaterialOpenError(outcome, storageFailure(ctx, StageOpen, err))
		}
	}
	if err := secureCreatedSidecars(owned.directory); err != nil {
		return nil, incomingMaterialOpenError(outcome, classified(ErrStorage, StageOpen, ReasonIO))
	}
	if fault != nil {
		if err := fault(incomingMaterialOpenRootSyncFault); err != nil {
			return nil, incomingMaterialOpenError(outcome, storageFailure(ctx, StageOpen, err))
		}
	}
	if err := unix.Fsync(owned.rootFD); err != nil {
		return nil, incomingMaterialOpenError(outcome, classified(ErrStorage, StageOpen, ReasonIO))
	}
	if fault != nil {
		if err := fault(incomingMaterialOpenPreflightFault); err != nil {
			return nil, incomingMaterialOpenError(outcome, storageFailure(ctx, StageOpen, err))
		}
	}
	for _, name := range []string{"publication.db.lock", "publication.db", "publication.db-wal", "publication.db-shm"} {
		if err := preflightFile(filepath.Join(owned.directory, name)); err != nil {
			return nil, incomingMaterialOpenError(outcome, classified(ErrInvalid, StageOpen, ReasonBinding))
		}
	}
	transferred = true
	return owned, nil
}
