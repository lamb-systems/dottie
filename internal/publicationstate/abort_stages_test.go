package publicationstate

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAcceptRollsBackOnFloorAndMetadataAbort(t *testing.T) {
	for _, test := range []struct{ name, create, drop, canary string }{
		{name: "floor", create: "CREATE TEMP TRIGGER fail_floor BEFORE INSERT ON main.active_floor BEGIN SELECT RAISE(ABORT,'floor-stage-canary'); END", drop: "DROP TRIGGER fail_floor", canary: "floor-stage-canary"},
		{name: "metadata", create: "CREATE TEMP TRIGGER fail_revision BEFORE UPDATE ON main.store_meta WHEN OLD.key='revision' BEGIN SELECT RAISE(ABORT,'metadata-stage-canary'); END", drop: "DROP TRIGGER fail_revision", canary: "metadata-stage-canary"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, dir := newStore(t, f)
			observation := f.observation(1)
			proposal := prepareFirstUse(t, store, observation, f.payload)
			_, err := store.RecordObservation(ctx, observation)
			require.NoError(t, err)
			before := readLogicalRows(t, store.conn)
			_, err = store.conn.ExecContext(ctx, test.create)
			require.NoError(t, err)
			floor, err := store.Accept(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
			requireErrorMetadata(t, err, ErrStorage, StageAccept, ReasonIO)
			assert.Equal(t, Floor{}, floor)
			assertErrorRedacted(t, err, test.canary)
			assert.Equal(t, before, readLogicalRows(t, store.conn))
			_, err = store.conn.ExecContext(ctx, test.drop)
			require.NoError(t, err)
			require.NoError(t, store.Close())
			reopened, err := Open(dir, f.binding)
			require.NoError(t, err)
			_, present, err := reopened.Load(ctx)
			require.NoError(t, err)
			assert.False(t, present)
			_, err = reopened.Accept(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
			require.NoError(t, err)
			require.NoError(t, reopened.Close())
		})
	}
}
