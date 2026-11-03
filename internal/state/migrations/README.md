# Migrations

Migration files use `NNNN_description.sql`, are embedded in the binary and are applied in ascending contiguous version order. Migration DDL and the corresponding `schema_version` insert/update are one transaction, followed by an in-transaction `PRAGMA foreign_key_check`.

Migration 1 has no table rebuild. SQLite's documented rebuild order for a future migration is: disable foreign-key enforcement outside a transaction; rebuild and check with `PRAGMA foreign_key_check` inside the transaction; commit; restore enforcement. The pragma is a no-op after `BEGIN`. Failed migrations roll back the DDL and version stamp together. The runner currently executes each migration body inside one transaction, performs the in-transaction `foreign_key_check` and the post-commit restore, but never the pre-`BEGIN` disable, so the first migration that needs a table rebuild must extend the runner to disable enforcement before `BEGIN` rather than attempting the pragma inside the transaction.

Migration 2 adds `transition_attempts` for the durable marker, expected record CID, candidate blob CID, epoch, policy digest, outcome and resolution evidence. It does not rebuild existing tables.

Migration 3 adds `vault_checkpoints`, one row per vault, retaining the control bytes and freshness fields needed for local rollback comparison. It does not rebuild existing tables.

Migration 4 adds `vault_publication_observations`, one row per vault, retaining the last authenticated epoch, publication count and head snapshot CID used for per-device replay detection. It does not rebuild existing tables.

Migration 7 adds the last authenticated control CID to `vault_publication_observations`; existing rows receive an empty value. The store now treats the observed control as immutable within an epoch, so an empty legacy value cannot be refreshed by a differing same-epoch observation or authorize a later epoch advance.

Migration 8 adds `vault_epoch_first_seen`, keyed by vault and epoch, with the caller-supplied Unix-seconds time when that epoch was first authenticated locally. Inserts are idempotent and never replace an existing timestamp; no epoch history is backfilled because its original time cannot be recovered.

Migration 9 adds current per-device retention declarations and recovery-point inventories, plus immutable declaration history. Migration 10 adds `retention_recovery_material`, associating payload and journal-backup references with recovery-point epochs and snapshot CIDs. Existing and newly declared points get an incomplete inventory marker; pruning refuses until a caller records a complete material inventory.
