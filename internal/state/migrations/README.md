# Migrations

Migration files use `NNNN_description.sql`, are embedded in the binary and are applied in ascending contiguous version order. For each migration, the runner disables foreign-key enforcement before `BEGIN`, runs DDL and the corresponding `schema_version` insert/update in one transaction, performs `PRAGMA foreign_key_check` inside that transaction, commits, then restores enforcement. Failed migrations roll back the DDL and version stamp together before enforcement is restored. `PRAGMA foreign_keys=OFF` inside a transaction has no effect.

Migration 2 adds `transition_attempts` for the durable marker, expected record CID, candidate blob CID, epoch, policy digest, outcome and resolution evidence. It does not rebuild existing tables.

Migration 3 adds `vault_checkpoints`, one row per vault, retaining the control bytes and freshness fields needed for local rollback comparison. It does not rebuild existing tables.

Migration 4 adds `vault_publication_observations`, one row per vault, retaining the last authenticated epoch, publication count and head snapshot CID used for per-device replay detection. It does not rebuild existing tables.

Migration 7 adds the last authenticated control CID to `vault_publication_observations`; existing rows receive an empty value. The store now treats the observed control as immutable within an epoch, so an empty legacy value cannot be refreshed by a differing same-epoch observation or authorize a later epoch advance.

Migration 8 adds `vault_epoch_first_seen`, keyed by vault and epoch, with the caller-supplied Unix-seconds time when that epoch was first authenticated locally. Inserts are idempotent and never replace an existing timestamp; no epoch history is backfilled because its original time cannot be recovered.

Migration 9 adds current per-device retention declarations and recovery-point inventories, plus immutable declaration history. Migration 10 adds `retention_recovery_material`, associating payload and journal-backup references with recovery-point epochs and snapshot CIDs. Existing and newly declared points get an incomplete inventory marker; pruning refuses until a caller records a complete material inventory.

Migration 11 adds `authenticated_position_evidence`, keyed by vault, epoch and policy digest, plus an ordered certificate child table. It stores signed policy/control/head bytes, the encrypted snapshot envelope, certificates and an optional checkpoint position. It does not store plaintext snapshot content, keys, kits or credentials, and does not rebuild existing tables. Migration 14 rebuilds current and historical position evidence and certificate children without retaining envelope ciphertext; verified remote fetches provide historical bodies when required.

Migration 12 adds `vault_selections`, keyed by `(vault, device_id)`, with a caller-supplied Unix-seconds recording time. It contains no secrets, anchor or tokens and does not rebuild existing tables.

Migration 13 adds append-only authenticated position history keyed by `(vault, epoch, policy_digest, head snapshot CID)` and ordered certificate rows. It retains optional kit-signed checkpoint-position bytes without storing the kit. Existing latest-position rows are preserved and remain queryable; prior overwritten heads cannot be backfilled.

Migration 14 removes `snapshot_bytes` from both current and historical authenticated-position tables and their certificate children while preserving all remaining rows and columns. It adds `policy_digest` and `control_cid` to current and historical retention point rows. Existing declaration digests remain version 1 and are checked with their original point fields; newly authenticated declarations use version 2 digests that include the per-point bindings. Existing current point inventories are incomplete until a newly authenticated declaration supplies bindings. The empty control CID marks an unknown legacy binding and cannot authorize retention operations.

Migration 15 adds the vault, epoch, snapshot CID, policy digest and control CID binding to `apply_journal`. Legacy journal rows have no binding and must remain ineligible for age-based deletion; any bound backup is likewise protected even if no retention-material association was committed.
