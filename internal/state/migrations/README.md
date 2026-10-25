# Migrations

Migration files use `NNNN_description.sql`, are embedded in the binary and are applied in ascending contiguous version order. Migration DDL and the corresponding `schema_version` insert/update are one transaction, followed by an in-transaction `PRAGMA foreign_key_check`.

Migration 1 has no table rebuild. SQLite's documented rebuild order for a future migration is: disable foreign-key enforcement outside a transaction; rebuild and check with `PRAGMA foreign_key_check` inside the transaction; commit; restore enforcement. The pragma is a no-op after `BEGIN`. Failed migrations roll back the DDL and version stamp together. The runner currently executes each migration body inside one transaction, performs the in-transaction `foreign_key_check` and the post-commit restore, but never the pre-`BEGIN` disable, so the first migration that needs a table rebuild must extend the runner to disable enforcement before `BEGIN` rather than attempting the pragma inside the transaction.
