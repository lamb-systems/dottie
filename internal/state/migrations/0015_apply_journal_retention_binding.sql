ALTER TABLE apply_journal ADD COLUMN vault BLOB;
ALTER TABLE apply_journal ADD COLUMN epoch INTEGER;
ALTER TABLE apply_journal ADD COLUMN snapshot_cid BLOB;
ALTER TABLE apply_journal ADD COLUMN policy_digest BLOB;
ALTER TABLE apply_journal ADD COLUMN control_cid BLOB;
ALTER TABLE apply_journal ADD COLUMN retention_binding_version INTEGER NOT NULL DEFAULT 0 CHECK (retention_binding_version IN (0, 1));
