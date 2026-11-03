CREATE TABLE retention_recovery_material (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    device_id TEXT NOT NULL CHECK (length(device_id) > 0),
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    snapshot_cid BLOB NOT NULL CHECK (length(snapshot_cid) BETWEEN 1 AND 128),
    payload_ref TEXT NOT NULL DEFAULT '',
    backup_ref TEXT NOT NULL DEFAULT '',
    inventory_complete INTEGER NOT NULL CHECK (inventory_complete IN (0, 1)),
    CHECK ((payload_ref = '' AND backup_ref = '') OR (payload_ref <> '' AND backup_ref = '') OR (payload_ref = '' AND backup_ref <> '')),
    CHECK (inventory_complete = 1 OR (payload_ref = '' AND backup_ref = '')),
    PRIMARY KEY (vault, device_id, epoch, snapshot_cid, payload_ref, backup_ref)
) WITHOUT ROWID;
INSERT INTO retention_recovery_material(vault, device_id, epoch, snapshot_cid, payload_ref, backup_ref, inventory_complete)
SELECT vault, device_id, epoch, snapshot_cid, '', '', 0 FROM retention_recovery_points;
