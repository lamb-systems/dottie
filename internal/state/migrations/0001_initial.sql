CREATE TABLE schema_version (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    version INTEGER NOT NULL CHECK (version >= 0)
);
CREATE TABLE targets (
    target_id TEXT PRIMARY KEY,
    descriptor_version INTEGER NOT NULL,
    source TEXT NOT NULL,
    source_version INTEGER NOT NULL,
    logical_base TEXT NOT NULL,
    logical_path TEXT NOT NULL,
    kind TEXT NOT NULL,
    mode TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE applied_base (
    target_id TEXT NOT NULL,
    source TEXT NOT NULL,
    file_path TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    settings_path TEXT NOT NULL,
    setting_key TEXT NOT NULL,
    entry_state TEXT NOT NULL,
    kind TEXT NOT NULL,
    mode INTEGER NOT NULL,
    link_target TEXT NOT NULL,
    value_type TEXT NOT NULL,
    value_text TEXT NOT NULL,
    size INTEGER NOT NULL,
    digest TEXT NOT NULL,
    payload_ref TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (target_id, source, file_path, schema_id, settings_path, setting_key),
    FOREIGN KEY (target_id) REFERENCES targets(target_id)
);
CREATE TABLE outbound_intent (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    source TEXT NOT NULL,
    file_path TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    settings_path TEXT NOT NULL,
    setting_key TEXT NOT NULL,
    payload_ref TEXT NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(target_id)
);
CREATE TABLE conflicts (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    source TEXT NOT NULL,
    file_path TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    settings_path TEXT NOT NULL,
    setting_key TEXT NOT NULL,
    local_payload_ref TEXT NOT NULL,
    remote_payload_ref TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(target_id)
);
CREATE TABLE checkpoints (
    id TEXT PRIMARY KEY,
    counter INTEGER NOT NULL,
    cid TEXT NOT NULL,
    recorded_at INTEGER NOT NULL
);
CREATE TABLE apply_journal (
    id TEXT PRIMARY KEY,
    operation TEXT NOT NULL,
    state TEXT NOT NULL,
    target_id TEXT NOT NULL,
    source TEXT NOT NULL,
    file_path TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    settings_path TEXT NOT NULL,
    setting_key TEXT NOT NULL,
    preimage_state TEXT NOT NULL,
    preimage_kind TEXT NOT NULL,
    preimage_mode INTEGER NOT NULL,
    preimage_link_target TEXT NOT NULL,
    preimage_value_type TEXT NOT NULL,
    preimage_value_text TEXT NOT NULL,
    preimage_size INTEGER NOT NULL,
    preimage_digest TEXT NOT NULL,
    postimage_state TEXT NOT NULL,
    postimage_kind TEXT NOT NULL,
    postimage_mode INTEGER NOT NULL,
    postimage_link_target TEXT NOT NULL,
    postimage_value_type TEXT NOT NULL,
    postimage_value_text TEXT NOT NULL,
    postimage_size INTEGER NOT NULL,
    postimage_digest TEXT NOT NULL,
    backup_ref TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(target_id)
);
CREATE INDEX applied_base_target_recorded ON applied_base(target_id, recorded_at);
CREATE INDEX outbound_intent_target_state ON outbound_intent(target_id, state);
CREATE INDEX conflicts_target_state ON conflicts(target_id, state);
CREATE INDEX apply_journal_target_state ON apply_journal(target_id, state);
