CREATE TABLE transition_attempts (
    id TEXT PRIMARY KEY,
    marker_collection TEXT NOT NULL,
    marker_rkey TEXT NOT NULL,
    expected_record_cid TEXT NOT NULL,
    candidate_blob_cid TEXT NOT NULL,
    epoch_seq INTEGER NOT NULL CHECK (epoch_seq >= 0),
    policy_digest TEXT NOT NULL,
    outcome TEXT NOT NULL,
    evidence TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX transition_attempts_outcome_created ON transition_attempts(outcome, created_at, id);
