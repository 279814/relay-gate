-- Independent Data Keys: only these small wrappers change on Master rotation.
CREATE TABLE data_key (
    purpose TEXT PRIMARY KEY CHECK (purpose IN ('sample','security')),
    key_id TEXT NOT NULL UNIQUE,
    wrapped_key TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
