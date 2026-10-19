CREATE TABLE audit_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL UNIQUE CHECK (length(operation_id)=32 AND operation_id NOT GLOB '*[^0-9a-f]*'),
    at_ms INTEGER NOT NULL CHECK (at_ms>=0),
    finished_at_ms INTEGER NOT NULL DEFAULT 0 CHECK (finished_at_ms>=0),
    category TEXT NOT NULL CHECK (category IN ('credential','sample','probe','route','transform','security','configuration','session','backup')),
    action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 64 AND action NOT GLOB '*[^a-z0-9_]*'),
    resource_type TEXT NOT NULL CHECK (length(resource_type) BETWEEN 1 AND 40 AND resource_type NOT GLOB '*[^a-z0-9_]*'),
    resource_id TEXT NOT NULL DEFAULT '' CHECK (length(resource_id)<=128 AND resource_id NOT GLOB '*[^a-zA-Z0-9_:.-]*'),
    actor_hash TEXT NOT NULL CHECK (length(actor_hash)=64 AND actor_hash NOT GLOB '*[^0-9a-f]*'),
    outcome TEXT NOT NULL DEFAULT 'pending' CHECK (outcome IN ('pending','succeeded','failed','unknown')),
    reason_code TEXT NOT NULL DEFAULT '' CHECK (length(reason_code)<=40 AND reason_code NOT GLOB '*[^a-z0-9_]*'),
    CHECK ((outcome='pending' AND finished_at_ms=0) OR (outcome!='pending' AND finished_at_ms>=at_ms))
);
CREATE INDEX idx_audit_event_category_id ON audit_event(category,id DESC);
CREATE INDEX idx_audit_event_action_id ON audit_event(action,id DESC);
CREATE INDEX idx_audit_event_at_id ON audit_event(at_ms,id DESC);
CREATE INDEX idx_audit_event_resource_id ON audit_event(resource_type,resource_id,id DESC);
