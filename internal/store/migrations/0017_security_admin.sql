ALTER TABLE security_finding ADD COLUMN upstream_id INTEGER NOT NULL DEFAULT 0 CHECK (upstream_id >= 0);
ALTER TABLE security_finding ADD COLUMN rule_id TEXT NOT NULL DEFAULT '' CHECK (length(CAST(rule_id AS BLOB)) <= 128);

CREATE TABLE security_finding_review (
    finding_id TEXT PRIMARY KEY NOT NULL REFERENCES security_finding(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','false_positive')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
);

CREATE TABLE security_ignore_rule (
    id INTEGER PRIMARY KEY AUTOINCREMENT CHECK (id > 0),
    scope TEXT NOT NULL CHECK (scope IN ('rule','route')),
    rule_id TEXT NOT NULL DEFAULT '' CHECK (length(CAST(rule_id AS BLOB)) <= 128),
    route_id INTEGER NOT NULL DEFAULT 0 CHECK (route_id >= 0),
    expires_at_ms INTEGER NOT NULL DEFAULT 0 CHECK (expires_at_ms >= 0),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    CHECK ((scope='rule' AND rule_id<>'' AND route_id=0) OR (scope='route' AND rule_id='' AND route_id>0))
);

CREATE INDEX idx_sec_finding_page ON security_finding(at_ms DESC,id DESC);
CREATE INDEX idx_sec_finding_upstream_page ON security_finding(upstream_id,at_ms DESC,id DESC);
CREATE INDEX idx_sec_finding_route_page ON security_finding(route_id,at_ms DESC,id DESC);
CREATE INDEX idx_sec_finding_rule_page ON security_finding(rule_id,at_ms DESC,id DESC);
CREATE INDEX idx_sec_review_state ON security_finding_review(status,finding_id);
CREATE INDEX idx_sec_ignore_rule_match ON security_ignore_rule(scope,enabled,rule_id,expires_at_ms,id);
CREATE INDEX idx_sec_ignore_route_match ON security_ignore_rule(scope,enabled,route_id,expires_at_ms,id);
