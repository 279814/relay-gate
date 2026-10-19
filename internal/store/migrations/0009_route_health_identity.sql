-- schema 9: bound RouteHealth negatives and cooldown survive cold restart.
ALTER TABLE route_health ADD COLUMN cooldown_until INTEGER NOT NULL DEFAULT 0;
ALTER TABLE route_health ADD COLUMN dead_since INTEGER NOT NULL DEFAULT 0;
ALTER TABLE route_health ADD COLUMN recovery_required INTEGER NOT NULL DEFAULT 0 CHECK (recovery_required IN (0,1));
ALTER TABLE route_health ADD COLUMN identity_json TEXT NOT NULL DEFAULT '';
