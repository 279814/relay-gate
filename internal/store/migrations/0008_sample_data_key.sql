-- Independent Data Keys: only these small wrappers change on Master rotation.
CREATE TABLE data_key (
    purpose TEXT PRIMARY KEY CHECK (purpose IN ('sample','security')),
    key_id TEXT NOT NULL UNIQUE,
    wrapped_key TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- Physical retention helpers; also ensured on existing schema-8 databases.
CREATE INDEX IF NOT EXISTS idx_probe_execution_calibration_run ON probe_execution(calibration_run_id) WHERE calibration_run_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_calibration_candidate_execution ON calibration_candidate(execution_id) WHERE execution_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_recipe_test_execution ON probe_recipe(last_test_execution_id) WHERE last_test_execution_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_profile_test_execution ON client_probe_profile(tested_execution_id) WHERE tested_execution_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_probe_execution_trigger_created ON probe_execution(trigger,created_at,id);
