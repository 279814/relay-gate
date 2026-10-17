package store

import (
	"context"
	"database/sql"
	"strings"
)

// Physical helpers only: existing schema-8 databases receive these while the
// instance lock is held, before listeners. Read-only backup validation never
// calls this. Keep the new-database definitions in migration 8 identical.
const probeRetentionIndexes = `
CREATE INDEX IF NOT EXISTS idx_probe_execution_calibration_run ON probe_execution(calibration_run_id) WHERE calibration_run_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_calibration_candidate_execution ON calibration_candidate(execution_id) WHERE execution_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_recipe_test_execution ON probe_recipe(last_test_execution_id) WHERE last_test_execution_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_profile_test_execution ON client_probe_profile(tested_execution_id) WHERE tested_execution_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_probe_execution_trigger_created ON probe_execution(trigger,created_at,id);
`

func ensureProbeRetentionIndexes(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, probeRetentionIndexes); err != nil {
		return err
	}
	return tx.Commit()
}

// Accept only exact known physical helpers over an otherwise byte-for-byte
// known schema-8 catalog. The caller still returns the full physical hash,
// so backup manifests distinguish the old and indexed layouts precisely.
func knownSchemaEightWithRetentionIndexes(catalog []schemaCatalogRow) bool {
	definitions := make(map[string]schemaCatalogRow)
	for _, ddl := range strings.Split(probeRetentionIndexes, ";") {
		ddl = normalizeSchemaStatement(strings.Replace(ddl, "IF NOT EXISTS ", "", 1))
		if ddl == "" {
			continue
		}
		parts := strings.Fields(ddl)
		name := parts[2]
		table, _, _ := strings.Cut(parts[4], "(")
		definitions[name] = schemaCatalogRow{objectType: "index", name: name, table: table, statement: ddl}
	}
	base := make([]schemaCatalogRow, 0, len(catalog))
	matched := 0
	for _, row := range catalog {
		if expected, ok := definitions[row.name]; ok {
			if row != expected {
				return false
			}
			matched++
			continue
		}
		base = append(base, row)
	}
	return matched == len(definitions) && schemaVersionFingerprintKnown(8, schemaCatalogFingerprint(base))
}
