package store

import (
	"context"
	"database/sql"
	"fmt"
)

// Run before any detach in the immediate deletion transaction. Routes are
// independent configuration; historical rows must retain their original owner.
func requireEntityDeleteUnreferenced(ctx context.Context, tx *sql.Tx, kind string, id int64) error {
	var query string
	switch kind {
	case "route":
		query = `WITH target(id) AS (VALUES (?)) SELECT
		 EXISTS(SELECT 1 FROM probe_recipe r JOIN probe_recipe_version v ON v.recipe_id=r.id WHERE r.route_id=(SELECT id FROM target)) OR
		 EXISTS(SELECT 1 FROM probe_execution WHERE route_id=(SELECT id FROM target)) OR
		 EXISTS(SELECT 1 FROM endpoint_capability WHERE scope_route_id=(SELECT id FROM target)) OR
		 EXISTS(SELECT 1 FROM calibration_run WHERE route_id=(SELECT id FROM target)) OR
		 EXISTS(SELECT 1 FROM sample_attempt WHERE route_id=(SELECT id FROM target)) OR
		 EXISTS(SELECT 1 FROM request_log WHERE route_id=(SELECT id FROM target)) OR
		 EXISTS(SELECT 1 FROM probe_cost_daily WHERE route_id=(SELECT id FROM target)) OR
		 EXISTS(SELECT 1 FROM security_finding WHERE route_id=(SELECT id FROM target))`
	case "upstream":
		query = `WITH target(id) AS (VALUES (?)) SELECT
		 EXISTS(SELECT 1 FROM route WHERE upstream_id=(SELECT id FROM target)) OR
		 EXISTS(SELECT 1 FROM probe_recipe r JOIN probe_recipe_version v ON v.recipe_id=r.id WHERE r.upstream_id=(SELECT id FROM target)) OR
		 EXISTS(SELECT 1 FROM probe_execution WHERE upstream_id=(SELECT id FROM target)) OR
		 EXISTS(SELECT 1 FROM client_probe_profile WHERE upstream_id=(SELECT id FROM target)) OR
		 EXISTS(SELECT 1 FROM transform_binding WHERE endpoint_id IN (SELECT id FROM upstream_endpoint WHERE upstream_id=(SELECT id FROM target))) OR
		 EXISTS(SELECT 1 FROM upstream_reachability WHERE upstream_id=(SELECT id FROM target)) OR
		 EXISTS(SELECT 1 FROM endpoint_capability WHERE scope_upstream_id=(SELECT id FROM target) OR endpoint_id IN (SELECT id FROM upstream_endpoint WHERE upstream_id=(SELECT id FROM target))) OR
		 EXISTS(SELECT 1 FROM sample_attempt WHERE upstream_id=(SELECT id FROM target)) OR
		 EXISTS(SELECT 1 FROM request_log WHERE upstream_id=(SELECT id FROM target)) OR
		 EXISTS(SELECT 1 FROM probe_cost_daily WHERE upstream_id=(SELECT id FROM target))`
	case "model_name":
		query = `WITH target(id) AS (VALUES (?)) SELECT
		 EXISTS(SELECT 1 FROM route WHERE model_name_id=(SELECT id FROM target)) OR
		 EXISTS(SELECT 1 FROM sample_attempt WHERE model_name_id=(SELECT id FROM target)) OR
		 EXISTS(SELECT 1 FROM request_log WHERE model_name_id=(SELECT id FROM target))`
	default:
		return fmt.Errorf("unknown configuration kind %q", kind)
	}
	var referenced bool
	if err := tx.QueryRowContext(ctx, query, id).Scan(&referenced); err != nil {
		return err
	}
	if referenced {
		return fmt.Errorf("%w: 存在历史或外部引用，请停用或归档，不可硬删除", ErrDependencyConflict)
	}
	return nil
}
