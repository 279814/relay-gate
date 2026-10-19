package store

import (
	"context"
	"database/sql"
)

// clearStaleRouteHealthTx checks the saved, pre-send identity against the new
// configuration inside its write transaction. A lower-priority binding or an
// unrelated endpoint/policy edit must not erase still-current evidence.
//
// Legacy rows have no dependency proof. Only a definite Route/Model/Upstream
// lifecycle reset, or a reducer-policy change, may clear those rows; otherwise
// they retain the conservative RecoveryGate requirement on startup.
// predicate is internal SQL, never administrator input.
func clearStaleRouteHealthTx(ctx context.Context, tx *sql.Tx, predicate string, clearLegacy bool, args ...any) error {
	rows, err := tx.QueryContext(ctx, `SELECT `+routeHealthCols+` FROM route_health WHERE (`+predicate+`) AND
		(identity_json!='' OR state!='unknown' OR cooldown_until!=0 OR recovery_required!=0)`, args...)
	if err != nil {
		return err
	}
	var snapshots []*RouteHealth
	for rows.Next() {
		row, err := scanRouteHealth(rows)
		if err != nil {
			rows.Close()
			return err
		}
		snapshots = append(snapshots, row)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, row := range snapshots {
		if row.Identity == nil && !clearLegacy {
			continue
		}
		if row.Identity != nil {
			current, err := routeHealthIdentityCurrent(ctx, tx, row.RouteID, row.Identity)
			if err != nil {
				return err
			}
			if current {
				continue
			}
		}
		if err := resetRouteHealthTx(ctx, tx, row.RouteID); err != nil {
			return err
		}
	}
	return nil
}

func resetRouteHealthTx(ctx context.Context, tx *sql.Tx, routeID int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE route_health SET state='unknown',consecutive_ok=0,
		consecutive_fail=0,last_ok_at=0,last_err_at=0,last_error='',last_ttft_ms=0,
		cooldown_until=0,dead_since=0,recovery_required=0,identity_json='',updated_at=? WHERE route_id=?`, nowMS(), routeID)
	return err
}

func clearRecipeScopeHealthTx(ctx context.Context, tx *sql.Tx, recipeID int64) error {
	return clearStaleRouteHealthTx(ctx, tx, `route_id IN (SELECT r.id FROM route r JOIN probe_recipe p
		ON p.route_id=r.id OR p.upstream_id=r.upstream_id WHERE p.id=?)`, false, recipeID)
}
