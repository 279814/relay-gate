package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

const authBindingUpgradeMarker = "auth_secret_bindings_v1"

// Before Auth SecretRef was executable, existing probe:<name> declarations did
// not create active references. Capture those identities once, under the process
// instance lock and before listeners start. Later missing bindings are errors;
// restart must never silently bind a recreated name to an existing Endpoint.
func repairLegacyAuthSecretBindings(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM setting WHERE key=?`, authBindingUpgradeMarker).Scan(&exists); err != nil {
		return err
	}
	if exists != 0 {
		return tx.Commit()
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+endpointColumns+` FROM upstream_endpoint WHERE auth_secret_ref LIKE 'probe:%'`)
	if err != nil {
		return err
	}
	type pendingBinding struct {
		endpointID int64
		name       string
	}
	var pending []pendingBinding
	for rows.Next() {
		endpoint, err := scanEndpoint(rows)
		if err != nil || endpoint.Validate() != nil {
			continue // Dirty Auth fields never acquire a new binding.
		}
		placeholder, err := endpoint.AuthProfile.SecretPlaceholder()
		if err != nil {
			continue // Invalid historical configuration stays route-local.
		}
		if name, ok := strings.CutPrefix(placeholder, "SECRET:"); ok {
			if endpoint.AuthProfile.Mode != model.AuthModeLegacyAutoRealOnly {
				pending = append(pending, pendingBinding{endpointID: endpoint.ID, name: name})
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, binding := range pending {
		var id, revision int64
		if err := tx.QueryRowContext(ctx, `SELECT id,revision FROM probe_secret WHERE name=?`, binding.name).Scan(&id, &revision); errors.Is(err, sql.ErrNoRows) {
			// Missing legacy credentials remain unbound, but their previously
			// ignored Auth declaration still starts a new evidence lifecycle.
		} else if err != nil {
			return err
		} else if _, err := tx.ExecContext(ctx, `INSERT INTO endpoint_active_secret_ref(endpoint_id,secret_id,name,revision)
			VALUES (?,?,?,?) ON CONFLICT(endpoint_id,name) DO NOTHING`, binding.endpointID, id, binding.name, revision); err != nil {
			return err
		}
		// This implementation now honors Auth SecretRef. Even a reference that
		// already existed through query/manual headers must invalidate evidence
		// produced by the old implementation that ignored the Auth declaration.
		if _, err := tx.ExecContext(ctx, `UPDATE upstream_endpoint SET revision=revision+1,
			auth_profile_revision=auth_profile_revision+1,updated_at=? WHERE id=?`, nowMS(), binding.endpointID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO setting(key,value,updated_at,revision) VALUES (?, '1', ?, 1)`, authBindingUpgradeMarker, nowMS()); err != nil {
		return err
	}
	return tx.Commit()
}
