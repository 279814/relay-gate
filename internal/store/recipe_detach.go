package store

import (
	"database/sql"
	"fmt"
)

// recipeArchiveHolderID parks archived probe_recipe rows whose owning Upstream
// was deleted. probe_recipe CHECK requires exactly one of upstream_id/route_id;
// ON DELETE RESTRICT would otherwise block Upstream delete, and leaving a
// published row keyed by the numeric id would poison SQLite id reuse.
//
// Negative id stays outside AUTOINCREMENT reuse. List/query helpers skip id<=0.
const recipeArchiveHolderID int64 = -1

const recipeArchiveHolderName = "__relay_gate_recipe_archive__"

func ensureRecipeArchiveHolderTx(tx *sql.Tx) error {
	var exists int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM upstream WHERE id=?`, recipeArchiveHolderID).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return nil
	}
	now := nowMS()
	_, err := tx.Exec(`INSERT INTO upstream (
		id,name,base_url,api_key_enc,auth_style,full_url_mode,proxy_url,enabled,l1_path,probe_headers,
		created_at,updated_at,probe_mode,host_override,tls_server_name,revision,network_revision,credential_revision
	) VALUES (?,?,?,?,?,0,'',0,'/v1/models','',?,?,?,?,?,1,1,1)`,
		recipeArchiveHolderID, recipeArchiveHolderName, "http://127.0.0.1", "", "auto",
		now, now, "lazy", "", "")
	if err != nil {
		return fmt.Errorf("ensure recipe archive holder: %w", err)
	}
	return nil
}

// detachProbeRecipesRehomeTx archives recipes matching scopePred and re-homes
// them onto rehomeUpstreamID so route_id can be cleared while CHECK still holds.
// Archived status keeps them out of publishedBinding. Versions stay (immutable).
func detachProbeRecipesRehomeTx(tx *sql.Tx, rehomeUpstreamID int64, scopePred string, scopeArgs ...any) error {
	rows, err := tx.Query(`SELECT id FROM probe_recipe WHERE `+scopePred, scopeArgs...)
	if err != nil {
		return err
	}
	recipeIDs := make([]int64, 0, 4)
	for rows.Next() {
		var recipeID int64
		if err = rows.Scan(&recipeID); err != nil {
			rows.Close()
			return err
		}
		recipeIDs = append(recipeIDs, recipeID)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(recipeIDs) == 0 {
		return nil
	}

	updatedAt := nowMS()
	args := make([]any, 0, 2+len(scopeArgs))
	args = append(args, rehomeUpstreamID, updatedAt)
	args = append(args, scopeArgs...)
	if _, err = tx.Exec(`UPDATE probe_recipe SET status='archived',upstream_id=?,route_id=NULL,
		revision=revision+1,active_binding_revision=active_binding_revision+1,updated_at=?
		WHERE `+scopePred, args...); err != nil {
		return err
	}
	for _, recipeID := range recipeIDs {
		if _, err = tx.Exec(`DELETE FROM recipe_active_secret_ref WHERE recipe_id=?`, recipeID); err != nil {
			return err
		}
	}
	return nil
}
