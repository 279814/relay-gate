package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/279814/relay-gate/internal/model"
)

var ErrClientProfileCapacity = model.ErrClientProfileCapacity

// UpsertClientProbeProfile is the atomic observation path, separate from
// administrator edits: matching evidence only touches telemetry; it never
// changes status, revision or an active tested binding.
func (store *Store) UpsertClientProbeProfile(ctx context.Context, profile *model.ClientProbeProfile) (err error) {
	if err := validateClientProfile(profile); err != nil {
		return err
	}
	headers, err := json.Marshal(profile.SafeHeaders)
	if err != nil {
		return err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	current, err := scanClientProfile(tx.QueryRowContext(ctx, `SELECT `+clientProfileCols+` FROM client_probe_profile
		WHERE upstream_id=? AND endpoint=? AND client_family=? AND shape_hash=?`, profile.UpstreamID, profile.Endpoint, profile.ClientFamily, profile.ShapeHash))
	if err == nil {
		if current.FixedRawQuery != profile.FixedRawQuery || !reflect.DeepEqual(current.SafeHeaders, profile.SafeHeaders) ||
			!bytes.Equal(current.QueryShapeJSON, profile.QueryShapeJSON) || !bytes.Equal(current.BodyTemplate, profile.BodyTemplate) || !bytes.Equal(current.BodyShapeJSON, profile.BodyShapeJSON) {
			return ErrRevisionConflict
		}
		seenAt := profile.LastSeenAt
		if seenAt == 0 {
			seenAt = nowMS()
		}
		if _, err = tx.ExecContext(ctx, `UPDATE client_probe_profile SET last_seen_at=MAX(last_seen_at,?),seen_count=seen_count+1 WHERE id=?`, seenAt, current.ID); err != nil {
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		current.SeenCount++
		if seenAt > current.LastSeenAt {
			current.LastSeenAt = seenAt
		}
		*profile = *current
		return nil
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	var scopeCount, upstreamCount, globalCount int
	if err = tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM client_probe_profile WHERE upstream_id=? AND endpoint=? AND client_family=? AND status='candidate'),
		(SELECT COUNT(*) FROM client_probe_profile WHERE upstream_id=?),
		(SELECT COUNT(*) FROM client_probe_profile)`, profile.UpstreamID, profile.Endpoint, profile.ClientFamily, profile.UpstreamID).
		Scan(&scopeCount, &upstreamCount, &globalCount); err != nil {
		return err
	}
	// Old administrator-created rows can exceed learning bounds. Do not pretend
	// replacing one row repairs that state, or silently delete a batch of history.
	if scopeCount > model.ClientProfileScopeLimit || upstreamCount > model.ClientProfileUpstreamLimit || globalCount > model.ClientProfileGlobalLimit {
		return ErrClientProfileCapacity
	}
	if scopeCount >= model.ClientProfileScopeLimit || upstreamCount >= model.ClientProfileUpstreamLimit || globalCount >= model.ClientProfileGlobalLimit {
		condition := ""
		var args []any
		if scopeCount >= model.ClientProfileScopeLimit {
			condition = " AND p.upstream_id=? AND p.endpoint=? AND p.client_family=?"
			args = []any{profile.UpstreamID, profile.Endpoint, profile.ClientFamily}
		} else if upstreamCount >= model.ClientProfileUpstreamLimit {
			condition = " AND p.upstream_id=?"
			args = []any{profile.UpstreamID}
		}
		var victimID int64
		err = tx.QueryRowContext(ctx, `SELECT p.id FROM client_probe_profile p WHERE p.status='candidate'
			AND COALESCE(p.tested_execution_id,'')='' AND NOT EXISTS(SELECT 1 FROM probe_execution e WHERE e.client_profile_id=p.id)
			AND NOT EXISTS(SELECT 1 FROM client_profile_active_secret_ref a WHERE a.client_profile_id=p.id)
			AND NOT EXISTS(SELECT 1 FROM client_profile_required_secret r WHERE r.client_profile_id=p.id)`+condition+
			` ORDER BY p.last_seen_at,p.id LIMIT 1`, args...).Scan(&victimID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrClientProfileCapacity
		}
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM client_probe_profile WHERE id=?`, victimID); err != nil {
			return err
		}
	}
	now := nowMS()
	profile.Status, profile.Revision, profile.TestedExecutionID = model.ProfileCandidate, 1, ""
	profile.CreatedAt, profile.UpdatedAt = now, now
	if profile.LastSeenAt == 0 {
		profile.LastSeenAt = now
	}
	profile.SeenCount = 1
	result, err := tx.ExecContext(ctx, `INSERT INTO client_probe_profile
		(upstream_id,endpoint,status,safe_headers_json,fixed_raw_query,query_shape_json,body_template,body_shape_json,client_family,shape_hash,revision,last_seen_at,seen_count,tested_execution_id,created_at,updated_at)
		VALUES (?,?,'candidate',?,?,?,?,?,?,?,1,?,1,NULL,?,?)`, profile.UpstreamID, profile.Endpoint, string(headers), profile.FixedRawQuery,
		profile.QueryShapeJSON, profile.BodyTemplate, profile.BodyShapeJSON, profile.ClientFamily, profile.ShapeHash, profile.LastSeenAt, now, now)
	if err != nil {
		return wrapConstraint(err, "client_probe_profile")
	}
	if profile.ID, err = result.LastInsertId(); err != nil {
		return err
	}
	if err = replaceClientProfileSecretRefs(ctx, tx, profile); err != nil {
		return err
	}
	return tx.Commit()
}
