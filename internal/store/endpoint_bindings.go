package store

import (
	"context"
	"database/sql"

	"github.com/279814/relay-gate/internal/model"
)

func loadEndpointBindingMetadata(ctx context.Context, tx *sql.Tx, endpointID int64) ([]model.SecretRevision, error) {
	rows, err := tx.QueryContext(ctx, `SELECT r.name,r.secret_id,s.id,s.revision
		FROM endpoint_active_secret_ref r LEFT JOIN probe_secret s ON s.id=r.secret_id AND s.name=r.name
		WHERE r.endpoint_id=? ORDER BY r.name`, endpointID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var bindings []model.SecretRevision
	for rows.Next() {
		var value model.SecretRevision
		var currentID, revision sql.NullInt64
		if err := rows.Scan(&value.Name, &value.ID, &currentID, &revision); err != nil {
			return nil, err
		}
		if currentID.Valid && currentID.Int64 == value.ID && revision.Valid && revision.Int64 > 0 {
			value.Revision, value.Resolved = revision.Int64, true
		}
		bindings = append(bindings, value)
	}
	return bindings, rows.Err()
}

func materializeEndpointBindings(bundle *ConfigBundle) {
	current := make(map[string]model.SecretRevision, len(bundle.SecretRevisions))
	for _, value := range bundle.SecretRevisions {
		current[value.Name] = value
	}
	for _, endpoint := range bundle.Endpoints {
		endpoint.BoundSecrets = nil
		for _, ref := range bundle.EndpointSecretRefs[endpoint.ID] {
			value := model.SecretRevision{Name: ref.Name, ID: ref.BoundSecretID}
			if found, ok := current[ref.Name]; ok && found.ID == ref.BoundSecretID {
				value = found
			}
			endpoint.BoundSecrets = append(endpoint.BoundSecrets, value)
		}
	}
}
