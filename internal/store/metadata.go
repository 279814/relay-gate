package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"github.com/279814/relay-gate/internal/model"
)

// GetUpstreamByName resolves one unique, operator-visible identity. Unlike a
// list-and-filter lookup it never decrypts an unrelated site's credential.
func (s *Store) GetUpstreamByName(ctx context.Context, name string) (*model.Upstream, error) {
	up, err := s.scanUpstream(s.db.QueryRowContext(ctx, `SELECT `+upstreamCols+` FROM upstream WHERE id>0 AND name=?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return up, err
}

// ListRouteMetadataPage performs the join inside one bounded SQL query. No
// credential column is selected, decoded or default-filled for display.
func (s *Store) ListRouteMetadataPage(ctx context.Context, filter model.RouteFilter) (model.Page[model.RouteMetadata], error) {
	limit, err := normalizePageLimit(filter.Limit)
	if err != nil {
		return model.Page[model.RouteMetadata]{}, err
	}
	if filter.UpstreamID < 0 || filter.ModelNameID < 0 {
		return model.Page[model.RouteMetadata]{}, model.WrapValidation("metadata identity filter 无效")
	}
	cursorFilter := filter
	cursorFilter.PageRequest = model.PageRequest{}
	keys, err := decodePageCursor(filter.Cursor, "route-metadata", cursorFilter, 1)
	if err != nil {
		return model.Page[model.RouteMetadata]{}, err
	}
	conditions := []string{"1=1"}
	args := make([]any, 0, 5)
	if filter.UpstreamID > 0 {
		conditions = append(conditions, "r.upstream_id=?")
		args = append(args, filter.UpstreamID)
	}
	if filter.ModelNameID > 0 {
		conditions = append(conditions, "r.model_name_id=?")
		args = append(args, filter.ModelNameID)
	}
	if filter.Enabled != nil {
		conditions = append(conditions, "r.enabled=?")
		args = append(args, *filter.Enabled)
	}
	if len(keys) == 1 {
		id, err := cursorID(keys[0])
		if err != nil {
			return model.Page[model.RouteMetadata]{}, err
		}
		conditions = append(conditions, "r.id>?")
		args = append(args, id)
	}
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, `SELECT r.id,r.model_name_id,r.upstream_id,r.priority,r.weight,r.upstream_model,
		r.max_concurrency,r.enabled,r.created_at,r.updated_at,r.revision,r.capability_revision,
		COALESCE(m.name,''),COALESCE(m.protocol,''),COALESCE(m.enabled,0),m.id IS NOT NULL,
		COALESCE(u.name,''),COALESCE(u.enabled,0),u.id IS NOT NULL,COALESCE(u.network_revision,0),COALESCE(u.probe_mode,'')
		FROM route r LEFT JOIN model_name m ON m.id=r.model_name_id LEFT JOIN upstream u ON u.id=r.upstream_id
		WHERE `+strings.Join(conditions, " AND ")+` ORDER BY r.id LIMIT ?`, args...)
	if err != nil {
		return model.Page[model.RouteMetadata]{}, err
	}
	defer rows.Close()
	items := make([]model.RouteMetadata, 0, limit+1)
	for rows.Next() {
		var item model.RouteMetadata
		r := &item.Route
		if err := rows.Scan(&r.ID, &r.ModelNameID, &r.UpstreamID, &r.Priority, &r.Weight, &r.UpstreamModel, &r.MaxConcurrency,
			&r.Enabled, &r.CreatedAt, &r.UpdatedAt, &r.Revision, &r.CapabilityRevision,
			&item.ModelName, &item.ModelProtocol, &item.ModelEnabled, &item.ModelExists, &item.UpstreamName, &item.UpstreamEnabled,
			&item.UpstreamExists, &item.UpstreamNetworkRevision, &item.UpstreamProbeMode); err != nil {
			return model.Page[model.RouteMetadata]{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return model.Page[model.RouteMetadata]{}, err
	}
	page := model.Page[model.RouteMetadata]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor, err = encodePageCursor("route-metadata", cursorFilter, strconv.FormatInt(page.Items[len(page.Items)-1].Route.ID, 10))
	}
	return page, err
}
