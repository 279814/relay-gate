package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/transform"
)

func validTransformState(state string) bool {
	return state == "" || state == "active" || state == "disabled" || state == "archived"
}

// The three persistent Transform lists share one read transaction for their
// filtered count and bounded keyset page. All SQL fragments are internal.
func readTransformPage[T any](ctx context.Context, s *Store, resource string, filter any, limit int, from, columns, where, after, order string, args, afterArgs []any, scan func(*sql.Rows) (T, error), keys func(T) []string) (model.TransformPage[T], error) {
	page := model.TransformPage[T]{Items: make([]T, 0, limit), Limit: limit}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+from+" WHERE "+where, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	queryArgs := append([]any(nil), args...)
	if after != "" {
		where += " AND (" + after + ")"
		queryArgs = append(queryArgs, afterArgs...)
	}
	queryArgs = append(queryArgs, limit+1)
	rows, err := tx.QueryContext(ctx, "SELECT "+columns+" FROM "+from+" WHERE "+where+" ORDER BY "+order+" LIMIT ?", queryArgs...)
	if err != nil {
		return page, err
	}
	for rows.Next() {
		item, err := scan(rows)
		if err != nil {
			rows.Close()
			return page, err
		}
		page.Items = append(page.Items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return page, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor, err = encodePageCursor(resource, filter, keys(page.Items[len(page.Items)-1])...)
		if err != nil {
			return page, err
		}
	}
	if err := tx.Commit(); err != nil {
		return page, err
	}
	return page, nil
}

func (s *Store) ListTransformSetsPage(ctx context.Context, f model.TransformSetFilter) (model.TransformPage[model.TransformSetSummary], error) {
	var empty model.TransformPage[model.TransformSetSummary]
	if !validTransformState(f.State) || len(f.Name) > 256 {
		return empty, model.WrapValidation("转换筛选无效")
	}
	limit, err := normalizePageLimit(f.Limit)
	if err != nil {
		return empty, err
	}
	cursorFilter := f
	cursorFilter.PageRequest = model.PageRequest{}
	cursor, err := decodePageCursor(f.Cursor, "transform_sets", cursorFilter, 1)
	if err != nil {
		return empty, err
	}
	where := []string{"1=1"}
	var args, afterArgs []any
	if f.State != "" {
		where = append(where, "s.lifecycle_state=?")
		args = append(args, f.State)
	}
	if f.Name != "" {
		where = append(where, "instr(lower(s.name),lower(?))>0")
		args = append(args, f.Name)
	}
	after := ""
	if len(cursor) > 0 {
		id, err := cursorID(cursor[0])
		if err != nil {
			return empty, err
		}
		after = "s.id<?"
		afterArgs = []any{id}
	}
	columns := `s.id,s.name,s.created_at,s.revision,s.lifecycle_state,COALESCE(json_extract(NULLIF(s.draft_json,''),'$.id'),0),COALESCE(json_extract(NULLIF(s.draft_json,''),'$.revision'),0),(SELECT COUNT(*) FROM transform_version v WHERE v.set_id=s.id)`
	return readTransformPage(ctx, s, "transform_sets", cursorFilter, limit, "transform_set s", columns, strings.Join(where, " AND "), after, "s.id DESC", args, afterArgs, func(rows *sql.Rows) (model.TransformSetSummary, error) {
		var v model.TransformSetSummary
		err := rows.Scan(&v.ID, &v.Name, &v.CreatedAt, &v.Revision, &v.State, &v.DraftVersionID, &v.DraftRevision, &v.HistoryCount)
		return v, err
	}, func(v model.TransformSetSummary) []string { return []string{strconv.FormatInt(v.ID, 10)} })
}

func (s *Store) ListTransformVersionsPage(ctx context.Context, f model.TransformVersionFilter) (model.TransformPage[model.TransformVersionSummary], error) {
	var empty model.TransformPage[model.TransformVersionSummary]
	if f.SetID < 1 || (f.Mode != "" && f.Mode != "published" && f.Mode != "shadow" && f.Mode != "history") {
		return empty, model.WrapValidation("转换版本筛选无效")
	}
	limit, err := normalizePageLimit(f.Limit)
	if err != nil {
		return empty, err
	}
	cursorFilter := f
	cursorFilter.PageRequest = model.PageRequest{}
	cursor, err := decodePageCursor(f.Cursor, "transform_versions", cursorFilter, 1)
	if err != nil {
		return empty, err
	}
	where := "v.set_id=?"
	args := []any{f.SetID}
	switch f.Mode {
	case "published":
		where += " AND v.id IN (SELECT published_id FROM transform_binding WHERE published_id<>0)"
	case "shadow":
		where += " AND v.id IN (SELECT shadow_id FROM transform_binding WHERE shadow_id<>0)"
	case "history":
		where += " AND v.id NOT IN (SELECT published_id FROM transform_binding WHERE published_id<>0) AND v.id NOT IN (SELECT shadow_id FROM transform_binding WHERE shadow_id<>0)"
	}
	after := ""
	var afterArgs []any
	if len(cursor) > 0 {
		id, err := cursorID(cursor[0])
		if err != nil {
			return empty, err
		}
		after = "v.id<?"
		afterArgs = []any{id}
	}
	columns := `v.id,v.set_id,v.revision,v.created_at,substr(v.note,1,256),length(v.note)>256,v.id IN (SELECT published_id FROM transform_binding WHERE published_id<>0),v.id IN (SELECT shadow_id FROM transform_binding WHERE shadow_id<>0)`
	return readTransformPage(ctx, s, "transform_versions", cursorFilter, limit, "transform_version v", columns, where, after, "v.id DESC", args, afterArgs, func(rows *sql.Rows) (model.TransformVersionSummary, error) {
		var v model.TransformVersionSummary
		err := rows.Scan(&v.ID, &v.SetID, &v.Revision, &v.CreatedAt, &v.Note, &v.NoteTruncated, &v.Published, &v.Shadow)
		return v, err
	}, func(v model.TransformVersionSummary) []string { return []string{strconv.FormatInt(v.ID, 10)} })
}

func (s *Store) ListTransformBindingsPage(ctx context.Context, f model.TransformBindingFilter) (model.TransformPage[model.TransformBindingSummary], error) {
	var empty model.TransformPage[model.TransformBindingSummary]
	if !validTransformState(f.State) || f.SetID < 0 || f.RouteID < 0 || f.EndpointID < 0 || f.VersionID < 0 {
		return empty, model.WrapValidation("转换绑定筛选无效")
	}
	limit, err := normalizePageLimit(f.Limit)
	if err != nil {
		return empty, err
	}
	cursorFilter := f
	cursorFilter.PageRequest = model.PageRequest{}
	cursor, err := decodePageCursor(f.Cursor, "transform_bindings", cursorFilter, 2)
	if err != nil {
		return empty, err
	}
	where := []string{"1=1"}
	var args, afterArgs []any
	for _, v := range []struct {
		column string
		id     int64
	}{{"b.set_id", f.SetID}, {"b.route_id", f.RouteID}, {"b.endpoint_id", f.EndpointID}} {
		if v.id > 0 {
			where = append(where, v.column+"=?")
			args = append(args, v.id)
		}
	}
	if f.VersionID > 0 {
		where = append(where, "(b.published_id=? OR b.shadow_id=?)")
		args = append(args, f.VersionID, f.VersionID)
	}
	if f.State != "" {
		where = append(where, "s.lifecycle_state=?")
		args = append(args, f.State)
	}
	after := ""
	if len(cursor) > 0 {
		route, err := cursorID(cursor[0])
		if err != nil {
			return empty, err
		}
		endpoint, err := cursorID(cursor[1])
		if err != nil {
			return empty, err
		}
		after = "b.route_id<? OR (b.route_id=? AND b.endpoint_id<?)"
		afterArgs = []any{route, route, endpoint}
	}
	return readTransformPage(ctx, s, "transform_bindings", cursorFilter, limit, "transform_binding b JOIN transform_set s ON s.id=b.set_id", `b.route_id,b.endpoint_id,b.set_id,b.revision,b.published_id,b.shadow_id,s.lifecycle_state`, strings.Join(where, " AND "), after, "b.route_id DESC,b.endpoint_id DESC", args, afterArgs, func(rows *sql.Rows) (model.TransformBindingSummary, error) {
		var v model.TransformBindingSummary
		err := rows.Scan(&v.RouteID, &v.EndpointID, &v.SetID, &v.Revision, &v.PublishedID, &v.ShadowID, &v.State)
		return v, err
	}, func(v model.TransformBindingSummary) []string {
		return []string{strconv.FormatInt(v.RouteID, 10), strconv.FormatInt(v.EndpointID, 10)}
	})
}

func (s *Store) GetTransformVersion(ctx context.Context, id int64) (transform.Version, error) {
	var version transform.Version
	var created int64
	var rules []byte
	err := s.db.QueryRowContext(ctx, `SELECT id,set_id,revision,created_at,rules_json,req_fail_policy,res_fail_policy,note FROM transform_version WHERE id=?`, id).Scan(&version.ID, &version.SetID, &version.Revision, &created, &rules, &version.ReqFailPolicy, &version.ResFailPolicy, &version.Note)
	if err == sql.ErrNoRows {
		return version, ErrNotFound
	}
	if err != nil {
		return version, err
	}
	if err := json.Unmarshal(rules, &version.Rules); err != nil {
		return version, err
	}
	version.CreatedAt = time.UnixMilli(created).UTC()
	return version, nil
}
