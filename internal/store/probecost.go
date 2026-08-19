package store

// 探活成本的查询与旁路记账。累加与幂等门禁在 capability.go 的
// recordProbeCostEvidenceTx —— 这里只是它的公开入口，不重复实现一套。

import (
	"context"
	"strconv"
	"strings"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

const probeCostCols = `day_utc,trigger,origin,endpoint,route_id,upstream_id,requests,succeeded,
	failed,canceled,estimated_input_tokens,observed_output_tokens,canceled_after_semantic,piggyback_l2_saved`

// RecordProbePiggybackSaving 记一次「真实流量顺带完成了 L2 探活」省下的额度。
// eventID 由调用方给定并作为幂等键：同 ID 重复提交只累加一次，
// 提交内容不一致则返回 ErrIdempotencyConflict。
func (store *Store) RecordProbePiggybackSaving(ctx context.Context, eventID string, value model.ProbeCostDaily) error {
	if eventID == "" {
		return model.WrapValidation("piggyback event id 不能为空")
	}
	evidence, err := revisioncodec.CostEvidenceFromPiggyback(value)
	if err != nil {
		return err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := recordProbeCostEvidenceTx(ctx, tx, eventID, evidence); err != nil {
		return err
	}
	return tx.Commit()
}

// ListProbeCostDaily 按主键六元组倒序翻页。这张表没有自增 id，
// 主键本身就是 keyset，且 idx_probe_cost_page 的列序与方向都对得上。
//
// 六段 cursor 展开成 (a<A) OR (a=A AND b<B) OR … 的阶梯条件；写成
// 元组比较 (a,b,…)<(A,B,…) 更短，但 SQLite 不会为它用上索引。
func (store *Store) ListProbeCostDaily(ctx context.Context, filter model.ProbeCostFilter) (model.Page[*model.ProbeCostDaily], error) {
	limit, err := normalizePageLimit(filter.Limit)
	if err != nil {
		return model.Page[*model.ProbeCostDaily]{}, err
	}
	cursorFilter := filter
	cursorFilter.PageRequest = model.PageRequest{}
	keys, err := decodePageCursor(filter.Cursor, "probe-cost-daily", cursorFilter, 6)
	if err != nil {
		return model.Page[*model.ProbeCostDaily]{}, err
	}
	conditions := []string{"1=1"}
	args := make([]any, 0, 14)
	if filter.DayFrom != "" {
		conditions = append(conditions, "day_utc>=?")
		args = append(args, filter.DayFrom)
	}
	if filter.DayTo != "" {
		conditions = append(conditions, "day_utc<=?")
		args = append(args, filter.DayTo)
	}
	if filter.Trigger != "" {
		if !filter.Trigger.Valid() {
			return model.Page[*model.ProbeCostDaily]{}, model.WrapValidation("trigger filter 无效")
		}
		conditions = append(conditions, "trigger=?")
		args = append(args, filter.Trigger)
	}
	if filter.Origin != "" {
		if !filter.Origin.Valid() {
			return model.Page[*model.ProbeCostDaily]{}, model.WrapValidation("origin filter 无效")
		}
		conditions = append(conditions, "origin=?")
		args = append(args, filter.Origin)
	}
	if filter.Endpoint != "" {
		if !filter.Endpoint.Valid() {
			return model.Page[*model.ProbeCostDaily]{}, model.WrapValidation("endpoint filter 无效")
		}
		conditions = append(conditions, "endpoint=?")
		args = append(args, filter.Endpoint)
	}
	if filter.RouteID > 0 {
		conditions = append(conditions, "route_id=?")
		args = append(args, filter.RouteID)
	}
	if filter.UpstreamID > 0 {
		conditions = append(conditions, "upstream_id=?")
		args = append(args, filter.UpstreamID)
	}
	if len(keys) == 6 {
		routeID, routeErr := strconv.ParseInt(keys[4], 10, 64)
		upstreamID, upstreamErr := strconv.ParseInt(keys[5], 10, 64)
		if routeErr != nil || upstreamErr != nil || routeID < 0 || upstreamID < 0 {
			return model.Page[*model.ProbeCostDaily]{}, ErrInvalidCursor
		}
		conditions = append(conditions, `(day_utc<? OR (day_utc=? AND (trigger<? OR (trigger=? AND
			(origin<? OR (origin=? AND (endpoint<? OR (endpoint=? AND (route_id<? OR
			(route_id=? AND upstream_id<?)))))))))) `)
		args = append(args, keys[0], keys[0], keys[1], keys[1], keys[2], keys[2],
			keys[3], keys[3], routeID, routeID, upstreamID)
	}
	args = append(args, limit+1)
	rows, err := store.db.QueryContext(ctx, `SELECT `+probeCostCols+` FROM probe_cost_daily WHERE `+
		strings.Join(conditions, " AND ")+` ORDER BY day_utc DESC,trigger DESC,origin DESC,
		endpoint DESC,route_id DESC,upstream_id DESC LIMIT ?`, args...)
	if err != nil {
		return model.Page[*model.ProbeCostDaily]{}, err
	}
	defer rows.Close()
	items := make([]*model.ProbeCostDaily, 0, limit+1)
	for rows.Next() {
		var item model.ProbeCostDaily
		if err := rows.Scan(&item.DayUTC, &item.Trigger, &item.Origin, &item.Endpoint, &item.RouteID,
			&item.UpstreamID, &item.Requests, &item.Succeeded, &item.Failed, &item.Canceled,
			&item.EstimatedInputTokens, &item.ObservedOutputTokens, &item.CanceledAfterSemantic,
			&item.PiggybackL2Saved); err != nil {
			return model.Page[*model.ProbeCostDaily]{}, err
		}
		items = append(items, &item)
	}
	if err := rows.Err(); err != nil {
		return model.Page[*model.ProbeCostDaily]{}, err
	}
	page := model.Page[*model.ProbeCostDaily]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = encodePageCursor("probe-cost-daily", cursorFilter,
			last.DayUTC, string(last.Trigger), string(last.Origin), string(last.Endpoint),
			strconv.FormatInt(last.RouteID, 10), strconv.FormatInt(last.UpstreamID, 10))
		if err != nil {
			return model.Page[*model.ProbeCostDaily]{}, err
		}
	}
	return page, nil
}
