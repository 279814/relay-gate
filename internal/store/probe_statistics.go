package store

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

const statisticKeys = `day_utc,scope_id,upstream_id,endpoint,trigger,origin,binding_use,storage,recipe_id,version_id,profile_id,template_id,identity_revision`
const statisticMetrics = `executions,requests,models_requests,l2_requests,succeeded,failed,canceled,incomplete,not_sent,canceled_after_semantic,estimated_input_tokens,observed_output_tokens,unknown_input_rows,unknown_output_rows,piggyback_l2_saved,created_time_fallback_rows`
const statisticBudget = 2 * time.Second

func normalizeStatisticFilter(filter model.ProbeStatisticsFilter) (model.ProbeStatisticsFilter, error) {
	if filter.Basis == "" {
		filter.Basis = "executions"
	}
	if filter.Scope == "" {
		filter.Scope = "route"
	}
	if !slices.Contains([]string{"executions", "daily"}, filter.Basis) || !slices.Contains([]string{"route", "upstream"}, filter.Scope) {
		return filter, model.WrapValidation("统计 basis/scope 无效")
	}
	if filter.Endpoint != "" && !filter.Endpoint.Valid() || filter.Trigger != "" && !filter.Trigger.Valid() || filter.Origin != "" && !filter.Origin.Valid() {
		return filter, model.WrapValidation("统计 Endpoint/Trigger/Origin 无效")
	}
	if filter.Storage != "" && filter.Storage != model.RecipeStorageDB && filter.Storage != model.RecipeStorageProfile && filter.Storage != model.RecipeStorageEmbedded {
		return filter, model.WrapValidation("统计 storage 无效")
	}
	if filter.RouteID < 0 || filter.UpstreamID < 0 || filter.RecipeID < 0 || filter.VersionID < 0 || filter.ProfileID < 0 || filter.IdentityRevision < 0 || len(filter.TemplateID) > 128 {
		return filter, model.WrapValidation("统计身份筛选无效")
	}
	if filter.Basis == "daily" && (filter.Storage != "" || filter.RecipeID != 0 || filter.VersionID != 0 || filter.ProfileID != 0 || filter.IdentityRevision != 0 || filter.TemplateID != "") {
		return filter, model.WrapValidation("daily 账本未记录 Recipe identity，不能按 Recipe/版本筛选")
	}
	if filter.Basis == "daily" && filter.Trigger == model.TriggerRealTraffic {
		return filter, model.WrapValidation("真实流量不是 Probe 成本，请查看执行统计")
	}
	return filter, nil
}

func statisticDays(filter model.ProbeStatisticsFilter, at int64) (string, string, int64, int64, error) {
	to := filter.DayTo
	if to == "" {
		to = time.UnixMilli(at).UTC().Format("2006-01-02")
	}
	end, err := time.Parse("2006-01-02", to)
	if err != nil || end.Year() < 1970 {
		return "", "", 0, 0, model.WrapValidation("day_to 无效")
	}
	from := filter.DayFrom
	if from == "" {
		from = end.AddDate(0, 0, -6).Format("2006-01-02")
	}
	start, err := time.Parse("2006-01-02", from)
	maxDays := 92
	if filter.Basis == "daily" {
		maxDays = 730
	}
	if err != nil || start.Year() < 1970 || start.After(end) || end.Sub(start) > time.Duration(maxDays-1)*24*time.Hour {
		return "", "", 0, 0, model.WrapValidation("UTC 日期窗口无效；executions 最多92日、daily最多730日")
	}
	return from, to, start.UnixMilli(), end.AddDate(0, 0, 1).UnixMilli(), nil
}

// ListProbeStatistics reads only immutable execution facts or committed daily
// counters. Count, retention watermark and page share one SQLite read snapshot.
func (s *Store) ListProbeStatistics(ctx context.Context, filter model.ProbeStatisticsFilter) (model.ProbeStatisticsPage, error) {
	var page model.ProbeStatisticsPage
	filter, err := normalizeStatisticFilter(filter)
	if err != nil {
		return page, err
	}
	limit, err := normalizePageLimit(filter.Limit)
	if err != nil {
		return page, err
	}
	if len(filter.Cursor) > 4096 {
		return page, ErrInvalidCursor
	}
	fingerprint := filter
	fingerprint.PageRequest = model.PageRequest{}
	keys, at, err := decodePageCursorAt(filter.Cursor, "probe-statistics", fingerprint, 17)
	if err != nil {
		return page, err
	}
	if at == 0 {
		at = time.Now().UnixMilli()
	}
	from, to, start, end, err := statisticDays(filter, at)
	if err != nil {
		return page, err
	}
	ctx, cancel := context.WithTimeout(ctx, statisticBudget)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	var anchor [3]int64
	direction := "next"
	if len(keys) == 0 {
		query := `SELECT COALESCE(MAX(rowid),0),COALESCE(MAX(observation_order),0),COALESCE(MAX(created_at),0) FROM probe_execution`
		if filter.Basis == "daily" {
			query = `SELECT COALESCE(MAX(rowid),0),0,0 FROM probe_cost_daily`
		}
		if err := tx.QueryRowContext(ctx, query).Scan(&anchor[0], &anchor[1], &anchor[2]); err != nil {
			return page, err
		}
	} else {
		direction = keys[0]
		if direction != "next" && direction != "previous" {
			return page, ErrInvalidCursor
		}
		for i := range anchor {
			anchor[i], err = strconv.ParseInt(keys[i+1], 10, 64)
			if err != nil || anchor[i] < 0 {
				return page, ErrInvalidCursor
			}
		}
	}
	page = model.ProbeStatisticsPage{Basis: filter.Basis, Scope: filter.Scope, DayFrom: from, DayTo: to, EvaluatedAtMS: at, Items: []model.ProbeStatistic{}, Coverage: model.ProbeStatisticsCoverage{
		CanarySource: "unavailable", TokenPresence: "legacy_zero_unknown", PiggybackRecipe: "unavailable", RetainedExecutionsOnly: filter.Basis == "executions",
		RetentionNote: "执行仅覆盖保留行：真实流量7日/5万、周期与恢复90日/20万、手动90日/5万；引用保护行可更早。daily为730日账本，保留删除可能减少后续页。",
		OutcomeNote:   "成功率=成功/(成功+失败)；取消/忽略和观察不完整排除。首语义后预期取消不算失败。发送前失败保留在结果中但不增加发送数。真实流量上下文不生成Recipe率。",
	}}
	if filter.Basis == "daily" {
		page.EvaluatedAtMS = time.Now().UnixMilli()
		page.Coverage.DailyCountsLive = true
		page.Coverage.OutcomeNote = "daily 每页读取当前已提交账本，计数可能增长；其成功/失败/取消为持久化计数，不能生成 Recipe 成功率。"
	}
	if err := tx.QueryRowContext(ctx, `SELECT closed_through_day_utc FROM probe_cost_retention_watermark WHERE singleton=1`).Scan(&page.Coverage.CostClosedThroughDay); err != nil {
		return page, err
	}
	groupSQL, args := statisticGroupSQL(filter, anchor, from, to, start, end, page.Coverage.CostClosedThroughDay)
	if err := tx.QueryRowContext(ctx, `WITH grouped AS (`+groupSQL+`) SELECT COUNT(*),COALESCE(MIN(day_utc),''),COALESCE(MAX(day_utc),'') FROM grouped`, args...).Scan(&page.TotalRows, &page.Coverage.FirstDay, &page.Coverage.LastDay); err != nil {
		return page, err
	}
	query := `WITH grouped AS (` + groupSQL + `) SELECT ` + statisticKeys + `,` + statisticMetrics + ` FROM grouped`
	pageArgs := append([]any(nil), args...)
	if len(keys) > 0 {
		values, err := statisticCursorValues(keys[4:])
		if err != nil {
			return page, err
		}
		comparison := "<"
		if direction == "previous" {
			comparison = ">"
		}
		query += ` WHERE (` + statisticKeys + `)` + comparison + `(?,?,?,?,?,?,?,?,?,?,?,?,?)`
		pageArgs = append(pageArgs, values...)
	}
	order := " DESC"
	if direction == "previous" {
		order = " ASC"
	}
	query += ` ORDER BY ` + strings.Join(strings.Split(statisticKeys, ","), order+",") + order + ` LIMIT ?`
	pageArgs = append(pageArgs, limit+1)
	rows, err := tx.QueryContext(ctx, query, pageArgs...)
	if err != nil {
		return page, err
	}
	for rows.Next() {
		var row model.ProbeStatistic
		err = rows.Scan(&row.DayUTC, &row.ScopeID, &row.UpstreamID, &row.Endpoint, &row.Trigger, &row.Origin, &row.BindingUse, &row.Storage, &row.RecipeID, &row.VersionID, &row.ProfileID, &row.TemplateID, &row.IdentityRevision,
			&row.Executions, &row.Requests, &row.ModelsRequests, &row.L2Requests, &row.Succeeded, &row.Failed, &row.Canceled, &row.Incomplete, &row.NotSent, &row.CanceledAfterSemantic, &row.EstimatedInputTokens, &row.ObservedOutputTokens, &row.UnknownInputRows, &row.UnknownOutputRows, &row.PiggybackL2Saved, &row.CreatedTimeFallbackRows)
		if err != nil {
			rows.Close()
			return page, err
		}
		if filter.Basis == "executions" && row.Trigger != model.TriggerRealTraffic {
			denominator := row.Succeeded + row.Failed
			row.RecipeDenominator = &denominator
			if denominator > 0 {
				rate := float64(row.Succeeded) / float64(denominator)
				row.RecipeSuccessRate = &rate
			}
		}
		page.Items = append(page.Items, row)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return page, err
	}
	more := len(page.Items) > limit
	if more {
		page.Items = page.Items[:limit]
	}
	if direction == "previous" {
		slices.Reverse(page.Items)
	}
	if len(page.Items) > 0 {
		cursor := func(direction string, row model.ProbeStatistic) (string, error) {
			parts := []string{direction, strconv.FormatInt(anchor[0], 10), strconv.FormatInt(anchor[1], 10), strconv.FormatInt(anchor[2], 10)}
			parts = append(parts, statisticRowKeys(row)...)
			return encodePageCursorAt("probe-statistics", fingerprint, at, parts...)
		}
		if direction == "next" && more || direction == "previous" {
			page.NextCursor, err = cursor("next", page.Items[len(page.Items)-1])
			if err != nil {
				return page, err
			}
		}
		if direction == "previous" && more || direction == "next" && len(keys) > 0 {
			page.PreviousCursor, err = cursor("previous", page.Items[0])
			if err != nil {
				return page, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return page, err
	}
	return page, nil
}

func statisticRowKeys(row model.ProbeStatistic) []string {
	return []string{row.DayUTC, strconv.FormatInt(row.ScopeID, 10), strconv.FormatInt(row.UpstreamID, 10), string(row.Endpoint), string(row.Trigger), string(row.Origin), row.BindingUse, string(row.Storage), strconv.FormatInt(row.RecipeID, 10), strconv.FormatInt(row.VersionID, 10), strconv.FormatInt(row.ProfileID, 10), row.TemplateID, strconv.FormatInt(row.IdentityRevision, 10)}
}

func statisticCursorValues(keys []string) ([]any, error) {
	if len(keys) != 13 {
		return nil, ErrInvalidCursor
	}
	out := make([]any, len(keys))
	for i, key := range keys {
		if len(key) > 256 {
			return nil, ErrInvalidCursor
		}
		out[i] = key
	}
	for _, i := range []int{1, 2, 8, 9, 10, 12} {
		value, err := strconv.ParseInt(keys[i], 10, 64)
		if err != nil || value < 0 {
			return nil, ErrInvalidCursor
		}
		out[i] = value
	}
	if _, err := time.Parse("2006-01-02", keys[0]); err != nil {
		return nil, ErrInvalidCursor
	}
	return out, nil
}

func statisticGroupSQL(f model.ProbeStatisticsFilter, anchor [3]int64, from, to string, start, end int64, closed string) (string, []any) {
	alias := "e"
	if f.Basis == "daily" {
		alias = "c"
	}
	conditions := []string{alias + `.rowid<=?`}
	args := []any{anchor[0]}
	if f.Basis == "executions" {
		conditions = append(conditions, `e.observation_order<=?`, `e.created_at<=?`, `CASE WHEN e.sent_at_ms>0 THEN e.sent_at_ms WHEN e.done_at_ms>0 THEN e.done_at_ms ELSE e.created_at END >=?`, `CASE WHEN e.sent_at_ms>0 THEN e.sent_at_ms WHEN e.done_at_ms>0 THEN e.done_at_ms ELSE e.created_at END <?`)
		args = append(args, anchor[1], anchor[2], start, end)
	} else {
		conditions = append(conditions, `c.day_utc>=?`, `c.day_utc<=?`, `c.day_utc>?`, `c.trigger<>'real_traffic'`)
		args = append(args, from, to, closed)
	}
	add := func(column string, value any) {
		conditions = append(conditions, alias+"."+column+"=?")
		args = append(args, value)
	}
	if f.RouteID > 0 {
		add("route_id", f.RouteID)
	}
	if f.UpstreamID > 0 {
		add("upstream_id", f.UpstreamID)
	}
	if f.Endpoint != "" {
		add("endpoint", f.Endpoint)
	}
	if f.Trigger != "" {
		add("trigger", f.Trigger)
	}
	originColumn := "recipe_origin"
	if f.Basis == "daily" {
		originColumn = "origin"
	}
	if f.Origin != "" {
		add(originColumn, f.Origin)
	}
	if f.Basis == "executions" {
		if f.Storage != "" {
			add("recipe_storage", f.Storage)
		}
		if f.RecipeID > 0 {
			add("recipe_id", f.RecipeID)
		}
		if f.VersionID > 0 {
			add("recipe_version_id", f.VersionID)
		}
		if f.ProfileID > 0 {
			add("client_profile_id", f.ProfileID)
		}
		if f.TemplateID != "" {
			add("template_id", f.TemplateID)
		}
		if f.IdentityRevision > 0 {
			add("recipe_identity_revision", f.IdentityRevision)
		}
	}
	scope := `COALESCE(` + alias + `.route_id,0)`
	if f.Scope == "upstream" {
		scope = alias + `.upstream_id`
	}
	where := strings.Join(conditions, " AND ")
	if f.Basis == "daily" {
		return fmt.Sprintf(`SELECT c.day_utc,%s AS scope_id,c.upstream_id,c.endpoint,c.trigger,c.origin,'' AS binding_use,'' AS storage,0 AS recipe_id,0 AS version_id,0 AS profile_id,'' AS template_id,0 AS identity_revision,
		NULL AS executions,SUM(requests) AS requests,SUM(CASE WHEN endpoint='models' THEN requests ELSE 0 END) AS models_requests,SUM(CASE WHEN endpoint IN ('messages','responses','chat_completions') THEN requests ELSE 0 END) AS l2_requests,
		SUM(succeeded) AS succeeded,SUM(failed) AS failed,SUM(canceled) AS canceled,NULL AS incomplete,NULL AS not_sent,SUM(canceled_after_semantic) AS canceled_after_semantic,
		NULLIF(SUM(estimated_input_tokens),0) AS estimated_input_tokens,NULLIF(SUM(observed_output_tokens),0) AS observed_output_tokens,NULL AS unknown_input_rows,NULL AS unknown_output_rows,SUM(piggyback_l2_saved) AS piggyback_l2_saved,NULL AS created_time_fallback_rows
		FROM probe_cost_daily c WHERE %s GROUP BY %s`, scope, where, statisticKeys), args
	}
	return fmt.Sprintf(`SELECT %s,COUNT(*) AS executions,SUM(sent) AS requests,SUM(sent AND endpoint='models') AS models_requests,SUM(sent AND endpoint IN ('messages','responses','chat_completions')) AS l2_requests,
	SUM(outcome='success') AS succeeded,SUM(outcome='failed') AS failed,SUM(outcome='canceled') AS canceled,SUM(outcome='incomplete') AS incomplete,SUM(sent=0) AS not_sent,SUM(expected_semantic) AS canceled_after_semantic,
	SUM(CASE WHEN estimated_input_tokens>0 THEN estimated_input_tokens END) AS estimated_input_tokens,SUM(CASE WHEN observed_output_tokens>0 THEN observed_output_tokens END) AS observed_output_tokens,
	SUM(estimated_input_tokens=0) AS unknown_input_rows,SUM(observed_output_tokens=0) AS unknown_output_rows,NULL AS piggyback_l2_saved,SUM(time_fallback) AS created_time_fallback_rows
	FROM (SELECT strftime('%%Y-%%m-%%d',(CASE WHEN sent_at_ms>0 THEN sent_at_ms WHEN done_at_ms>0 THEN done_at_ms ELSE created_at END)/1000,'unixepoch') AS day_utc,%s AS scope_id,e.upstream_id,e.endpoint,e.trigger,e.recipe_origin AS origin,e.recipe_binding_use AS binding_use,e.recipe_storage AS storage,COALESCE(e.recipe_id,0) AS recipe_id,COALESCE(e.recipe_version_id,0) AS version_id,COALESCE(e.client_profile_id,0) AS profile_id,e.template_id,e.recipe_identity_revision AS identity_revision,
	(sent_at_ms>0) AS sent,CASE WHEN observer_incomplete=1 THEN 'incomplete' WHEN success=1 OR (expected_cancel=1 AND semantic_seen=1 AND error_class IN ('none','ignored')) THEN 'success' WHEN error_class='ignored' THEN 'canceled' ELSE 'failed' END AS outcome,
	(expected_cancel=1 AND semantic_seen=1) AS expected_semantic,estimated_input_tokens,observed_output_tokens,(sent_at_ms=0 AND done_at_ms=0) AS time_fallback
	FROM probe_execution e WHERE %s) GROUP BY %s`, statisticKeys, scope, where, statisticKeys), args
}
