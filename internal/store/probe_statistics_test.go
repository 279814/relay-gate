package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

var statisticDay = time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)

func statisticExecution(t *testing.T, s *Store, row model.ProbeExecution) {
	t.Helper()
	if row.Trigger == "" {
		row.Trigger = model.TriggerScheduled
	}
	if row.Endpoint == "" {
		row.Endpoint = model.EndpointMessages
	}
	if row.RecipeStorage == "" {
		row.RecipeStorage = model.RecipeStorageEmbedded
		row.TemplateID = "builtin:messages"
		row.RecipeIdentityRevision = 1
	}
	if row.RecipeOrigin == "" {
		row.RecipeOrigin = model.RecipeBasic
	}
	if row.RecipeBindingUse == "" {
		row.RecipeBindingUse = model.BindingResolved
	}
	if row.ErrorClass == "" {
		row.ErrorClass = model.ErrorNone
	}
	row.UpstreamNetworkRevision = 1
	row.UpstreamCredentialRevision = 1
	row.EvidenceHash = "synthetic-evidence"
	row.Capability = model.CapabilityUnknown
	row.Scope = model.ScopeRouteEndpoint
	row.Final = true
	if row.DoneAtMS == 0 {
		row.DoneAtMS = statisticDay.Add(time.Hour).UnixMilli()
	}
	if err := s.InsertProbeExecution(context.Background(), &row); err != nil {
		t.Fatal(err)
	}
}

func TestProbeStatisticsSameTransactionCountAndPageDuringRetention(t *testing.T) {
	s := testStore(t)
	up := mkUpstream(t, s, "statistics-snapshot")
	for i := 0; i < 60; i++ {
		statisticExecution(t, s, model.ProbeExecution{ID: fmt.Sprintf("snapshot-%d", i), ObservationOrder: int64(i + 1), UpstreamID: up.ID, RecipeStorage: model.RecipeStorageEmbedded, TemplateID: fmt.Sprintf("builtin:%03d", i), RecipeIdentityRevision: 1, SentAtMS: statisticDay.UnixMilli(), Success: true})
	}
	start := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		<-start
		for i := 0; i < 60; i++ {
			if _, err := s.db.Exec(`DELETE FROM probe_execution WHERE id=?`, fmt.Sprintf("snapshot-%d", i)); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	close(start)
	for i := 0; i < 30; i++ {
		page, err := s.ListProbeStatistics(context.Background(), statisticFilter())
		if err != nil {
			t.Fatal(err)
		}
		if page.TotalRows != int64(len(page.Items)) {
			t.Fatalf("count/page used different snapshots: total=%d items=%d", page.TotalRows, len(page.Items))
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ListProbeStatistics(ctx, statisticFilter()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled statistics read did not stop: %v", err)
	}
}

func statisticRecipeVersions(t *testing.T, s *Store, upstreamID int64) (int64, int64, int64) {
	t.Helper()
	result, err := s.db.Exec(`INSERT INTO probe_recipe(upstream_id,endpoint,status,created_at,updated_at) VALUES(?,'messages','archived',1,1)`, upstreamID)
	if err != nil {
		t.Fatal(err)
	}
	recipe, _ := result.LastInsertId()
	versions := make([]int64, 2)
	for i := range versions {
		result, err := s.db.Exec(`INSERT INTO probe_recipe_version(recipe_id,version,origin,method,timeout_profile,created_at) VALUES(?,?,'manual','POST','l2_standard',1)`, recipe, i+1)
		if err != nil {
			t.Fatal(err)
		}
		versions[i], _ = result.LastInsertId()
	}
	return recipe, versions[0], versions[1]
}

func statisticFilter() model.ProbeStatisticsFilter {
	return model.ProbeStatisticsFilter{DayFrom: "2026-10-19", DayTo: "2026-10-19", PageRequest: model.PageRequest{Limit: 200}}
}

func TestProbeStatisticsStoredVersionsAndOutcomeDenominator(t *testing.T) {
	s := testStore(t)
	route := mkRoute(t, s)
	recipe, v1, v2 := statisticRecipeVersions(t, s, route.UpstreamID)
	base := model.ProbeExecution{UpstreamID: route.UpstreamID, RouteID: route.ID, RecipeStorage: model.RecipeStorageDB, RecipeOrigin: model.RecipeManual, RecipeID: recipe, RecipeVersionID: v1, SentAtMS: statisticDay.UnixMilli()}
	for i, kind := range []string{"success", "failed", "cancel", "expected", "incomplete", "not-sent"} {
		row := base
		row.ID = kind
		row.ObservationOrder = int64(i + 1)
		switch kind {
		case "success":
			row.Success = true
			row.EstimatedInputTokens = 10
			row.ObservedOutputTokens = 2
		case "failed":
			row.ErrorClass = model.ErrorTransient
		case "cancel":
			row.ErrorClass = model.ErrorIgnored
		case "expected":
			row.ErrorClass = model.ErrorIgnored
			row.ExpectedCancel = true
			row.SemanticSeen = true
		case "incomplete":
			row.ErrorClass = model.ErrorIgnored
			row.ObserverIncomplete = true
			row.ObserverIncompleteReason = model.ObserverDeadline
		case "not-sent":
			row.SentAtMS = 0
			row.ErrorClass = model.ErrorConfig
		}
		statisticExecution(t, s, row)
	}
	other := base
	other.ID = "version-two"
	other.ObservationOrder = 7
	other.RecipeVersionID = v2
	other.Trigger = model.TriggerManual
	other.Success = true
	statisticExecution(t, s, other)
	if _, err := s.db.Exec(`UPDATE probe_recipe SET published_version_id=?,revision=99 WHERE id=?`, v2, recipe); err != nil {
		t.Fatal(err)
	}
	// This field is deliberately unusable as JSON. Aggregation must not fetch
	// full execution DTOs or parse any payload/diagnostic identity JSON.
	if _, err := s.db.Exec(`UPDATE probe_execution SET recipe_binding_facts_json='not-json-private-synthetic',redacted_detail='private-synthetic-marker'`); err != nil {
		t.Fatal(err)
	}
	filter := statisticFilter()
	filter.RecipeID = recipe
	filter.VersionID = v1
	page, err := s.ListProbeStatistics(context.Background(), filter)
	if err != nil || page.TotalRows != 1 || len(page.Items) != 1 {
		t.Fatalf("version statistics=%+v err=%v", page, err)
	}
	row := page.Items[0]
	if row.VersionID != v1 || row.RecipeID != recipe || *row.Executions != 6 || row.Requests != 5 || row.L2Requests != 5 || row.ModelsRequests != 0 || row.Succeeded != 2 || row.Failed != 2 || row.Canceled != 1 || *row.Incomplete != 1 || *row.NotSent != 1 || row.CanceledAfterSemantic != 1 || *row.RecipeDenominator != 4 || *row.RecipeSuccessRate != 0.5 {
		t.Fatalf("wrong stored outcome denominator: %+v", row)
	}
	if row.EstimatedInputTokens == nil || *row.EstimatedInputTokens != 10 || row.ObservedOutputTokens == nil || *row.ObservedOutputTokens != 2 || *row.UnknownInputRows != 5 || *row.UnknownOutputRows != 5 || row.PiggybackL2Saved != nil {
		t.Fatalf("unknown token/recipe saving became zero: %+v", row)
	}
	filter.VersionID = 0
	page, err = s.ListProbeStatistics(context.Background(), filter)
	if err != nil || page.TotalRows != 2 {
		t.Fatalf("current publication rewrote old version history: %+v %v", page, err)
	}
	filter.VersionID = v2
	page, err = s.ListProbeStatistics(context.Background(), filter)
	if err != nil || len(page.Items) != 1 || page.Items[0].ObservedOutputTokens != nil || page.Items[0].Trigger != model.TriggerManual || page.Coverage.CanarySource != "unavailable" {
		t.Fatalf("manual/canary or zero usage fabricated: %+v %v", page, err)
	}
}

func TestProbeStatisticsBuiltinProfileRevisionsAndRealContextStayDistinct(t *testing.T) {
	s := testStore(t)
	route := mkRoute(t, s)
	result, err := s.db.Exec(`INSERT INTO client_probe_profile(upstream_id,endpoint,status,client_family,shape_hash,last_seen_at,created_at,updated_at) VALUES(?,'messages','disabled','synthetic','shape',1,1,1)`, route.UpstreamID)
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := result.LastInsertId()
	for i := 0; i < 2; i++ {
		statisticExecution(t, s, model.ProbeExecution{ID: fmt.Sprintf("builtin-%d", i), ObservationOrder: int64(i + 1), UpstreamID: route.UpstreamID, RecipeStorage: model.RecipeStorageEmbedded, RecipeOrigin: model.RecipeBasic, TemplateID: fmt.Sprintf("builtin:models-%d", i), RecipeIdentityRevision: 1, Endpoint: model.EndpointModels, SentAtMS: statisticDay.UnixMilli(), Success: true})
		statisticExecution(t, s, model.ProbeExecution{ID: fmt.Sprintf("profile-%d", i), ObservationOrder: int64(i + 3), UpstreamID: route.UpstreamID, RouteID: route.ID, RecipeStorage: model.RecipeStorageProfile, ClientProfileID: profile, RecipeIdentityRevision: int64(i + 1), Trigger: model.TriggerRecovery, SentAtMS: statisticDay.UnixMilli(), Success: true})
	}
	statisticExecution(t, s, model.ProbeExecution{ID: "real-context", ObservationOrder: 6, UpstreamID: route.UpstreamID, RouteID: route.ID, Trigger: model.TriggerRealTraffic, RecipeBindingUse: model.BindingRealTrafficContext, RealRequestShapeUnavailableReason: model.ShapeUnsupported, SentAtMS: statisticDay.UnixMilli(), Success: true})
	page, err := s.ListProbeStatistics(context.Background(), statisticFilter())
	if err != nil || page.TotalRows != 5 {
		t.Fatalf("builtin/profile revisions merged: %+v %v", page, err)
	}
	var models, real int
	for _, row := range page.Items {
		models += int(row.ModelsRequests)
		if row.Trigger == model.TriggerRealTraffic {
			real++
			if row.RecipeDenominator != nil || row.RecipeSuccessRate != nil {
				t.Fatalf("real request context became a Recipe rate: %+v", row)
			}
		}
	}
	if models != 2 || real != 1 {
		t.Fatalf("source/endpoint counts wrong: %+v", page.Items)
	}
}

func TestProbeStatisticsKeysetIsBidirectionalAndExcludesConcurrentInserts(t *testing.T) {
	s := testStore(t)
	route := mkRoute(t, s)
	for i := 0; i < 7; i++ {
		statisticExecution(t, s, model.ProbeExecution{ID: fmt.Sprintf("page-%d", i), ObservationOrder: int64(i + 1), UpstreamID: route.UpstreamID, RouteID: route.ID, RecipeStorage: model.RecipeStorageEmbedded, TemplateID: fmt.Sprintf("builtin:%d", i), RecipeIdentityRevision: 1, SentAtMS: statisticDay.UnixMilli(), Success: true})
	}
	filter := statisticFilter()
	filter.Limit = 2
	first, err := s.ListProbeStatistics(context.Background(), filter)
	if err != nil || len(first.Items) != 2 || first.PreviousCursor != "" || first.NextCursor == "" || first.TotalRows != 7 {
		t.Fatalf("first=%+v %v", first, err)
	}
	// One new group and one update to an existing aggregate arrive after the
	// first page; both have real new committed insertion/order identities.
	for i, template := range []string{"builtin:new", first.Items[0].TemplateID} {
		statisticExecution(t, s, model.ProbeExecution{ID: fmt.Sprintf("concurrent-%d", i), ObservationOrder: int64(100 + i), UpstreamID: route.UpstreamID, RouteID: route.ID, RecipeStorage: model.RecipeStorageEmbedded, TemplateID: template, RecipeIdentityRevision: 1, SentAtMS: statisticDay.UnixMilli(), Success: true})
	}
	filter.Cursor = first.NextCursor
	second, err := s.ListProbeStatistics(context.Background(), filter)
	if err != nil || second.TotalRows != 7 || len(second.Items) != 2 || second.PreviousCursor == "" {
		t.Fatalf("insert changed cursor snapshot: %+v %v", second, err)
	}
	filter.Cursor = second.PreviousCursor
	back, err := s.ListProbeStatistics(context.Background(), filter)
	if err != nil || !reflect.DeepEqual(back.Items, first.Items) || back.PreviousCursor != "" {
		t.Fatalf("previous page changed: %+v %v", back, err)
	}
	filter.Cursor = first.NextCursor
	var all []model.ProbeStatistic
	all = append(all, first.Items...)
	for rounds := 0; filter.Cursor != ""; rounds++ {
		if rounds > 10 {
			t.Fatal("cursor did not advance")
		}
		page, err := s.ListProbeStatistics(context.Background(), filter)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, page.Items...)
		filter.Cursor = page.NextCursor
	}
	if len(all) != 7 {
		t.Fatalf("cursor duplicate/gap/new insert: %+v", all)
	}
	for _, row := range all {
		if *row.Executions != 1 {
			t.Fatalf("new execution changed an old group: %+v", row)
		}
	}
	filter.Cursor = ""
	fresh, err := s.ListProbeStatistics(context.Background(), filter)
	if err != nil || fresh.TotalRows != 8 {
		t.Fatalf("fresh query missed committed insert: %+v %v", fresh, err)
	}
	filter.Cursor = first.NextCursor
	filter.Trigger = model.TriggerRecovery
	if _, err := s.ListProbeStatistics(context.Background(), filter); err != ErrInvalidCursor {
		t.Fatalf("cursor reused after filter change: %v", err)
	}
}

func TestProbeStatisticsUTCAndDailyRetentionHaveDifferentCoverage(t *testing.T) {
	s := testStore(t)
	up := mkUpstream(t, s, "statistics-retention")
	for i, sent := range []int64{statisticDay.UnixMilli() - 1, statisticDay.UnixMilli(), statisticDay.AddDate(0, 0, 1).UnixMilli()} {
		statisticExecution(t, s, model.ProbeExecution{ID: fmt.Sprintf("boundary-%d", i), ObservationOrder: int64(i + 1), UpstreamID: up.ID, SentAtMS: sent, Success: true})
	}
	page, err := s.ListProbeStatistics(context.Background(), statisticFilter())
	if err != nil || len(page.Items) != 1 || *page.Items[0].Executions != 1 {
		t.Fatalf("UTC half-open boundary changed: %+v %v", page, err)
	}
	if _, err := s.db.Exec(`DELETE FROM probe_execution; UPDATE probe_cost_retention_watermark SET closed_through_day_utc='2025-01-01'; INSERT INTO probe_cost_daily(day_utc,trigger,origin,endpoint,route_id,upstream_id,requests,succeeded,failed,canceled_after_semantic,piggyback_l2_saved) VALUES('2025-01-01','manual','compact_native','models',0,?,9,9,0,0,0),('2025-02-01','recovery','compact_native','messages',0,?,3,2,1,2,4)`, up.ID, up.ID); err != nil {
		t.Fatal(err)
	}
	filter := model.ProbeStatisticsFilter{Basis: "daily", Scope: "upstream", DayFrom: "2025-01-01", DayTo: "2025-02-01"}
	page, err = s.ListProbeStatistics(context.Background(), filter)
	if err != nil || page.TotalRows != 1 || len(page.Items) != 1 || page.Coverage.CostClosedThroughDay != "2025-01-01" {
		t.Fatalf("closed retention day resurrected: %+v %v", page, err)
	}
	row := page.Items[0]
	if row.Requests != 3 || row.L2Requests != 3 || row.Succeeded != 2 || row.Failed != 1 || row.CanceledAfterSemantic != 2 || *row.PiggybackL2Saved != 4 || row.RecipeSuccessRate != nil || row.Executions != nil || row.ObservedOutputTokens != nil {
		t.Fatalf("daily became a fake recipe/zero usage: %+v", row)
	}
	filter.RecipeID = 1
	if _, err := s.ListProbeStatistics(context.Background(), filter); err == nil {
		t.Fatal("unrecorded daily recipe filter silently accepted")
	}
}
