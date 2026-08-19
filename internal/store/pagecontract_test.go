package store

// P0-02 验收项 23：每个 Page 方法都要覆盖空页、默认/最大 limit、tie-breaker、
// 每个服务端 filter、跨页无重复无漏项，以及四类坏 cursor；并用 EXPLAIN QUERY PLAN
// 证明常用过滤组合走 keyset 索引。
//
// 这里用「表驱动 + 泛型 walk」而不是给 11 个方法各写一遍：分页契约本身是同一套，
// 逐个手写会让漏测某一项的地方看不出来。

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

// pager 把「一个分页方法」抽象成可反复调用的形状：给 cursor+limit，
// 回一页的键与下一页 cursor。键取每行的稳定标识，用来查重复/遗漏。
type pager func(cursor string, limit int) (keys []string, next string, err error)

func pageOf[T any](t *testing.T, list func(model.PageRequest) (model.Page[T], error), key func(T) string) pager {
	t.Helper()
	return func(cursor string, limit int) ([]string, string, error) {
		page, err := list(model.PageRequest{Cursor: cursor, Limit: limit})
		if err != nil {
			return nil, "", err
		}
		keys := make([]string, 0, len(page.Items))
		for _, item := range page.Items {
			keys = append(keys, key(item))
		}
		return keys, page.NextCursor, nil
	}
}

// walkAll 按 limit 逐页翻到底，返回拼接后的全部键。
// 页数上限防的是 cursor 不前进导致的死循环 —— 那正是分页最容易写错的地方。
func walkAll(t *testing.T, next pager, limit int) []string {
	t.Helper()
	var all []string
	cursor := ""
	for page := 0; ; page++ {
		if page > 100 {
			t.Fatalf("翻页超过 100 页仍未结束，cursor 没有前进")
		}
		keys, nextCursor, err := next(cursor, limit)
		if err != nil {
			t.Fatalf("第 %d 页失败: %v", page, err)
		}
		if len(keys) > limit {
			t.Fatalf("第 %d 页返回 %d 项，超过 limit %d", page, len(keys), limit)
		}
		all = append(all, keys...)
		if nextCursor == "" {
			return all
		}
		if nextCursor == cursor {
			t.Fatalf("第 %d 页的 NextCursor 与上一页相同，会死循环", page)
		}
		cursor = nextCursor
	}
}

// assertNoDuplicateOrGap 断言逐页拼出的序列与一次性全量读出的完全一致。
func assertNoDuplicateOrGap(t *testing.T, label string, paged, want []string) {
	t.Helper()
	seen := map[string]int{}
	for _, key := range paged {
		seen[key]++
		if seen[key] > 1 {
			t.Errorf("%s: 键 %q 跨页重复出现 %d 次", label, key, seen[key])
		}
	}
	if len(paged) != len(want) {
		t.Errorf("%s: 翻页共 %d 项，全量 %d 项", label, len(paged), len(want))
	}
	for index := range want {
		if index >= len(paged) {
			t.Errorf("%s: 第 %d 项 %q 在翻页结果里缺失", label, index, want[index])
			continue
		}
		if paged[index] != want[index] {
			t.Errorf("%s: 第 %d 项 = %q, 全量为 %q（顺序不一致）", label, index, paged[index], want[index])
		}
	}
}

// assertCursorRejections 覆盖四类坏 cursor：格式坏、跨资源、改 filter 后复用、超限 limit。
// crossResource 传另一个分页方法产出的真实 cursor。
func assertCursorRejections(t *testing.T, label string, next pager, crossResource string, changedFilter pager) {
	t.Helper()
	if _, _, err := next("not-a-valid-cursor", 0); !errors.Is(err, ErrInvalidCursor) {
		t.Errorf("%s: 坏格式 cursor 的 error = %v, want ErrInvalidCursor", label, err)
	}
	if crossResource != "" {
		if _, _, err := next(crossResource, 0); !errors.Is(err, ErrInvalidCursor) {
			t.Errorf("%s: 跨资源 cursor 的 error = %v, want ErrInvalidCursor", label, err)
		}
	}
	if _, _, err := next("", maximumPageLimit+1); !errors.Is(err, ErrInvalidCursor) {
		t.Errorf("%s: 超限 limit 的 error = %v, want ErrInvalidCursor", label, err)
	}
	if _, _, err := next("", -1); !errors.Is(err, ErrInvalidCursor) {
		t.Errorf("%s: 负 limit 的 error = %v, want ErrInvalidCursor", label, err)
	}
	if changedFilter != nil {
		_, cursor, err := next("", 1)
		if err != nil {
			t.Fatalf("%s: 取首页失败: %v", label, err)
		}
		if cursor == "" {
			t.Fatalf("%s: 数据不足以产生 NextCursor，无法验证改 filter 后复用", label)
		}
		if _, _, err := changedFilter(cursor, 1); !errors.Is(err, ErrInvalidCursor) {
			t.Errorf("%s: 改 filter 后复用 cursor 的 error = %v, want ErrInvalidCursor", label, err)
		}
	}
}

func TestListUpstreamsPageContract(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	enabled := []string{}
	for _, name := range []string{"alpha", "bravo", "charlie", "delta", "echo"} {
		upstream := mkUpstream(t, store, name)
		enabled = append(enabled, upstream.Name)
	}
	// 一个 disabled + 一个 Lazy，用来分别验证两个服务端 filter 真的生效。
	disabled := mkUpstream(t, store, "foxtrot")
	disabled.Enabled = false
	if err := store.UpdateUpstream(disabled); err != nil {
		t.Fatal(err)
	}
	lazy := mkUpstream(t, store, "golf")
	lazy.ProbeMode = model.ProbeModeLazy
	if err := store.UpdateUpstream(lazy); err != nil {
		t.Fatal(err)
	}

	all := pageOf(t, func(request model.PageRequest) (model.Page[*model.Upstream], error) {
		return store.ListUpstreamsPage(ctx, model.UpstreamFilter{PageRequest: request})
	}, func(item *model.Upstream) string { return item.Name })

	full, _, err := all("", maximumPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != 7 {
		t.Fatalf("全量 = %d 项, want 7", len(full))
	}
	for _, limit := range []int{1, 2, 3, 7} {
		assertNoDuplicateOrGap(t, "upstreams", walkAll(t, all, limit), full)
	}

	// 默认 limit：不传 limit 时按 defaultPageLimit 取，本例数据不足一页故无 cursor。
	keys, next, err := all("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 7 || next != "" {
		t.Errorf("默认 limit 返回 %d 项 next=%q, want 7 项且无 cursor", len(keys), next)
	}

	yes, no := true, false
	enabledOnly, _, err := pageOf(t, func(request model.PageRequest) (model.Page[*model.Upstream], error) {
		return store.ListUpstreamsPage(ctx, model.UpstreamFilter{PageRequest: request, Enabled: &yes})
	}, func(item *model.Upstream) string { return item.Name })("", maximumPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(enabledOnly) != 6 {
		t.Errorf("enabled=true 得到 %v, want 6 项（不含 foxtrot）", enabledOnly)
	}
	disabledOnly, _, err := pageOf(t, func(request model.PageRequest) (model.Page[*model.Upstream], error) {
		return store.ListUpstreamsPage(ctx, model.UpstreamFilter{PageRequest: request, Enabled: &no})
	}, func(item *model.Upstream) string { return item.Name })("", maximumPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(disabledOnly) != 1 || disabledOnly[0] != "foxtrot" {
		t.Errorf("enabled=false 得到 %v, want [foxtrot]", disabledOnly)
	}
	lazyOnly, _, err := pageOf(t, func(request model.PageRequest) (model.Page[*model.Upstream], error) {
		return store.ListUpstreamsPage(ctx, model.UpstreamFilter{PageRequest: request, ProbeMode: model.ProbeModeLazy})
	}, func(item *model.Upstream) string { return item.Name })("", maximumPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(lazyOnly) != 1 || lazyOnly[0] != "golf" {
		t.Errorf("probe_mode=lazy 得到 %v, want [golf]", lazyOnly)
	}
	if _, err := store.ListUpstreamsPage(ctx, model.UpstreamFilter{ProbeMode: "bogus"}); err == nil {
		t.Error("非法 probe_mode filter 应报错")
	}

	// 空页：过滤到没有任何行时返回空 Items 而不是 error，也不能带 NextCursor。
	// 全部 upstream 都 enabled 或 disabled，故 lazy+disabled 的交集必然为空。
	emptyPage, err := store.ListUpstreamsPage(ctx,
		model.UpstreamFilter{Enabled: &no, ProbeMode: model.ProbeModeLazy})
	if err != nil {
		t.Fatal(err)
	}
	if len(emptyPage.Items) != 0 || emptyPage.NextCursor != "" {
		t.Errorf("空页 = %d 项 next=%q, want 0 项且无 cursor", len(emptyPage.Items), emptyPage.NextCursor)
	}

	crossResource := crossResourceCursor(t, store)
	changed := pageOf(t, func(request model.PageRequest) (model.Page[*model.Upstream], error) {
		return store.ListUpstreamsPage(ctx, model.UpstreamFilter{PageRequest: request, Enabled: &yes})
	}, func(item *model.Upstream) string { return item.Name })
	assertCursorRejections(t, "upstreams", all, crossResource, changed)
}

// crossResourceCursor 造一个别的资源的真实 cursor，用来证明 cursor 认资源名。
// 用 probe_secret：它不依赖任何外键，两行就能产出 NextCursor。
func crossResourceCursor(t *testing.T, store *Store) string {
	t.Helper()
	for _, name := range []string{"cross-a", "cross-b"} {
		if _, err := store.CreateProbeSecret(name, []byte("value-"+name)); err != nil {
			t.Fatal(err)
		}
	}
	page, err := store.ListProbeSecretsPage(context.Background(),
		model.ProbeSecretFilter{PageRequest: model.PageRequest{Limit: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if page.NextCursor == "" {
		t.Fatal("两条 Secret 取 limit=1 应产出 NextCursor")
	}
	return page.NextCursor
}

func TestListModelNamesPageContract(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	for _, name := range []string{"claude-opus-5", "claude-fable-5", "claude-opus-4-8"} {
		mkModelName(t, store, name, model.ProtoAnthropic)
	}
	openAI := mkModelName(t, store, "gpt-5.6-sol", model.ProtoOpenAIResponses)
	openAI.Enabled = false
	if err := store.UpdateModelName(openAI); err != nil {
		t.Fatal(err)
	}

	all := pageOf(t, func(request model.PageRequest) (model.Page[*model.ModelName], error) {
		return store.ListModelNamesPage(ctx, model.ModelNameFilter{PageRequest: request})
	}, func(item *model.ModelName) string { return item.Name })
	full, _, err := all("", maximumPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != 4 {
		t.Fatalf("全量 = %v, want 4 项", full)
	}
	for _, limit := range []int{1, 2, 4} {
		assertNoDuplicateOrGap(t, "model-names", walkAll(t, all, limit), full)
	}

	anthropicOnly, _, err := pageOf(t, func(request model.PageRequest) (model.Page[*model.ModelName], error) {
		return store.ListModelNamesPage(ctx,
			model.ModelNameFilter{PageRequest: request, Protocol: model.ProtoAnthropic})
	}, func(item *model.ModelName) string { return item.Name })("", maximumPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(anthropicOnly) != 3 {
		t.Errorf("protocol=anthropic 得到 %v, want 3 项", anthropicOnly)
	}
	no := false
	disabledOnly, _, err := pageOf(t, func(request model.PageRequest) (model.Page[*model.ModelName], error) {
		return store.ListModelNamesPage(ctx, model.ModelNameFilter{PageRequest: request, Enabled: &no})
	}, func(item *model.ModelName) string { return item.Name })("", maximumPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(disabledOnly) != 1 || disabledOnly[0] != "gpt-5.6-sol" {
		t.Errorf("enabled=false 得到 %v, want [gpt-5.6-sol]", disabledOnly)
	}
	if _, err := store.ListModelNamesPage(ctx, model.ModelNameFilter{Protocol: "bogus"}); err == nil {
		t.Error("非法 protocol filter 应报错")
	}

	changed := pageOf(t, func(request model.PageRequest) (model.Page[*model.ModelName], error) {
		return store.ListModelNamesPage(ctx,
			model.ModelNameFilter{PageRequest: request, Protocol: model.ProtoAnthropic})
	}, func(item *model.ModelName) string { return item.Name })
	assertCursorRejections(t, "model-names", all, crossResourceCursor(t, store), changed)
}

func TestListRoutesPageContract(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	modelName := mkModelName(t, store, "claude-opus-5", model.ProtoAnthropic)
	other := mkModelName(t, store, "claude-fable-5", model.ProtoAnthropic)
	var routeIDs []int64
	for index, name := range []string{"sta", "stb", "stc", "std"} {
		upstream := mkUpstream(t, store, name)
		owner := modelName.ID
		if index == 3 {
			owner = other.ID
		}
		// priority 故意重复：keyset 若误用 priority 排序，这里就会重复或漏项。
		route := &model.Route{ModelNameID: owner, UpstreamID: upstream.ID, Priority: 1, Enabled: index != 2}
		if err := store.CreateRoute(route); err != nil {
			t.Fatal(err)
		}
		routeIDs = append(routeIDs, route.ID)
	}

	all := pageOf(t, func(request model.PageRequest) (model.Page[*model.Route], error) {
		return store.ListRoutesPage(ctx, model.RouteFilter{PageRequest: request})
	}, func(item *model.Route) string { return strconv.FormatInt(item.ID, 10) })
	full, _, err := all("", maximumPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != 4 {
		t.Fatalf("全量 = %v, want 4 项", full)
	}
	for _, limit := range []int{1, 2, 3, 4} {
		assertNoDuplicateOrGap(t, "routes", walkAll(t, all, limit), full)
	}

	byModel, _, err := pageOf(t, func(request model.PageRequest) (model.Page[*model.Route], error) {
		return store.ListRoutesPage(ctx, model.RouteFilter{PageRequest: request, ModelNameID: modelName.ID})
	}, func(item *model.Route) string { return strconv.FormatInt(item.ID, 10) })("", maximumPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(byModel) != 3 {
		t.Errorf("model_name_id filter 得到 %v, want 3 项", byModel)
	}
	firstUpstream, err := store.GetRoute(routeIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	byUpstream, _, err := pageOf(t, func(request model.PageRequest) (model.Page[*model.Route], error) {
		return store.ListRoutesPage(ctx,
			model.RouteFilter{PageRequest: request, UpstreamID: firstUpstream.UpstreamID})
	}, func(item *model.Route) string { return strconv.FormatInt(item.ID, 10) })("", maximumPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(byUpstream) != 1 {
		t.Errorf("upstream_id filter 得到 %v, want 1 项", byUpstream)
	}
	no := false
	disabledOnly, _, err := pageOf(t, func(request model.PageRequest) (model.Page[*model.Route], error) {
		return store.ListRoutesPage(ctx, model.RouteFilter{PageRequest: request, Enabled: &no})
	}, func(item *model.Route) string { return strconv.FormatInt(item.ID, 10) })("", maximumPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(disabledOnly) != 1 || disabledOnly[0] != strconv.FormatInt(routeIDs[2], 10) {
		t.Errorf("enabled=false 得到 %v, want [%d]", disabledOnly, routeIDs[2])
	}

	changed := pageOf(t, func(request model.PageRequest) (model.Page[*model.Route], error) {
		return store.ListRoutesPage(ctx, model.RouteFilter{PageRequest: request, ModelNameID: modelName.ID})
	}, func(item *model.Route) string { return strconv.FormatInt(item.ID, 10) })
	assertCursorRejections(t, "routes", all, crossResourceCursor(t, store), changed)
}

// TestListProbeExecutionsPageContract 关键是 tie-breaker：同一轮 tick 发出的探活
// sent_at_ms 相同，只按时间排必然重复或漏项。
func TestListProbeExecutionsPageContract(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	upstream := mkUpstream(t, store, "exec-page")
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(model.DefaultSettings(), selector)
	if err != nil {
		t.Fatal(err)
	}
	revision := model.ReachabilityRevision{
		NetworkRevision:     upstream.NetworkRevision,
		SettingsFingerprint: revisioncodec.ReachabilitySettingsFingerprint(policy),
	}
	expectation := &model.ReachabilityExpectation{
		UpstreamID: upstream.ID, PolicySelector: selector, Revision: revision,
		ObservationToken: revisioncodec.NewReachabilityToken(revision),
	}
	// 六条 execution，两两共用同一个 sent_at_ms。
	for index := 1; index <= 6; index++ {
		execution := minimalReachabilityExecution(t, store, upstream, expectation,
			"exec-"+strconv.Itoa(index), "evidence-"+strconv.Itoa(index), int64(index))
		execution.SentAtMS = int64((index+1)/2) * 1000
		if index == 5 {
			execution.Trigger = model.TriggerManual
		}
		if index == 6 {
			execution.ErrorClass = model.ErrorTransient
			execution.Success, execution.Reachable = false, false
		}
		if err := store.InsertProbeExecution(ctx, &execution); err != nil {
			t.Fatalf("插入 exec-%d: %v", index, err)
		}
	}

	all := pageOf(t, func(request model.PageRequest) (model.Page[*model.ProbeExecution], error) {
		return store.ListProbeExecutions(ctx, model.ProbeExecutionFilter{PageRequest: request})
	}, func(item *model.ProbeExecution) string { return item.ID })
	full, _, err := all("", maximumPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != 6 {
		t.Fatalf("全量 = %v, want 6 项", full)
	}
	for _, limit := range []int{1, 2, 3, 5} {
		assertNoDuplicateOrGap(t, "probe-executions", walkAll(t, all, limit), full)
	}

	// 逐个服务端 filter。
	for _, testCase := range []struct {
		label  string
		filter model.ProbeExecutionFilter
		want   int
	}{
		{"upstream", model.ProbeExecutionFilter{UpstreamID: upstream.ID}, 6},
		{"endpoint", model.ProbeExecutionFilter{Endpoint: model.EndpointModels}, 6},
		{"endpoint 无匹配", model.ProbeExecutionFilter{Endpoint: model.EndpointResponses}, 0},
		{"trigger", model.ProbeExecutionFilter{Trigger: model.TriggerManual}, 1},
		{"error class", model.ProbeExecutionFilter{ErrorClass: model.ErrorTransient}, 1},
		{"capability state", model.ProbeExecutionFilter{CapabilityState: model.CapabilityUnknown}, 6},
	} {
		page, err := store.ListProbeExecutions(ctx, testCase.filter)
		if err != nil {
			t.Fatalf("%s filter: %v", testCase.label, err)
		}
		if len(page.Items) != testCase.want {
			t.Errorf("%s filter 得到 %d 项, want %d", testCase.label, len(page.Items), testCase.want)
		}
		if testCase.want == 0 && page.NextCursor != "" {
			t.Errorf("%s 空页仍带 NextCursor", testCase.label)
		}
	}
	if _, err := store.ListProbeExecutions(ctx, model.ProbeExecutionFilter{Trigger: "bogus"}); err == nil {
		t.Error("非法 trigger filter 应报错")
	}

	// GetProbeExecution round-trip：分页与单取必须读出同一条。
	single, err := store.GetProbeExecution(ctx, "exec-3")
	if err != nil {
		t.Fatal(err)
	}
	if single.ID != "exec-3" || single.UpstreamID != upstream.ID || single.Endpoint != model.EndpointModels {
		t.Errorf("GetProbeExecution = %+v", single)
	}
	if _, err := store.GetProbeExecution(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("不存在的 execution error = %v, want ErrNotFound", err)
	}

	changed := pageOf(t, func(request model.PageRequest) (model.Page[*model.ProbeExecution], error) {
		return store.ListProbeExecutions(ctx,
			model.ProbeExecutionFilter{PageRequest: request, UpstreamID: upstream.ID})
	}, func(item *model.ProbeExecution) string { return item.ID })
	assertCursorRejections(t, "probe-executions", all, crossResourceCursor(t, store), changed)
}

func TestListProbeCostDailyPageContract(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	days := []string{"2026-08-17", "2026-08-18", "2026-08-19"}
	for _, day := range days {
		for _, endpoint := range []model.EndpointKind{model.EndpointModels, model.EndpointMessages} {
			// 只传维度：省下的次数固定为 1，计数由 store 侧累加，
			// 调用方带计数会被 CostEvidenceFromPiggyback 拒掉。
			value := model.ProbeCostDaily{
				DayUTC: day, Trigger: model.TriggerScheduled, Origin: model.RecipeBasic,
				Endpoint: endpoint,
			}
			if err := store.RecordProbePiggybackSaving(ctx, "saving:"+day+":"+string(endpoint), value); err != nil {
				t.Fatalf("记 %s/%s: %v", day, endpoint, err)
			}
		}
	}

	all := pageOf(t, func(request model.PageRequest) (model.Page[*model.ProbeCostDaily], error) {
		return store.ListProbeCostDaily(ctx, model.ProbeCostFilter{PageRequest: request})
	}, func(item *model.ProbeCostDaily) string { return item.DayUTC + "/" + string(item.Endpoint) })
	full, _, err := all("", maximumPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != 6 {
		t.Fatalf("全量 = %v, want 6 项", full)
	}
	for _, limit := range []int{1, 2, 4} {
		assertNoDuplicateOrGap(t, "probe-cost-daily", walkAll(t, all, limit), full)
	}

	windowed, err := store.ListProbeCostDaily(ctx,
		model.ProbeCostFilter{DayFrom: "2026-08-18", DayTo: "2026-08-18"})
	if err != nil {
		t.Fatal(err)
	}
	if len(windowed.Items) != 2 {
		t.Errorf("单日窗口得到 %d 项, want 2", len(windowed.Items))
	}
	byEndpoint, err := store.ListProbeCostDaily(ctx, model.ProbeCostFilter{Endpoint: model.EndpointModels})
	if err != nil {
		t.Fatal(err)
	}
	if len(byEndpoint.Items) != 3 {
		t.Errorf("endpoint filter 得到 %d 项, want 3", len(byEndpoint.Items))
	}
	empty, err := store.ListProbeCostDaily(ctx, model.ProbeCostFilter{DayFrom: "2027-01-01"})
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.Items) != 0 || empty.NextCursor != "" {
		t.Errorf("空窗口 = %d 项 next=%q", len(empty.Items), empty.NextCursor)
	}
	if _, err := store.ListProbeCostDaily(ctx, model.ProbeCostFilter{Origin: "bogus"}); err == nil {
		t.Error("非法 origin filter 应报错")
	}

	// 同 event_id 重复记账只累加一次；维度变了要报 idempotency 冲突。
	repeat := model.ProbeCostDaily{
		DayUTC: "2026-08-19", Trigger: model.TriggerScheduled, Origin: model.RecipeBasic,
		Endpoint: model.EndpointModels,
	}
	if err := store.RecordProbePiggybackSaving(ctx, "saving:2026-08-19:models", repeat); err != nil {
		t.Fatal(err)
	}
	var saved int64
	if err := store.db.QueryRow(`SELECT piggyback_l2_saved FROM probe_cost_daily
		WHERE day_utc='2026-08-19' AND endpoint='models'`).Scan(&saved); err != nil {
		t.Fatal(err)
	}
	if saved != 1 {
		t.Errorf("重复 event_id 后 piggyback_l2_saved = %d, want 1", saved)
	}
	conflicting := repeat
	conflicting.Endpoint = model.EndpointMessages
	if err := store.RecordProbePiggybackSaving(ctx, "saving:2026-08-19:models", conflicting); !errors.Is(err, ErrIdempotencyConflict) {
		t.Errorf("同 ID 不同维度 error = %v, want ErrIdempotencyConflict", err)
	}
	if err := store.RecordProbePiggybackSaving(ctx, "", repeat); err == nil {
		t.Error("空 event_id 应报错")
	}
	if err := store.RecordProbePiggybackSaving(ctx, "with-counter",
		model.ProbeCostDaily{DayUTC: "2026-08-19", Trigger: model.TriggerScheduled,
			Origin: model.RecipeBasic, Endpoint: model.EndpointModels, Requests: 1}); err == nil {
		t.Error("调用方自带计数应被拒 —— 计数只能由 store 累加")
	}

	changed := pageOf(t, func(request model.PageRequest) (model.Page[*model.ProbeCostDaily], error) {
		return store.ListProbeCostDaily(ctx,
			model.ProbeCostFilter{PageRequest: request, Endpoint: model.EndpointModels})
	}, func(item *model.ProbeCostDaily) string { return item.DayUTC })
	assertCursorRejections(t, "probe-cost-daily", all, crossResourceCursor(t, store), changed)
}

// TestPageQueryPlansUseKeysetIndexes 是验收项 23 的索引部分：常用过滤组合必须
// 走对应索引，不能退化成全表扫。EXPLAIN QUERY PLAN 里出现 "SCAN" 且没有
// "USING ... INDEX" 就说明退化了。
func TestPageQueryPlansUseKeysetIndexes(t *testing.T) {
	store := testStore(t)
	cases := []struct {
		label string
		query string
		args  []any
	}{
		{"endpoints by upstream", `SELECT id FROM upstream_endpoint WHERE upstream_id=? AND id>? ORDER BY id LIMIT ?`,
			[]any{int64(1), int64(0), 51}},
		{"endpoints by review", `SELECT id FROM upstream_endpoint WHERE needs_review=? AND id>? ORDER BY id LIMIT ?`,
			[]any{true, int64(0), 51}},
		{"probe secrets by name", `SELECT id FROM probe_secret WHERE name>=? AND name<? ORDER BY name,id LIMIT ?`,
			[]any{"a", "b", 51}},
		{"recipes by status", `SELECT id FROM probe_recipe WHERE status=? AND id>? ORDER BY id LIMIT ?`,
			[]any{"published", int64(0), 51}},
		{"recipe versions by recipe", `SELECT id FROM probe_recipe_version WHERE recipe_id=? ORDER BY version,id LIMIT ?`,
			[]any{int64(1), 51}},
		{"executions by upstream", `SELECT id FROM probe_execution WHERE upstream_id=?
			ORDER BY sent_at_ms DESC,id DESC LIMIT ?`, []any{int64(1), 51}},
		{"executions by endpoint", `SELECT id FROM probe_execution WHERE endpoint=?
			ORDER BY sent_at_ms DESC,id DESC LIMIT ?`, []any{"messages", 51}},
		{"executions by error class", `SELECT id FROM probe_execution WHERE error_class=?
			ORDER BY sent_at_ms DESC,id DESC LIMIT ?`, []any{"none", 51}},
		{"executions by trigger", `SELECT id FROM probe_execution WHERE trigger=?
			ORDER BY sent_at_ms DESC,id DESC LIMIT ?`, []any{"scheduled", 51}},
		{"reachability by state", `SELECT upstream_id FROM upstream_reachability WHERE state=?
			ORDER BY upstream_id LIMIT ?`, []any{"reachable", 51}},
		{"cost by day", `SELECT day_utc FROM probe_cost_daily WHERE day_utc<=?
			ORDER BY day_utc DESC,trigger DESC,origin DESC,endpoint DESC,route_id DESC,upstream_id DESC LIMIT ?`,
			[]any{"2026-08-19", 51}},
	}
	for _, testCase := range cases {
		rows, err := store.db.Query(`EXPLAIN QUERY PLAN `+testCase.query, testCase.args...)
		if err != nil {
			t.Fatalf("%s: %v", testCase.label, err)
		}
		var plan strings.Builder
		for rows.Next() {
			var id, parent, notUsed int
			var detail string
			if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
				rows.Close()
				t.Fatalf("%s: %v", testCase.label, err)
			}
			plan.WriteString(detail)
			plan.WriteString("\n")
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatalf("%s: %v", testCase.label, err)
		}
		text := plan.String()
		if !strings.Contains(text, "USING INDEX") && !strings.Contains(text, "USING COVERING INDEX") &&
			!strings.Contains(text, "USING PRIMARY KEY") && !strings.Contains(text, "USING INTEGER PRIMARY KEY") {
			t.Errorf("%s 未使用索引，计划为:\n%s", testCase.label, text)
		}
		if strings.Contains(text, "USE TEMP B-TREE") {
			t.Errorf("%s 需要临时 B-tree 排序，说明 ORDER BY 没走索引:\n%s", testCase.label, text)
		}
	}
}
