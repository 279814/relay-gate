package store

// P0-02 验收项 23 对 ListCapabilities / ListReachability 的补充覆盖。
//
// 这两个方法此前一条测试都没有，而它们各有一处只靠读代码看不出来的约束：
// Capability 的 Expired 过滤要和「当前时刻」比较，Reachability 的 Current
// 过滤要和 Upstream 当前 network_revision 比较（相关子查询里也有 upstream_id，
// 列名必须带 r. 别名，否则 SQLite 会解析到外层那个）。

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// insertCapabilityRow 直接插一行 capability。
//
// 不走 CommitProbeObservation：那条路要先备齐 expectation/policy/token，
// 而这里要测的是查询侧的过滤与翻页，用最小行更能看清测的是什么。
func insertCapabilityRow(t *testing.T, store *Store, upstreamID, endpointID int64,
	endpoint model.EndpointKind, state model.CapabilityState, expiresAt int64) {
	t.Helper()
	if _, err := store.db.Exec(`INSERT INTO endpoint_capability
		(scope_upstream_id,endpoint,endpoint_id,evidence_kind,state,observation_token,
		 upstream_network_revision,upstream_credential_revision,endpoint_revision,
		 auth_profile_revision,recipe_binding_revision,probe_settings_fingerprint,
		 probe_secret_revisions_hash,observed_at,expires_at)
		VALUES (?,?,?,'l2',?,'tok',1,1,1,1,1,'fp','sh',?,?)`,
		upstreamID, endpoint, endpointID, state, expiresAt, expiresAt); err != nil {
		t.Fatal(err)
	}
}

func TestListCapabilitiesFiltersAndPaging(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	upstream := mkUpstream(t, store, "cap-page")
	endpoint := endpointOf(t, store, upstream.ID, model.EndpointModels)
	now := nowMS()

	// 五个 endpoint 各一行：三条已过期、一条未过期、一条无 TTL（expires_at=0）。
	insertCapabilityRow(t, store, upstream.ID, endpoint.ID, model.EndpointModels,
		model.CapabilitySupported, now-3000)
	insertCapabilityRow(t, store, upstream.ID, endpoint.ID, model.EndpointMessages,
		model.CapabilitySupported, now-2000)
	insertCapabilityRow(t, store, upstream.ID, endpoint.ID, model.EndpointResponses,
		model.CapabilityUnsupported, now-1000)
	insertCapabilityRow(t, store, upstream.ID, endpoint.ID, model.EndpointChatCompletions,
		model.CapabilitySupported, now+600000)
	insertCapabilityRow(t, store, upstream.ID, endpoint.ID, model.EndpointCountTokens,
		model.CapabilitySupported, 0)

	all := pageOf(t, func(request model.PageRequest) (model.Page[*model.EndpointCapability], error) {
		return store.ListCapabilities(ctx, model.CapabilityFilter{PageRequest: request})
	}, func(item *model.EndpointCapability) string { return string(item.Endpoint) })
	full, _, err := all("", maximumPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != 5 {
		t.Fatalf("全量 = %v, want 5 项", full)
	}
	for _, limit := range []int{1, 2, 3, 5} {
		assertNoDuplicateOrGap(t, "capabilities", walkAll(t, all, limit), full)
	}

	keys, next, err := all("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 5 || next != "" {
		t.Errorf("默认 limit 返回 %d 项 next=%q, want 5 项且无 cursor", len(keys), next)
	}

	for _, testCase := range []struct {
		label  string
		filter model.CapabilityFilter
		want   int
	}{
		{"upstream", model.CapabilityFilter{UpstreamID: upstream.ID}, 5},
		{"route 无匹配", model.CapabilityFilter{RouteID: 999}, 0},
		{"endpoint", model.CapabilityFilter{Endpoint: model.EndpointMessages}, 1},
		{"state=supported", model.CapabilityFilter{State: model.CapabilitySupported}, 4},
		{"state=unsupported", model.CapabilityFilter{State: model.CapabilityUnsupported}, 1},
	} {
		page, err := store.ListCapabilities(ctx, testCase.filter)
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
	if _, err := store.ListCapabilities(ctx, model.CapabilityFilter{Endpoint: "bogus"}); err == nil {
		t.Error("非法 endpoint filter 应报错")
	}

	// expires_at=0 表示「无 TTL」，永远不算过期。
	yes, no := true, false
	expired, err := store.ListCapabilities(ctx, model.CapabilityFilter{Expired: &yes})
	if err != nil {
		t.Fatal(err)
	}
	if len(expired.Items) != 3 {
		t.Errorf("Expired=true 得到 %d 项, want 3（无 TTL 的不算过期）", len(expired.Items))
	}
	fresh, err := store.ListCapabilities(ctx, model.CapabilityFilter{Expired: &no})
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh.Items) != 2 {
		t.Errorf("Expired=false 得到 %d 项, want 2（未过期 + 无 TTL）", len(fresh.Items))
	}

	changed := pageOf(t, func(request model.PageRequest) (model.Page[*model.EndpointCapability], error) {
		return store.ListCapabilities(ctx,
			model.CapabilityFilter{PageRequest: request, UpstreamID: upstream.ID})
	}, func(item *model.EndpointCapability) string { return string(item.Endpoint) })
	assertCursorRejections(t, "capabilities", all, crossResourceCursor(t, store), changed)
}

// TestListCapabilitiesExpiredPagingIsStableAcrossTime 是本次审查发现的缺陷回归。
//
// Expired 过滤要和「当前时刻」比较。若每页都重新取当前时间，翻页途中状态改变
// 的行就会改变结果集。分页是 id DESC，后续页只读 id 比 cursor 小的行，所以
// 漏项发生在「尚未读到的行在途中过期」这个方向：它在首页时满足 Expired=false，
// 翻第二页时不再满足，于是永远读不到 —— 用户看到的是少了一行，且不会报错。
//
// 判定时刻必须在首页固定下来并随 cursor 传递。
func TestListCapabilitiesExpiredPagingIsStableAcrossTime(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	upstream := mkUpstream(t, store, "cap-time")
	endpoint := endpointOf(t, store, upstream.ID, model.EndpointModels)
	now := nowMS()

	// 四条都未过期，id 依次为 1..4。其中 messages（id=2）的 TTL 只剩 150ms：
	// 它会在两次翻页之间自然到期。真实环境里流逝的是「当前时刻」而不是
	// expires_at，所以这里也只让时间走，不改数据。
	ordered := []model.EndpointKind{
		model.EndpointModels, model.EndpointMessages,
		model.EndpointResponses, model.EndpointChatCompletions,
	}
	for index, kind := range ordered {
		expiresAt := now + int64(600000+index)
		if kind == model.EndpointMessages {
			expiresAt = now + 150
		}
		insertCapabilityRow(t, store, upstream.ID, endpoint.ID, kind,
			model.CapabilitySupported, expiresAt)
	}

	no := false
	first, err := store.ListCapabilities(ctx,
		model.CapabilityFilter{PageRequest: model.PageRequest{Limit: 2}, Expired: &no})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatalf("第一页 = %d 项 next=%v, want 2 项且有 cursor", len(first.Items), first.NextCursor != "")
	}

	// 等到 messages 自然到期。它 id=2，比首页游标（id=3）小，属于「尚未读到」，
	// 所以判定时刻若不固定，第二页就再也看不到它。
	time.Sleep(300 * time.Millisecond)

	second, err := store.ListCapabilities(ctx, model.CapabilityFilter{
		PageRequest: model.PageRequest{Limit: 2, Cursor: first.NextCursor}, Expired: &no,
	})
	if err != nil {
		t.Fatalf("第二页失败: %v", err)
	}

	seen := map[model.EndpointKind]bool{}
	for _, item := range first.Items {
		seen[item.Endpoint] = true
	}
	for _, item := range second.Items {
		if seen[item.Endpoint] {
			t.Errorf("endpoint %s 跨页重复", item.Endpoint)
		}
		seen[item.Endpoint] = true
	}
	for _, want := range ordered {
		if !seen[want] {
			t.Errorf("%s 在首页判定时刻仍未过期，却在翻页结果里缺失 —— 判定时刻没有随 cursor 固定", want)
		}
	}
}

func insertReachabilityRow(t *testing.T, store *Store, upstreamID, observedNetworkRevision int64,
	state model.ReachabilityState) {
	t.Helper()
	if _, err := store.db.Exec(`INSERT INTO upstream_reachability
		(upstream_id,evidence_kind,endpoint,state,observed_network_revision,
		 settings_fingerprint,observation_token)
		VALUES (?,'l1','models',?,?,'fp','tok')`,
		upstreamID, state, observedNetworkRevision); err != nil {
		t.Fatal(err)
	}
}

func TestListReachabilityFiltersAndPaging(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	reachable := mkUpstream(t, store, "reach-a")
	unreachable := mkUpstream(t, store, "reach-b")
	staleRevision := mkUpstream(t, store, "reach-c")

	insertReachabilityRow(t, store, reachable.ID, reachable.NetworkRevision, model.ReachabilityReachable)
	insertReachabilityRow(t, store, unreachable.ID, unreachable.NetworkRevision, model.ReachabilityUnreachable)
	// observed_network_revision 落后于 Upstream 当前值：改过 base_url/代理之后，
	// 旧观察结果不再代表现在的连通性。
	insertReachabilityRow(t, store, staleRevision.ID, staleRevision.NetworkRevision+1, model.ReachabilityReachable)

	all := pageOf(t, func(request model.PageRequest) (model.Page[*model.UpstreamReachability], error) {
		return store.ListReachability(ctx, model.ReachabilityFilter{PageRequest: request})
	}, func(item *model.UpstreamReachability) string { return strconv.FormatInt(item.UpstreamID, 10) })
	full, _, err := all("", maximumPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != 3 {
		t.Fatalf("全量 = %v, want 3 项", full)
	}
	for _, limit := range []int{1, 2, 3} {
		assertNoDuplicateOrGap(t, "reachability", walkAll(t, all, limit), full)
	}

	yes, no := true, false
	for _, testCase := range []struct {
		label  string
		filter model.ReachabilityFilter
		want   int
	}{
		{"upstream", model.ReachabilityFilter{UpstreamID: reachable.ID}, 1},
		{"upstream 无匹配", model.ReachabilityFilter{UpstreamID: 99999}, 0},
		{"state=reachable", model.ReachabilityFilter{State: model.ReachabilityReachable}, 2},
		{"state=unreachable", model.ReachabilityFilter{State: model.ReachabilityUnreachable}, 1},
		{"current=true", model.ReachabilityFilter{Current: &yes}, 2},
		{"current=false", model.ReachabilityFilter{Current: &no}, 1},
	} {
		page, err := store.ListReachability(ctx, testCase.filter)
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

	// current=false 必须精确命中那个 revision 落后的站。
	stale, err := store.ListReachability(ctx, model.ReachabilityFilter{Current: &no})
	if err != nil {
		t.Fatal(err)
	}
	if len(stale.Items) != 1 || stale.Items[0].UpstreamID != staleRevision.ID {
		t.Errorf("current=false 得到 %+v, want 仅 upstream %d", stale.Items, staleRevision.ID)
	}

	// UpstreamID 与 Current 组合：证明 r. 别名让相关子查询绑到正确的那一列。
	combined, err := store.ListReachability(ctx,
		model.ReachabilityFilter{UpstreamID: staleRevision.ID, Current: &no})
	if err != nil {
		t.Fatalf("组合 filter 失败（相关子查询列名歧义？）: %v", err)
	}
	if len(combined.Items) != 1 {
		t.Errorf("组合 filter 得到 %d 项, want 1", len(combined.Items))
	}

	changed := pageOf(t, func(request model.PageRequest) (model.Page[*model.UpstreamReachability], error) {
		return store.ListReachability(ctx,
			model.ReachabilityFilter{PageRequest: request, State: model.ReachabilityReachable})
	}, func(item *model.UpstreamReachability) string { return strconv.FormatInt(item.UpstreamID, 10) })
	assertCursorRejections(t, "reachability", all, crossResourceCursor(t, store), changed)
	if !errors.Is(errCursorSanity(t, store, ctx), ErrInvalidCursor) {
		t.Error("Reachability 的坏 cursor 应回 ErrInvalidCursor")
	}
}

// errCursorSanity 单独验证一次 keyset 键坏掉（非数字 upstream_id）的情形：
// cursor 是客户端可见的，里面的数字未必还是数字。
func errCursorSanity(t *testing.T, store *Store, ctx context.Context) error {
	t.Helper()
	bad, err := encodePageCursor("reachability", model.ReachabilityFilter{}, "not-a-number")
	if err != nil {
		t.Fatal(err)
	}
	_, listErr := store.ListReachability(ctx,
		model.ReachabilityFilter{PageRequest: model.PageRequest{Cursor: bad}})
	return listErr
}
