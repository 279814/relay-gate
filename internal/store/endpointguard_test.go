package store

// P0-02 验收项 13：Endpoint 硬删与「五端点齐备」的门禁。
//
// 这两件事是一体的：普通 Upstream 缺任一 Endpoint 时既不能建 Route 也不能
// enable，否则选路会拿到一个解析不出 URL 的站；而删 Endpoint 必须先证明
// Upstream 已停用、零 Route、零历史引用。

import (
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// disabledUpstreamWithEndpoints 建一个已停用的**普通** Upstream（含五个标准 Endpoint）。
//
// 必须显式给 AuthStyle：留空会被 Defaults 填成 auto，而 auto 映射到
// legacy_auto_real_only —— 那是「migration-only」形态，五端点齐备门禁对它
// 是刻意放行的（旧库可能本来就只有一个协议可用）。用 auto 建基线会让本组
// 测试测到另一条分支上去。
func disabledUpstreamWithEndpoints(t *testing.T, store *Store, name string) *model.Upstream {
	t.Helper()
	upstream := &model.Upstream{
		Name: name, BaseURL: "https://" + name + ".example.com",
		APIKey: "sk-" + name + "-secret-value", AuthStyle: model.AuthXAPIKey, Enabled: false,
	}
	if err := store.CreateUpstream(upstream); err != nil {
		t.Fatal(err)
	}
	current, err := store.GetUpstream(upstream.ID)
	if err != nil {
		t.Fatal(err)
	}
	return current
}

func endpointOf(t *testing.T, store *Store, upstreamID int64, kind model.EndpointKind) *model.UpstreamEndpoint {
	t.Helper()
	page, err := store.ListEndpointsPage(context.Background(),
		model.EndpointFilter{UpstreamID: upstreamID, Endpoint: kind})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("%s endpoint = %d 项, want 1", kind, len(page.Items))
	}
	return page.Items[0]
}

func TestDeleteEndpointRequiresDisabledUpstreamAndNoDependents(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	// Upstream 仍启用时不能删：它还在服务，删掉某个 Endpoint 会让该协议直接不可解析。
	enabled := mkUpstream(t, store, "still-enabled")
	target := endpointOf(t, store, enabled.ID, model.EndpointCountTokens)
	if err := store.DeleteEndpoint(target.ID, target.Revision); !errors.Is(err, ErrDependencyConflict) {
		t.Errorf("启用中的 Upstream 删 Endpoint error = %v, want ErrDependencyConflict", err)
	}

	// 停用后、且无任何引用时可以删。
	upstream := disabledUpstreamWithEndpoints(t, store, "deletable")
	deletable := endpointOf(t, store, upstream.ID, model.EndpointCountTokens)
	if err := store.DeleteEndpoint(deletable.ID, deletable.Revision+99); !errors.Is(err, ErrRevisionConflict) {
		t.Errorf("错的 expectedRevision error = %v, want ErrRevisionConflict", err)
	}
	if err := store.DeleteEndpoint(deletable.ID, deletable.Revision); err != nil {
		t.Fatalf("停用且无引用时应可删: %v", err)
	}
	if _, err := store.GetEndpoint(deletable.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("删除后 GetEndpoint error = %v, want ErrNotFound", err)
	}

	// 有 Route 时不能删。Route 依赖整套 Endpoint 解析 URL。
	withRoute := disabledUpstreamWithEndpoints(t, store, "has-route")
	modelName := mkModelName(t, store, "claude-opus-5", model.ProtoAnthropic)
	route := &model.Route{ModelNameID: modelName.ID, UpstreamID: withRoute.ID, Enabled: true}
	if err := store.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	routeBlocked := endpointOf(t, store, withRoute.ID, model.EndpointCountTokens)
	if err := store.DeleteEndpoint(routeBlocked.ID, routeBlocked.Revision); !errors.Is(err, ErrDependencyConflict) {
		t.Errorf("有 Route 时删 Endpoint error = %v, want ErrDependencyConflict", err)
	}

	// 有 execution 历史时不能删：那条记录用 RESTRICT 外键指着它。
	withHistory := disabledUpstreamWithEndpoints(t, store, "has-history")
	historyEndpoint := endpointOf(t, store, withHistory.ID, model.EndpointModels)
	execution := model.ProbeExecution{
		ID: "exec-history", Trigger: model.TriggerScheduled, UpstreamID: withHistory.ID,
		UpstreamNetworkRevision:    withHistory.NetworkRevision,
		UpstreamCredentialRevision: withHistory.CredentialRevision,
		EndpointID:                 historyEndpoint.ID, EndpointRevision: historyEndpoint.Revision,
		AuthProfileRevision: historyEndpoint.AuthProfile.Revision,
		Endpoint:            model.EndpointModels, RecipeBindingUse: model.BindingResolved,
		RecipeStorage: model.RecipeStorageEmbedded, RecipeOrigin: model.RecipeBasic,
		TemplateID: "builtin:models", RecipeIdentityRevision: 1,
		EvidenceHash: "evidence-history", ErrorClass: model.ErrorNone,
		Capability: model.CapabilityUnknown, Scope: model.ScopeUpstreamReachability,
		Reachable: true, Final: true, Success: true,
		ObservationOrder: 1, SentAtMS: 1, DoneAtMS: 2,
	}
	if err := store.InsertProbeExecution(ctx, &execution); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteEndpoint(historyEndpoint.ID, historyEndpoint.Revision); !errors.Is(err, ErrDependencyConflict) {
		t.Errorf("有 execution 历史时删 Endpoint error = %v, want ErrDependencyConflict", err)
	}
}

// TestIncompleteUpstreamCannotBeRoutedOrEnabled 是验收项 13 的另一半：
// 「普通 Upstream 缺任一五类 Endpoint 时 enable/CreateRoute 返回 409」。
func TestIncompleteUpstreamCannotBeRoutedOrEnabled(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	upstream := disabledUpstreamWithEndpoints(t, store, "incomplete")
	// 删掉一个 Endpoint，制造「缺一类」的状态。
	missing := endpointOf(t, store, upstream.ID, model.EndpointCountTokens)
	if err := store.DeleteEndpoint(missing.ID, missing.Revision); err != nil {
		t.Fatal(err)
	}

	modelName := mkModelName(t, store, "claude-opus-5", model.ProtoAnthropic)
	blocked := &model.Route{ModelNameID: modelName.ID, UpstreamID: upstream.ID, Enabled: true}
	if err := store.CreateRoute(blocked); !errors.Is(err, ErrDependencyConflict) {
		t.Errorf("缺 Endpoint 时 CreateRoute error = %v, want ErrDependencyConflict", err)
	}

	// enable 同样要被拦住。放行它等于让选路拿到一个解析不出 count_tokens
	// URL 的站 —— 客户端一调 count_tokens 就 500，而配置界面看起来完全正常。
	current, err := store.GetUpstream(upstream.ID)
	if err != nil {
		t.Fatal(err)
	}
	current.Enabled = true
	if err := store.UpdateUpstreamWithRevision(ctx, current, current.Revision); !errors.Is(err, ErrDependencyConflict) {
		t.Errorf("缺 Endpoint 时 enable error = %v, want ErrDependencyConflict", err)
	}
	// 确认没有被悄悄写进去。
	reread, err := store.GetUpstream(upstream.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reread.Enabled {
		t.Error("enable 被拒后 Upstream 仍被标记为启用")
	}

	// 补回 Endpoint 后两者都应放行。
	restored := &model.UpstreamEndpoint{
		UpstreamID: upstream.ID, Kind: model.EndpointCountTokens,
		URLMode: model.EndpointURLCanonical,
		AuthProfile: model.EndpointAuthProfile{
			Mode:      model.AuthModeXAPIKey,
			SecretRef: "upstream_api_key", Revision: 1,
		},
	}
	if err := store.CreateEndpoint(restored); err != nil {
		t.Fatal(err)
	}
	allowed := &model.Route{ModelNameID: modelName.ID, UpstreamID: upstream.ID, Enabled: true}
	if err := store.CreateRoute(allowed); err != nil {
		t.Fatalf("补齐 Endpoint 后 CreateRoute 应成功: %v", err)
	}
	current, err = store.GetUpstream(upstream.ID)
	if err != nil {
		t.Fatal(err)
	}
	current.Enabled = true
	if err := store.UpdateUpstreamWithRevision(ctx, current, current.Revision); err != nil {
		t.Fatalf("补齐 Endpoint 后 enable 应成功: %v", err)
	}
}

// TestMigrationOnlyEndpointCannotBeDeleted 守「migration-only Endpoint 不可删」：
// 它承载 legacy full URL 的原样兼容，删掉就再也拼不出旧站的地址。
func TestMigrationOnlyEndpointCannotBeDeleted(t *testing.T) {
	store := testStore(t)
	upstream := disabledUpstreamWithEndpoints(t, store, "migration-only")
	endpoint := endpointOf(t, store, upstream.ID, model.EndpointModels)
	// needs_review 是 migration 物化时打的标记，代表这条需要人工确认。
	if _, err := store.db.Exec(`UPDATE upstream_endpoint SET needs_review=1,revision=revision+1 WHERE id=?`,
		endpoint.ID); err != nil {
		t.Fatal(err)
	}
	flagged, err := store.GetEndpoint(endpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteEndpoint(flagged.ID, flagged.Revision); !errors.Is(err, ErrDependencyConflict) {
		t.Errorf("needs_review 的 Endpoint 删除 error = %v, want ErrDependencyConflict", err)
	}
}
