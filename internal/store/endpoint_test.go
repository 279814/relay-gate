package store

import (
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestLegacyCreateUpstreamAtomicallyCreatesCanonicalEndpoints(t *testing.T) {
	store := testStore(t)
	upstream := &model.Upstream{
		Name: "bundle", BaseURL: "https://bundle.example", APIKey: "sk-bundle", Enabled: true,
		AuthStyle: model.AuthBearer,
	}
	if err := store.CreateUpstream(upstream); err != nil {
		t.Fatal(err)
	}
	page, err := store.ListEndpointsPage(context.Background(), model.EndpointFilter{UpstreamID: upstream.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 5 {
		t.Fatalf("endpoint count = %d, want 5", len(page.Items))
	}
	seen := map[model.EndpointKind]bool{}
	for _, endpoint := range page.Items {
		seen[endpoint.Kind] = true
		if endpoint.AuthProfile.Mode != model.AuthModeBearer || endpoint.AuthProfile.SecretRef != "upstream_api_key" {
			t.Fatalf("endpoint auth = %+v", endpoint.AuthProfile)
		}
		if endpoint.Revision != 1 || endpoint.AuthProfile.Revision != 1 {
			t.Fatalf("endpoint revisions = %+v", endpoint)
		}
	}
	for _, kind := range []model.EndpointKind{model.EndpointModels, model.EndpointMessages, model.EndpointResponses, model.EndpointChatCompletions, model.EndpointCountTokens} {
		if !seen[kind] {
			t.Errorf("missing endpoint %s", kind)
		}
	}
	got, err := store.GetUpstream(upstream.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != 1 || got.NetworkRevision != 1 || got.CredentialRevision != 1 {
		t.Fatalf("upstream revisions = %+v", got)
	}
}

func TestCreateUpstreamWithEndpointsRollsBackWholeBundle(t *testing.T) {
	store := testStore(t)
	upstream := &model.Upstream{Name: "rollback", BaseURL: "https://rollback.example", APIKey: "sk-rollback", Enabled: true}
	endpoints := canonicalEndpointBundle(upstream)
	endpoints[3].Kind = model.EndpointKind("invalid")
	if err := store.CreateUpstreamWithEndpoints(context.Background(), upstream, endpoints); !errors.Is(err, model.ErrValidation) {
		t.Fatalf("error = %v, want validation", err)
	}
	var upstreams, endpointCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM upstream WHERE name='rollback'`).Scan(&upstreams); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM upstream_endpoint`).Scan(&endpointCount); err != nil {
		t.Fatal(err)
	}
	if upstreams != 0 || endpointCount != 0 {
		t.Fatalf("partial bundle persisted: upstream=%d endpoints=%d", upstreams, endpointCount)
	}
}

func TestEndpointUpdateUsesRevisionCAS(t *testing.T) {
	store := testStore(t)
	upstream := mkUpstream(t, store, "endpoint-cas")
	page, err := store.ListEndpointsPage(context.Background(), model.EndpointFilter{
		UpstreamID: upstream.ID, Endpoint: model.EndpointMessages,
	})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("list endpoint = %v, err=%v", page.Items, err)
	}
	endpoint := page.Items[0]
	endpoint.FixedQueryTemplate = "beta=true"
	if err := store.UpdateEndpoint(endpoint, 1); err != nil {
		t.Fatal(err)
	}
	if endpoint.Revision != 2 {
		t.Fatalf("updated revision = %d", endpoint.Revision)
	}
	endpoint.FixedQueryTemplate = "beta=false"
	if err := store.UpdateEndpoint(endpoint, 1); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale update error = %v", err)
	}
	got, err := store.GetEndpoint(endpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.FixedQueryTemplate != "beta=true" || got.Revision != 2 {
		t.Fatalf("stale write changed endpoint: %+v", got)
	}
}

// 站级的 full_url_mode 与自定义 l1_path 必须在**创建**时就落成 url_override。
//
// 只在 UpdateUpstream 里翻译是不够的：EndpointResolver 只认 Endpoint 上的
// url_override，所以一个新建的 full_url_mode 站会被拼成 base+/v1/messages ——
// 而这个开关的全部用途正是「不要拼路径」。
func TestCreateUpstreamMaterializesLegacyURLSwitches(t *testing.T) {
	store := testStore(t)
	upstream := &model.Upstream{Name: "s", BaseURL: "https://a.com/custom/entry",
		APIKey: "sk-1", AuthStyle: model.AuthXAPIKey, FullURLMode: true,
		L1Path: "/status", Enabled: false}
	if err := store.CreateUpstream(upstream); err != nil {
		t.Fatal(err)
	}

	cases := map[model.EndpointKind]string{
		// full_url_mode：base_url 即完整端点
		model.EndpointMessages:        "https://a.com/custom/entry",
		model.EndpointCountTokens:     "https://a.com/custom/entry",
		model.EndpointResponses:       "https://a.com/custom/entry",
		model.EndpointChatCompletions: "https://a.com/custom/entry",
		// 自定义 l1_path 只影响 models
		model.EndpointModels: "https://a.com/custom/entry/status",
	}
	for kind, want := range cases {
		endpoint, err := store.Endpoint(context.Background(), upstream.ID, kind)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if endpoint.URLOverride != want {
			t.Errorf("%s 的 url_override want %q got %q", kind, want, endpoint.URLOverride)
		}
	}
}

// 改 base_url 时，override 值实际未变的 Endpoint 不得 bump revision。
//
// Endpoint revision 会失效对应的 Capability（§4.2）。无条件 bump 等于把
// 「改了一个字段」变成「五个端点全部重新探活」，而其中四个的 override
// 通常都是空、压根没变。
func TestUpdateUpstreamDoesNotBumpUnchangedEndpointOverrides(t *testing.T) {
	store := testStore(t)
	upstream := &model.Upstream{Name: "s", BaseURL: "https://a.com", APIKey: "sk-1",
		AuthStyle: model.AuthXAPIKey, L1Path: "/v1/models", Enabled: false}
	if err := store.CreateUpstream(upstream); err != nil {
		t.Fatal(err)
	}

	// 默认配置下五个 Endpoint 的 override 都是空
	before := make(map[model.EndpointKind]int64)
	for _, kind := range allEndpointKinds() {
		endpoint, err := store.Endpoint(context.Background(), upstream.ID, kind)
		if err != nil {
			t.Fatal(err)
		}
		if endpoint.URLOverride != "" {
			t.Fatalf("测试前提错误：%s 的 override 应为空，得到 %q", kind, endpoint.URLOverride)
		}
		before[kind] = endpoint.Revision
	}

	upstream.BaseURL = "https://b.com"
	if err := store.UpdateUpstream(upstream); err != nil {
		t.Fatal(err)
	}

	for _, kind := range allEndpointKinds() {
		endpoint, err := store.Endpoint(context.Background(), upstream.ID, kind)
		if err != nil {
			t.Fatal(err)
		}
		if endpoint.Revision != before[kind] {
			t.Errorf("%s 的 override 未变（仍为 %q）却 bump 了 revision：%d -> %d",
				kind, endpoint.URLOverride, before[kind], endpoint.Revision)
		}
	}
}

// 反面：override 真的改变时必须写入并 bump revision。
// 与上一条互为对照 —— 少了它，「一律不更新」也能让上一条通过。
func TestUpdateUpstreamRewritesChangedEndpointOverrides(t *testing.T) {
	store := testStore(t)
	upstream := &model.Upstream{Name: "s", BaseURL: "https://a.com", APIKey: "sk-1",
		AuthStyle: model.AuthXAPIKey, L1Path: "/status", Enabled: false}
	if err := store.CreateUpstream(upstream); err != nil {
		t.Fatal(err)
	}
	models, err := store.Endpoint(context.Background(), upstream.ID, model.EndpointModels)
	if err != nil {
		t.Fatal(err)
	}
	beforeRevision := models.Revision

	upstream.BaseURL = "https://b.com"
	if err := store.UpdateUpstream(upstream); err != nil {
		t.Fatal(err)
	}

	models, err = store.Endpoint(context.Background(), upstream.ID, model.EndpointModels)
	if err != nil {
		t.Fatal(err)
	}
	if models.URLOverride != "https://b.com/status" {
		t.Errorf("override 应跟随 base_url，得到 %q", models.URLOverride)
	}
	if models.Revision <= beforeRevision {
		t.Errorf("override 变了就必须 bump revision：%d -> %d", beforeRevision, models.Revision)
	}
}

func allEndpointKinds() []model.EndpointKind {
	return []model.EndpointKind{model.EndpointModels, model.EndpointMessages,
		model.EndpointResponses, model.EndpointChatCompletions, model.EndpointCountTokens}
}
