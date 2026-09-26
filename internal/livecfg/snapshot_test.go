package livecfg

import (
	"strings"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

// UpstreamEndpoint.AuthProfile.ManualHeaders 是 slice：浅拷贝会与 bundle 共享
// backing。发布后改 bundle 侧元素不得污染 probe 快照。
func TestBuildPublishedConfig_EndpointManualHeadersNotSharedWithBundle(t *testing.T) {
	headers := []model.HeaderTemplate{{Name: "X-Test", Values: []string{"before"}}}
	ep := &model.UpstreamEndpoint{
		ID: 1, UpstreamID: 1, Kind: model.EndpointMessages,
		AuthProfile: model.EndpointAuthProfile{
			Mode: model.AuthModeBearer, SecretRef: "api_key", ManualHeaders: headers,
		},
	}
	bundle := &store.ConfigBundle{
		Upstreams:  []*model.Upstream{{ID: 1, Name: "s1", BaseURL: "https://s1.example.com", Enabled: true}},
		ModelNames: []*model.ModelName{{ID: 1, Name: "m1", Protocol: model.ProtoAnthropic, Enabled: true}},
		Routes:     []*model.Route{{ID: 1, ModelNameID: 1, UpstreamID: 1, Enabled: true}},
		Endpoints:  []*model.UpstreamEndpoint{ep},
		Settings:   model.DefaultSettings(),
	}
	pub, err := buildPublishedConfig(bundle, 1, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	got := pub.Probe.Endpoints[1][model.EndpointMessages]
	if got == nil || len(got.AuthProfile.ManualHeaders) != 1 {
		t.Fatal("probe endpoint ManualHeaders missing")
	}
	if got.AuthProfile.ManualHeaders[0].Name != "X-Test" {
		t.Fatalf("want X-Test, got %q", got.AuthProfile.ManualHeaders[0].Name)
	}
	headers[0].Name = "after-bundle-mutate"
	if got.AuthProfile.ManualHeaders[0].Name != "X-Test" {
		t.Fatalf("probe ManualHeaders must not share slice with bundle: got %q",
			got.AuthProfile.ManualHeaders[0].Name)
	}
}

// ModelName / Route 无 slice/map 字段；Upstream.ProbeHeaders 是 map，浅拷贝会与
// bundle 共享 backing。发布后改 bundle 侧元素不得污染 routing 快照。
func TestBuildPublishedConfig_ProbeHeadersNotSharedWithBundle(t *testing.T) {
	headers := map[string]string{"user-agent": "before"}
	up := &model.Upstream{
		ID: 1, Name: "s1", BaseURL: "https://s1.example.com",
		Enabled: true, ProbeHeaders: headers,
	}
	mn := &model.ModelName{ID: 1, Name: "m1", Protocol: model.ProtoAnthropic, Enabled: true}
	rt := &model.Route{ID: 1, ModelNameID: 1, UpstreamID: 1, Enabled: true}
	bundle := &store.ConfigBundle{
		Upstreams:  []*model.Upstream{up},
		ModelNames: []*model.ModelName{mn},
		Routes:     []*model.Route{rt},
		Settings:   model.DefaultSettings(),
	}
	pub, err := buildPublishedConfig(bundle, 1, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	routed := pub.Routing.Upstreams[1]
	if routed == nil || routed.ProbeHeaders == nil {
		t.Fatal("routing upstream ProbeHeaders missing")
	}
	if routed.ProbeHeaders["user-agent"] != "before" {
		t.Fatalf("want before, got %q", routed.ProbeHeaders["user-agent"])
	}
	headers["user-agent"] = "after-bundle-mutate"
	if routed.ProbeHeaders["user-agent"] != "before" {
		t.Fatalf("routing ProbeHeaders must not share map with bundle: got %q",
			routed.ProbeHeaders["user-agent"])
	}
}

func TestProbeSnapshot_NoSecretPlaintextAndExpectations(t *testing.T) {
	st := testStore(t)
	_, upID, rtID := seed(t, st)
	s, _ := newSource(t, st)
	if err := s.Refresh(); err != nil {
		t.Fatal(err)
	}
	snap, err := s.ProbeSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	up := snap.Upstreams[upID]
	if up == nil {
		t.Fatal("missing upstream in probe snapshot")
	}
	// ProbeUpstreamConfig 没有 APIKey 字段；路由快照才有。
	routing, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if routing.Upstreams[upID].APIKey == "" {
		t.Fatal("routing snapshot still needs decrypted key")
	}
	if strings.Contains(routing.Upstreams[upID].APIKey, "enc:") {
		t.Fatal("routing key should be plaintext for outbound, not ciphertext marker")
	}

	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	reach, err := snap.ReachabilityExpectation(upID, selector)
	if err != nil {
		t.Fatal(err)
	}
	if reach.ObservationToken == "" || reach.Revision.NetworkRevision != up.NetworkRevision ||
		reach.Revision.CreatedAt != up.CreatedAt {
		t.Fatalf("reachability expectation=%+v upstream created_at=%d", reach, up.CreatedAt)
	}

	rt := snap.Routes[rtID]
	if rt == nil {
		t.Fatal("missing route in probe snapshot")
	}
	capSel := model.EvidencePolicySelector{
		Kind: model.EvidenceL2, Endpoint: model.EndpointMessages, TimeoutProfile: model.TimeoutL2Standard,
	}
	cap, err := snap.SemanticExpectation(model.SemanticTarget{
		Scope: model.RecipeScopeRoute, UpstreamID: upID, RouteID: rtID, Endpoint: model.EndpointMessages,
	}, model.RecipeIdentity{
		Storage: model.RecipeStorageEmbedded, Origin: model.RecipeBasic,
		TemplateID: "builtin:messages", Revision: 1,
	}, model.RecipeBindingFacts{Use: model.BindingResolved, ResolvedLayer: model.ResolvedEmbedded}, capSel)
	if err != nil {
		t.Fatal(err)
	}
	if cap.Revision.RouteCapability != rt.CapabilityRevision || cap.Revision.RouteCreatedAt != rt.CreatedAt {
		t.Fatalf("capability expectation=%+v route created_at=%d", cap.Revision, rt.CreatedAt)
	}
	if cap.Revision.UpstreamCreatedAt != up.CreatedAt {
		t.Fatalf("capability UpstreamCreatedAt=%d want %d", cap.Revision.UpstreamCreatedAt, up.CreatedAt)
	}
	messagesEP := snap.Endpoints[upID][model.EndpointMessages]
	if messagesEP == nil || cap.Revision.EndpointCreatedAt != messagesEP.CreatedAt {
		t.Fatalf("capability EndpointCreatedAt=%d want endpoint created_at", cap.Revision.EndpointCreatedAt)
	}

	modelsCap, err := snap.SemanticExpectation(model.SemanticTarget{
		Scope: model.RecipeScopeUpstream, UpstreamID: upID, Endpoint: model.EndpointModels,
	}, model.RecipeIdentity{
		Storage: model.RecipeStorageEmbedded, Origin: model.RecipeBasic,
		TemplateID: "builtin:models", Revision: 1,
	}, model.RecipeBindingFacts{Use: model.BindingResolved, ResolvedLayer: model.ResolvedEmbedded}, selector)
	if err != nil {
		t.Fatal(err)
	}
	modelsEP := snap.Endpoints[upID][model.EndpointModels]
	if modelsCap.Revision.UpstreamCreatedAt != up.CreatedAt || modelsCap.Revision.RouteCreatedAt != 0 ||
		modelsEP == nil || modelsCap.Revision.EndpointCreatedAt != modelsEP.CreatedAt {
		t.Fatalf("upstream-scope capability=%+v", modelsCap.Revision)
	}

	s.Invalidate()
	if _, err := s.ProbeSnapshot(); err == nil {
		t.Fatal("invalidate must make probe snapshot unavailable")
	}
	if _, err := s.Snapshot(); err != nil {
		t.Fatalf("routing must remain readable after invalidate: %v", err)
	}
	if err := s.Refresh(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ProbeSnapshot(); err != nil {
		t.Fatalf("refresh must restore probe snapshot: %v", err)
	}
}
