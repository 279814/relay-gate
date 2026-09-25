package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
	"github.com/279814/relay-gate/internal/transform"
)

// recordingInvalidator 记录每次触发，用于断言「改这个字段会不会重探」。
type recordingInvalidator struct {
	mu         sync.Mutex
	routes     []int64
	upstreams  []int64
	modelNames []int64
}

func (r *recordingInvalidator) InvalidateRoute(id int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes = append(r.routes, id)
}

func (r *recordingInvalidator) InvalidateUpstream(id int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.upstreams = append(r.upstreams, id)
}

func (r *recordingInvalidator) InvalidateModelName(id int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.modelNames = append(r.modelNames, id)
}

func (r *recordingInvalidator) counts() (routes, ups, mns int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.routes), len(r.upstreams), len(r.modelNames)
}

// newInvalidatorServer 起一个接了 recordingInvalidator 的管理端。
func newInvalidatorServer(t *testing.T) (http.Handler, *recordingInvalidator) {
	t.Helper()
	s, _ := newTestServer(t)
	inv := &recordingInvalidator{}
	return s.WithInvalidator(inv).Routes(testAdminPW), inv
}

// mkUpstreamViaAPI 经 API 建一个 Upstream，返回 id。
func mkUpstreamViaAPI(t *testing.T, h http.Handler, body string) int64 {
	t.Helper()
	rec := do(t, h, "POST", "/admin/api/upstreams", body, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("建 upstream 失败 %d：%s", rec.Code, rec.Body.String())
	}
	return int64(decodeBody[map[string]any](t, rec)["id"].(float64))
}

func TestInvalidate_CreateRouteTriggersProbe(t *testing.T) {
	// 新建 Route 是最该探的时刻：用户刚配好，想知道的正是「这个映射通不通」。
	// 不探的话它以 unknown 状态直接参与选路（乐观策略），真实请求撞上去
	// 才发现配错了。
	h, inv := newInvalidatorServer(t)
	upID := mkUpstreamViaAPI(t, h, `{"name":"u1","base_url":"https://a.example.com","api_key":"sk-aaaaaaaaaaaa"}`)

	rec := do(t, h, "POST", "/admin/api/model-names",
		`{"name":"m1","protocol":"anthropic"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("建 model_name 失败：%s", rec.Body.String())
	}
	mnID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))

	rec = do(t, h, "POST", "/admin/api/routes", `{"model_name_id":`+
		itoa(mnID)+`,"upstream_id":`+itoa(upID)+`}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("建 route 失败：%s", rec.Body.String())
	}

	routes, _, _ := inv.counts()
	if routes != 1 {
		t.Errorf("新建 Route 应触发 1 次探活，得到 %d", routes)
	}
}

func TestInvalidate_UpstreamMaskedKeyEchoKeepsSecret(t *testing.T) {
	// GET 回显的 api_key 是 MaskKey 结果；PUT 原样带回时绝不能覆盖密文，
	// 也不能当成「key 变了」去触发整站重探。
	s, h := newTestServer(t)
	const plain = "sk-aaaaaaaaaaaa"
	id := mkUpstreamViaAPI(t, h,
		`{"name":"u1","base_url":"https://a.example.com","api_key":"`+plain+`"}`)

	get := do(t, h, "GET", "/admin/api/upstreams/"+itoa(id), "", true)
	if get.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", get.Code, get.Body.String())
	}
	var before struct {
		APIKey             string `json:"api_key"`
		APIKeyIsSet        bool   `json:"api_key_is_set"`
		CredentialRevision int64  `json:"credential_revision"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &before); err != nil {
		t.Fatal(err)
	}
	if before.APIKey == "" || before.APIKey == plain || !before.APIKeyIsSet {
		t.Fatalf("GET 应回脱敏值且 is_set：%+v", before)
	}

	rec := do(t, h, "PUT", "/admin/api/upstreams/"+itoa(id),
		`{"name":"u1-renamed","api_key":`+mustJSON(t, before.APIKey)+`}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT masked echo: %d %s", rec.Code, rec.Body.String())
	}
	var after struct {
		Name               string `json:"name"`
		APIKey             string `json:"api_key"`
		APIKeyIsSet        bool   `json:"api_key_is_set"`
		CredentialRevision int64  `json:"credential_revision"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	if after.Name != "u1-renamed" || after.APIKey != before.APIKey || !after.APIKeyIsSet {
		t.Fatalf("响应应保留脱敏回显且改名成功：%+v", after)
	}
	if after.CredentialRevision != before.CredentialRevision {
		t.Fatalf("脱敏回写不应 bump credential_revision：got %d want %d",
			after.CredentialRevision, before.CredentialRevision)
	}
	if strings.Contains(rec.Body.String(), plain) {
		t.Fatal("写响应不得回显明文 api_key")
	}
	got, err := s.st.GetUpstream(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.APIKey != plain {
		t.Fatalf("库中真钥被覆盖成 %q", got.APIKey)
	}
}

func mustJSON(t *testing.T, v string) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestInvalidate_UpstreamKeyChangeTriggersProbe(t *testing.T) {
	// 改 key 是最典型的场景：用户换了 key，想立刻知道新 key 通不通。
	h, inv := newInvalidatorServer(t)
	id := mkUpstreamViaAPI(t, h,
		`{"name":"u1","base_url":"https://a.example.com","api_key":"sk-oldoldoldold"}`)

	rec := do(t, h, "PUT", "/admin/api/upstreams/"+itoa(id),
		`{"api_key":"sk-newnewnewnew"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("更新失败 %d：%s", rec.Code, rec.Body.String())
	}
	_, ups, _ := inv.counts()
	if ups != 1 {
		t.Errorf("改 key 应触发 1 次整站重探，得到 %d", ups)
	}
}

func TestInvalidate_UpstreamNameChangeDoesNotTriggerProbe(t *testing.T) {
	// name 只是标签，重探纯属浪费一次请求 —— 而 §5.2d 刚让这些请求变得可见。
	h, inv := newInvalidatorServer(t)
	id := mkUpstreamViaAPI(t, h,
		`{"name":"u1","base_url":"https://a.example.com","api_key":"sk-aaaaaaaaaaaa"}`)

	rec := do(t, h, "PUT", "/admin/api/upstreams/"+itoa(id), `{"name":"u1-renamed"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("更新失败：%s", rec.Body.String())
	}
	_, ups, _ := inv.counts()
	if ups != 0 {
		t.Errorf("只改 name 不该触发重探，却触发了 %d 次", ups)
	}
}

func TestInvalidate_UpstreamNoOpUpdateDoesNotTriggerProbe(t *testing.T) {
	// 这条守的是一个真实的坑：updateUpstream 会把 cur.APIKey 置空
	// （「留空 = 不改」的语义）。若比对用的是置空后的值，就会把
	// 「没改 key」误判成「key 从有变没」，于是**每次保存都**触发全站重探。
	//
	// 提交一个空对象（什么都不改）是最能暴露这个 bug 的输入。
	h, inv := newInvalidatorServer(t)
	id := mkUpstreamViaAPI(t, h,
		`{"name":"u1","base_url":"https://a.example.com","api_key":"sk-aaaaaaaaaaaa"}`)

	rec := do(t, h, "PUT", "/admin/api/upstreams/"+itoa(id), `{}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("更新失败：%s", rec.Body.String())
	}
	_, ups, _ := inv.counts()
	if ups != 0 {
		t.Errorf("空更新（什么都没改）不该触发重探，却触发了 %d 次", ups)
	}
}

func TestInvalidate_UpstreamReEnableTriggersProbe(t *testing.T) {
	// 从停用变启用要探：那是「重新启用它，想知道还通不通」的时刻。
	h, inv := newInvalidatorServer(t)
	id := mkUpstreamViaAPI(t, h,
		`{"name":"u1","base_url":"https://a.example.com","api_key":"sk-aaaaaaaaaaaa","enabled":false}`)

	rec := do(t, h, "PUT", "/admin/api/upstreams/"+itoa(id), `{"enabled":true}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("更新失败：%s", rec.Body.String())
	}
	_, ups, _ := inv.counts()
	if ups != 1 {
		t.Errorf("重新启用应触发探活，得到 %d", ups)
	}
}

func TestInvalidate_UpstreamDisableDoesNotTriggerProbe(t *testing.T) {
	// 停用了就别探了 —— 探一个已经停用的站是纯浪费。
	h, inv := newInvalidatorServer(t)
	id := mkUpstreamViaAPI(t, h,
		`{"name":"u1","base_url":"https://a.example.com","api_key":"sk-aaaaaaaaaaaa"}`)

	rec := do(t, h, "PUT", "/admin/api/upstreams/"+itoa(id), `{"enabled":false}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("更新失败：%s", rec.Body.String())
	}
	_, ups, _ := inv.counts()
	if ups != 0 {
		t.Errorf("停用不该触发重探，却触发了 %d 次", ups)
	}
}

func TestInvalidate_NilInvalidatorIsSafe(t *testing.T) {
	// 不接钩子时（现有的冒烟脚本、单测）写入路径必须照常工作。
	// 钩子是可选的观测/优化，绝不能成为 CRUD 的依赖。
	_, h := newTestServer(t) // 没有 WithInvalidator
	id := mkUpstreamViaAPI(t, h,
		`{"name":"u1","base_url":"https://a.example.com","api_key":"sk-aaaaaaaaaaaa"}`)
	rec := do(t, h, "PUT", "/admin/api/upstreams/"+itoa(id),
		`{"api_key":"sk-newnewnewnew"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("没接钩子时更新应正常，得到 %d：%s", rec.Code, rec.Body.String())
	}
}

func TestProbeAffectingUpstream_FieldMatrix(t *testing.T) {
	base := model.Upstream{
		Name: "u", BaseURL: "https://a.example.com", APIKey: "sk-aaaa",
		AuthStyle: model.AuthAuto, L1Path: "/v1/models",
		ProbeHeaders: map[string]string{"user-agent": "claude-cli/2.1"},
	}

	cases := []struct {
		name   string
		mutate func(*model.Upstream)
		want   bool
	}{
		{"base_url 变", func(u *model.Upstream) { u.BaseURL = "https://b.example.com" }, true},
		{"api_key 变", func(u *model.Upstream) { u.APIKey = "sk-bbbb" }, true},
		{"auth_style 变", func(u *model.Upstream) { u.AuthStyle = model.AuthBearer }, true},
		{"full_url_mode 变", func(u *model.Upstream) { u.FullURLMode = true }, true},
		{"proxy_url 变", func(u *model.Upstream) { u.ProxyURL = "http://127.0.0.1:1080" }, true},
		{"host_override 变", func(u *model.Upstream) { u.HostOverride = "real.example.com" }, true},
		{"tls_server_name 变", func(u *model.Upstream) { u.TLSServerName = "sni.example.com" }, true},
		{"l1_path 变", func(u *model.Upstream) { u.L1Path = "" }, true},
		{"probe_headers 值变", func(u *model.Upstream) {
			u.ProbeHeaders = map[string]string{"user-agent": "other"}
		}, true},
		{"probe_headers 增项", func(u *model.Upstream) {
			u.ProbeHeaders = map[string]string{"user-agent": "claude-cli/2.1", "x-app": "cli"}
		}, true},
		{"probe_headers 删项", func(u *model.Upstream) { u.ProbeHeaders = nil }, true},
		// 下面这些不该触发
		{"name 变", func(u *model.Upstream) { u.Name = "renamed" }, false},
		{"什么都不改", func(u *model.Upstream) {}, false},
		{"probe_headers 同内容不同 map", func(u *model.Upstream) {
			u.ProbeHeaders = map[string]string{"user-agent": "claude-cli/2.1"}
		}, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			after := base
			// 深拷贝 map，否则 mutate 会改到 base 自己。
			after.ProbeHeaders = map[string]string{}
			for k, v := range base.ProbeHeaders {
				after.ProbeHeaders[k] = v
			}
			c.mutate(&after)
			if got := probeAffectingUpstream(&base, &after); got != c.want {
				t.Errorf("probeAffectingUpstream = %v，期望 %v", got, c.want)
			}
		})
	}
}

func TestInvalidate_ModelNamePromptChangeTriggersProbe(t *testing.T) {
	// 改 probe_prompt 只影响 L2 的请求内容，所以走 ModelName 级触发。
	h, inv := newInvalidatorServer(t)
	rec := do(t, h, "POST", "/admin/api/model-names",
		`{"name":"m1","protocol":"anthropic"}`, true)
	id := int64(decodeBody[map[string]any](t, rec)["id"].(float64))

	rec = do(t, h, "PUT", "/admin/api/model-names/"+itoa(id),
		`{"probe_prompt":"2+2=?"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("更新失败：%s", rec.Body.String())
	}
	_, _, mns := inv.counts()
	if mns != 1 {
		t.Errorf("改 probe_prompt 应触发 1 次，得到 %d", mns)
	}
}

// SemanticConfigInvalidator must clear §9.2 RouteHealth for child Routes when a
// ModelName changes — TriggerL2 alone leaves old dead/alive until the next probe.
func TestSemanticConfigInvalidator_ModelNameClearsChildRouteHealth(t *testing.T) {
	sem := &recordingSemantic{}
	inner := &recordingInvalidator{}
	wrap := &SemanticConfigInvalidator{
		Semantic: sem,
		Inner:    inner,
		RoutesOfModelName: func(modelNameID int64) []int64 {
			if modelNameID != 5 {
				t.Fatalf("unexpected modelNameID %d", modelNameID)
			}
			return []int64{101, 102}
		},
	}
	wrap.InvalidateModelName(5)
	if len(sem.modelNames) != 1 || sem.modelNames[0] != 5 {
		t.Fatalf("semantic InvalidateModelName calls=%v", sem.modelNames)
	}
	if len(sem.modelNameRoutes) != 1 || len(sem.modelNameRoutes[0]) != 2 ||
		sem.modelNameRoutes[0][0] != 101 || sem.modelNameRoutes[0][1] != 102 {
		t.Fatalf("semantic routeIDs=%v", sem.modelNameRoutes)
	}
	_, _, mns := inner.counts()
	if mns != 1 {
		t.Fatalf("inner InvalidateModelName count=%d", mns)
	}
}

// network-origin fields bump NetworkRevision; InvalidateUpstream must Forget
// child RouteHealth so an old alive/dead verdict cannot select for the new host (§9.2).
func TestSemanticConfigInvalidator_UpstreamNetworkChangeClearsAliveRouteHealth(t *testing.T) {
	fs := &fakeSettingsForInvalidate{s: model.DefaultSettings()}
	tr := health.NewTracker(fs)
	tr.Report(health.Report{RouteID: 41, Verdict: health.VerdictOK, Source: health.SourceReal})
	if tr.State(41) != model.StateAlive {
		t.Fatalf("setup state=%s", tr.State(41))
	}
	sem := health.NewSemanticInvalidator(tr, nil, nil, nil, nil)
	inner := &recordingInvalidator{}
	wrap := &SemanticConfigInvalidator{
		Semantic: sem,
		Inner:    inner,
		RoutesOfUpstream: func(upstreamID int64) []int64 {
			if upstreamID != 9 {
				t.Fatalf("unexpected upstreamID %d", upstreamID)
			}
			return []int64{41}
		},
	}
	// Same path updateUpstream takes after BaseURL / HostOverride / TLS change.
	wrap.InvalidateUpstream(9)
	if got := tr.State(41); got != model.StateUnknown {
		t.Fatalf("after network-origin invalidate, RouteHealth=%s want unknown (not old alive)", got)
	}
	_, ups, _ := inner.counts()
	if ups != 1 {
		t.Fatalf("inner InvalidateUpstream count=%d", ups)
	}
}

type fakeSettingsForInvalidate struct {
	s model.Settings
}

func (f *fakeSettingsForInvalidate) Settings() (model.Settings, error) { return f.s, nil }

type recordingSemantic struct {
	routes          []int64
	upstreams       []int64
	upstreamRoutes  [][]int64
	modelNames      []int64
	modelNameRoutes [][]int64
}

func (r *recordingSemantic) InvalidateRoute(routeID int64) {
	r.routes = append(r.routes, routeID)
}

func (r *recordingSemantic) InvalidateUpstream(upstreamID int64, routeIDs []int64) {
	r.upstreams = append(r.upstreams, upstreamID)
	cp := append([]int64(nil), routeIDs...)
	r.upstreamRoutes = append(r.upstreamRoutes, cp)
}

func (r *recordingSemantic) InvalidateModelName(modelNameID int64, routeIDs []int64) {
	r.modelNames = append(r.modelNames, modelNameID)
	cp := append([]int64(nil), routeIDs...)
	r.modelNameRoutes = append(r.modelNameRoutes, cp)
}

func TestInvalidate_RoutePriorityChangeDoesNotTriggerProbe(t *testing.T) {
	// priority / weight 只影响选路偏好，探活结果一模一样。
	h, inv := newInvalidatorServer(t)
	upID := mkUpstreamViaAPI(t, h,
		`{"name":"u1","base_url":"https://a.example.com","api_key":"sk-aaaaaaaaaaaa"}`)
	rec := do(t, h, "POST", "/admin/api/model-names",
		`{"name":"m1","protocol":"anthropic"}`, true)
	mnID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))
	rec = do(t, h, "POST", "/admin/api/routes",
		`{"model_name_id":`+itoa(mnID)+`,"upstream_id":`+itoa(upID)+`}`, true)
	rtID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))

	// 建 Route 时触发了一次，从这里开始只看增量。
	before, _, _ := inv.counts()

	rec = do(t, h, "PUT", "/admin/api/routes/"+itoa(rtID), `{"priority":5,"weight":50}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("更新失败：%s", rec.Body.String())
	}
	after, _, _ := inv.counts()
	if after != before {
		t.Errorf("只改 priority/weight 不该触发重探，却多触发了 %d 次", after-before)
	}
}

func TestInvalidate_RouteModelMappingChangeTriggersProbe(t *testing.T) {
	// 改 upstream_model 会改变探活打的模型名，必须重探 ——
	// 否则「探活通过但真实请求 model_not_found」。
	h, inv := newInvalidatorServer(t)
	upID := mkUpstreamViaAPI(t, h,
		`{"name":"u1","base_url":"https://a.example.com","api_key":"sk-aaaaaaaaaaaa"}`)
	rec := do(t, h, "POST", "/admin/api/model-names",
		`{"name":"m1","protocol":"anthropic"}`, true)
	mnID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))
	rec = do(t, h, "POST", "/admin/api/routes",
		`{"model_name_id":`+itoa(mnID)+`,"upstream_id":`+itoa(upID)+`}`, true)
	rtID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))
	before, _, _ := inv.counts()

	rec = do(t, h, "PUT", "/admin/api/routes/"+itoa(rtID),
		`{"upstream_model":"claude-3-5-sonnet"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("更新失败：%s", rec.Body.String())
	}
	after, _, _ := inv.counts()
	if after != before+1 {
		t.Errorf("改模型映射应触发 1 次重探，得到 %d", after-before)
	}
}

// Delete must drop in-memory RouteHealth / RecoveryGate / Capability (§9.2).
// Scheduler RetainOnly is too late: a reused id (or any lookup by the old id)
// would otherwise inherit StateDead or a held recovery slot.
func TestInvalidate_DeleteRouteClearsDeadRouteHealth(t *testing.T) {
	s, _ := newTestServer(t)
	fs := &fakeSettingsForInvalidate{s: model.DefaultSettings()}
	fs.s.FailThreshold = 1
	tr := health.NewTracker(fs)
	gate := health.NewRecoveryGate()
	caps := &recordingCaps{}
	sem := health.NewSemanticInvalidator(tr, gate, caps, nil, nil)
	inner := &recordingInvalidator{}
	h := s.WithInvalidator(&SemanticConfigInvalidator{
		Semantic: sem,
		Inner:    inner,
	}).Routes(testAdminPW)

	upID := mkUpstreamViaAPI(t, h, `{"name":"del-rt-u","base_url":"https://a.example.com","api_key":"sk-aaaaaaaaaaaa"}`)
	rec := do(t, h, "POST", "/admin/api/model-names",
		`{"name":"del-rt-m","protocol":"anthropic"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("建 model_name 失败：%s", rec.Body.String())
	}
	mnID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))
	rec = do(t, h, "POST", "/admin/api/routes",
		`{"model_name_id":`+itoa(mnID)+`,"upstream_id":`+itoa(upID)+`}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("建 route 失败：%s", rec.Body.String())
	}
	rtID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))

	tr.Report(health.Report{RouteID: rtID, Verdict: health.VerdictUnavailable, Source: health.SourceL2})
	if tr.State(rtID) != model.StateDead {
		t.Fatalf("setup state=%s want dead", tr.State(rtID))
	}
	if _, ok := gate.TryAcquire(rtID); !ok {
		t.Fatal("setup: acquire RecoveryGate")
	}

	rec = do(t, h, "DELETE", "/admin/api/routes/"+itoa(rtID), "", true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("删除 route 失败 %d：%s", rec.Code, rec.Body.String())
	}
	if got := tr.State(rtID); got != model.StateUnknown {
		t.Fatalf("delete 后 RouteHealth=%s want unknown（不得保留 StateDead）", got)
	}
	if gate.InFlight(rtID) {
		t.Fatal("delete 后 RecoveryGate 槽必须释放")
	}
	if !caps.has(rtID) {
		t.Fatalf("delete 后 Capability scope 必须 InvalidateScope，cleared=%v", caps.cleared)
	}
	routes, _, _ := inner.counts()
	if routes < 1 {
		t.Fatal("delete 应调用 InvalidateRoute")
	}

	// Re-create the same (model, upstream) mapping: even if SQLite reuses the
	// rowid, the new Route must not see the previous dead verdict.
	rec = do(t, h, "POST", "/admin/api/routes",
		`{"model_name_id":`+itoa(mnID)+`,"upstream_id":`+itoa(upID)+`}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("重建 route 失败：%s", rec.Body.String())
	}
	newID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))
	if tr.State(newID) != model.StateUnknown {
		t.Fatalf("重建后 RouteHealth=%s want unknown（id=%d 不得继承旧 dead）", tr.State(newID), newID)
	}
}

// Delete Upstream cascades child Routes in SQL; invalidate must run first so
// RoutesOfUpstream still returns those ids for Semantic Forget.
func TestInvalidate_DeleteUpstreamClearsChildRouteHealth(t *testing.T) {
	s, _ := newTestServer(t)
	fs := &fakeSettingsForInvalidate{s: model.DefaultSettings()}
	fs.s.FailThreshold = 1
	tr := health.NewTracker(fs)
	gate := health.NewRecoveryGate()
	caps := &recordingCaps{}
	sem := health.NewSemanticInvalidator(tr, gate, caps, nil, nil)
	inner := &recordingInvalidator{}
	h := s.WithInvalidator(&SemanticConfigInvalidator{
		Semantic: sem,
		Inner:    inner,
		RoutesOfUpstream: func(upstreamID int64) []int64 {
			routes, err := s.st.ListRoutes(0)
			if err != nil {
				return nil
			}
			var ids []int64
			for _, rt := range routes {
				if rt.UpstreamID == upstreamID {
					ids = append(ids, rt.ID)
				}
			}
			return ids
		},
	}).Routes(testAdminPW)

	upID := mkUpstreamViaAPI(t, h, `{"name":"del-up-u","base_url":"https://b.example.com","api_key":"sk-bbbbbbbbbbbb"}`)
	rec := do(t, h, "POST", "/admin/api/model-names",
		`{"name":"del-up-m","protocol":"anthropic"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("建 model_name 失败：%s", rec.Body.String())
	}
	mnID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))
	rec = do(t, h, "POST", "/admin/api/routes",
		`{"model_name_id":`+itoa(mnID)+`,"upstream_id":`+itoa(upID)+`}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("建 route 失败：%s", rec.Body.String())
	}
	rtID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))

	tr.Report(health.Report{RouteID: rtID, Verdict: health.VerdictUnavailable, Source: health.SourceL2})
	if tr.State(rtID) != model.StateDead {
		t.Fatalf("setup state=%s want dead", tr.State(rtID))
	}

	rec = do(t, h, "DELETE", "/admin/api/upstreams/"+itoa(upID), "", true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("删除 upstream 失败 %d：%s", rec.Code, rec.Body.String())
	}
	if got := tr.State(rtID); got != model.StateUnknown {
		t.Fatalf("delete upstream 后 child RouteHealth=%s want unknown", got)
	}
	if !caps.has(rtID) {
		t.Fatalf("child Capability 必须清除，cleared=%v", caps.cleared)
	}
	if !caps.hasUpstream(upID) {
		t.Fatalf("upstream-scoped Capability 必须清除，upstreamCleared=%v", caps.upstreamCleared)
	}
	_, ups, _ := inner.counts()
	if ups < 1 {
		t.Fatal("delete upstream 应调用 InvalidateUpstream")
	}
}

// Delete ModelName cascades child Routes in SQL; invalidate must run first so
// RoutesOfModelName still returns those ids for Semantic Forget.
func TestInvalidate_DeleteModelNameClearsChildRouteHealth(t *testing.T) {
	s, _ := newTestServer(t)
	fs := &fakeSettingsForInvalidate{s: model.DefaultSettings()}
	fs.s.FailThreshold = 1
	tr := health.NewTracker(fs)
	gate := health.NewRecoveryGate()
	caps := &recordingCaps{}
	sem := health.NewSemanticInvalidator(tr, gate, caps, nil, nil)
	inner := &recordingInvalidator{}
	h := s.WithInvalidator(&SemanticConfigInvalidator{
		Semantic: sem,
		Inner:    inner,
		RoutesOfModelName: func(modelNameID int64) []int64 {
			routes, err := s.st.ListRoutes(modelNameID)
			if err != nil {
				return nil
			}
			ids := make([]int64, 0, len(routes))
			for _, rt := range routes {
				ids = append(ids, rt.ID)
			}
			return ids
		},
	}).Routes(testAdminPW)

	upID := mkUpstreamViaAPI(t, h, `{"name":"del-mn-u","base_url":"https://c.example.com","api_key":"sk-cccccccccccc"}`)
	rec := do(t, h, "POST", "/admin/api/model-names",
		`{"name":"del-mn-m","protocol":"anthropic"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("建 model_name 失败：%s", rec.Body.String())
	}
	mnID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))
	rec = do(t, h, "POST", "/admin/api/routes",
		`{"model_name_id":`+itoa(mnID)+`,"upstream_id":`+itoa(upID)+`}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("建 route 失败：%s", rec.Body.String())
	}
	rtID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))

	tr.Report(health.Report{RouteID: rtID, Verdict: health.VerdictUnavailable, Source: health.SourceL2})
	if tr.State(rtID) != model.StateDead {
		t.Fatalf("setup state=%s want dead", tr.State(rtID))
	}
	if _, ok := gate.TryAcquire(rtID); !ok {
		t.Fatal("setup: acquire RecoveryGate")
	}

	rec = do(t, h, "DELETE", "/admin/api/model-names/"+itoa(mnID), "", true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("删除 model_name 失败 %d：%s", rec.Code, rec.Body.String())
	}
	if got := tr.State(rtID); got != model.StateUnknown {
		t.Fatalf("delete model_name 后 child RouteHealth=%s want unknown", got)
	}
	if gate.InFlight(rtID) {
		t.Fatal("delete model_name 后 RecoveryGate 槽必须释放")
	}
	if !caps.has(rtID) {
		t.Fatalf("child Capability 必须清除，cleared=%v", caps.cleared)
	}
	_, _, mns := inner.counts()
	if mns < 1 {
		t.Fatal("delete model_name 应调用 InvalidateModelName")
	}
}

type recordingCaps struct {
	cleared         []int64
	upstreamCleared []int64
}

func (r *recordingCaps) InvalidateScope(scope model.RecipeScope, scopeID int64) {
	switch scope {
	case model.RecipeScopeRoute:
		r.cleared = append(r.cleared, scopeID)
	case model.RecipeScopeUpstream:
		r.upstreamCleared = append(r.upstreamCleared, scopeID)
	}
}

func (r *recordingCaps) has(routeID int64) bool {
	for _, id := range r.cleared {
		if id == routeID {
			return true
		}
	}
	return false
}

func (r *recordingCaps) hasUpstream(upstreamID int64) bool {
	for _, id := range r.upstreamCleared {
		if id == upstreamID {
			return true
		}
	}
	return false
}

// §9.2: Transform publish/rollback must Forget RouteHealth for the bound Route.
// Leaving an old alive verdict would keep selecting a Route whose outbound
// request shape just changed.
func TestInvalidate_TransformPublishClearsAliveRouteHealth(t *testing.T) {
	s, _ := newTestServer(t)
	fs := &fakeSettingsForInvalidate{s: model.DefaultSettings()}
	tr := health.NewTracker(fs)
	gate := health.NewRecoveryGate()
	caps := &recordingCaps{}
	sem := health.NewSemanticInvalidator(tr, gate, caps, nil, nil)
	inner := &recordingInvalidator{}
	reg := transform.NewRegistry(20)
	h := s.WithInvalidator(&SemanticConfigInvalidator{
		Semantic: sem,
		Inner:    inner,
	}).WithTransformRegistry(reg).Routes(testAdminPW)

	const routeID int64 = 77
	tr.Report(health.Report{RouteID: routeID, Verdict: health.VerdictOK, Source: health.SourceReal})
	if tr.State(routeID) != model.StateAlive {
		t.Fatalf("setup state=%s want alive", tr.State(routeID))
	}
	if _, ok := gate.TryAcquire(routeID); !ok {
		t.Fatal("setup: acquire RecoveryGate")
	}

	rec := do(t, h, "POST", "/admin/api/transforms", `{"name":"pub-clear"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create transform set: %d %s", rec.Code, rec.Body.String())
	}
	setID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))

	rec = do(t, h, "PUT", "/admin/api/transforms/"+itoa(setID)+"/draft",
		`{"rules":[{"kind":"replace_bytes","from":"A","to":"B"}]}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("draft: %d %s", rec.Code, rec.Body.String())
	}

	rec = do(t, h, "POST", "/admin/api/transforms/"+itoa(setID)+"/publish",
		`{"route_id":`+itoa(routeID)+`,"endpoint_id":3}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	firstVersionID := int64(decodeBody[map[string]any](t, rec)["version"].(map[string]any)["id"].(float64))
	if got := tr.State(routeID); got != model.StateUnknown {
		t.Fatalf("after publish RouteHealth=%s want unknown", got)
	}
	if gate.InFlight(routeID) {
		t.Fatal("after publish RecoveryGate slot must be released")
	}
	if !caps.has(routeID) {
		t.Fatalf("after publish Capability scope must clear, cleared=%v", caps.cleared)
	}
	routes, _, _ := inner.counts()
	if routes < 1 {
		t.Fatal("publish must call InvalidateRoute")
	}

	// Publish a second version, re-seed alive, then rollback to the first.
	rec = do(t, h, "PUT", "/admin/api/transforms/"+itoa(setID)+"/draft",
		`{"rules":[{"kind":"replace_bytes","from":"A","to":"C"}]}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("second draft: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, "POST", "/admin/api/transforms/"+itoa(setID)+"/publish",
		`{"route_id":`+itoa(routeID)+`,"endpoint_id":3}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("second publish: %d %s", rec.Code, rec.Body.String())
	}
	tr.Report(health.Report{RouteID: routeID, Verdict: health.VerdictOK, Source: health.SourceReal})
	if tr.State(routeID) != model.StateAlive {
		t.Fatalf("re-seed state=%s want alive", tr.State(routeID))
	}
	beforeRollback, _, _ := inner.counts()
	rec = do(t, h, "POST", "/admin/api/transforms/rollback",
		`{"route_id":`+itoa(routeID)+`,"endpoint_id":3,"version_id":`+itoa(firstVersionID)+`}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback: %d %s", rec.Code, rec.Body.String())
	}
	if got := tr.State(routeID); got != model.StateUnknown {
		t.Fatalf("after rollback RouteHealth=%s want unknown", got)
	}
	afterRollback, _, _ := inner.counts()
	if afterRollback <= beforeRollback {
		t.Fatalf("rollback must call InvalidateRoute (before=%d after=%d)", beforeRollback, afterRollback)
	}
}

// §9.2: Endpoint URL / Auth Profile updates must Forget child RouteHealth.
// probe.Service alone only reaches Scheduler; the admin handler must also hit
// SemanticInvalidator via invalidateUpstream.
func TestInvalidate_EndpointURLChangeClearsAliveRouteHealth(t *testing.T) {
	s, _ := newTestServer(t)
	fs := &fakeSettingsForInvalidate{s: model.DefaultSettings()}
	tr := health.NewTracker(fs)
	gate := health.NewRecoveryGate()
	caps := &recordingCaps{}
	sem := health.NewSemanticInvalidator(tr, gate, caps, nil, nil)
	inner := &recordingInvalidator{}
	probeAdmin := probe.NewService(s.st, nil, nil, nil, nil, nil)
	h := s.WithProbeAdmin(probeAdmin).WithInvalidator(&SemanticConfigInvalidator{
		Semantic: sem,
		Inner:    inner,
		RoutesOfUpstream: func(upstreamID int64) []int64 {
			routes, err := s.st.ListRoutes(0)
			if err != nil {
				return nil
			}
			var ids []int64
			for _, rt := range routes {
				if rt.UpstreamID == upstreamID {
					ids = append(ids, rt.ID)
				}
			}
			return ids
		},
	}).Routes(testAdminPW)

	upID := mkUpstreamViaAPI(t, h, `{"name":"ep-url-u","base_url":"https://ep.example.com","api_key":"sk-eeeeeeeeeeee"}`)
	rec := do(t, h, "POST", "/admin/api/model-names",
		`{"name":"ep-url-m","protocol":"anthropic"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("建 model_name 失败：%s", rec.Body.String())
	}
	mnID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))
	rec = do(t, h, "POST", "/admin/api/routes",
		`{"model_name_id":`+itoa(mnID)+`,"upstream_id":`+itoa(upID)+`}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("建 route 失败：%s", rec.Body.String())
	}
	rtID := int64(decodeBody[map[string]any](t, rec)["id"].(float64))

	tr.Report(health.Report{RouteID: rtID, Verdict: health.VerdictOK, Source: health.SourceReal})
	if tr.State(rtID) != model.StateAlive {
		t.Fatalf("setup state=%s want alive", tr.State(rtID))
	}
	if _, ok := gate.TryAcquire(rtID); !ok {
		t.Fatal("setup: acquire RecoveryGate")
	}

	rec = do(t, h, "GET", "/admin/api/upstream-endpoints?upstream_id="+itoa(upID), "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("list endpoints: %d %s", rec.Code, rec.Body.String())
	}
	page := decodeBody[model.Page[model.UpstreamEndpoint]](t, rec)
	if len(page.Items) == 0 {
		t.Fatal("expected auto-created endpoints")
	}
	ep := page.Items[0]
	ep.URLOverride = "https://ep.example.com/v1/custom"
	body, err := json.Marshal(struct {
		model.UpstreamEndpoint
		ExpectedRevision int64 `json:"expected_revision"`
	}{UpstreamEndpoint: ep, ExpectedRevision: ep.Revision})
	if err != nil {
		t.Fatal(err)
	}

	rec = do(t, h, "PUT", "/admin/api/upstream-endpoints/"+itoa(ep.ID), string(body), true)
	if rec.Code != http.StatusOK {
		t.Fatalf("update endpoint: %d %s", rec.Code, rec.Body.String())
	}
	if got := tr.State(rtID); got != model.StateUnknown {
		t.Fatalf("after Endpoint URL change RouteHealth=%s want unknown", got)
	}
	if gate.InFlight(rtID) {
		t.Fatal("after Endpoint URL change RecoveryGate slot must be released")
	}
	if !caps.has(rtID) {
		t.Fatalf("after Endpoint URL change Capability must clear, cleared=%v", caps.cleared)
	}
	_, ups, _ := inner.counts()
	if ups < 1 {
		t.Fatal("Endpoint URL change must call InvalidateUpstream")
	}
}
