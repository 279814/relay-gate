package api

import (
	"net/http"
	"sync"
	"testing"

	"github.com/279814/relay-gate/internal/model"
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
