package api

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

// stubHealth 是最小的 HealthView：所有 Route 都报 unknown。
//
// 用假的而不是真 Tracker：这里量的是 getHealth 的**数据库**开销，
// 而真 Tracker 会把状态机的逻辑也算进来，模糊掉要测的东西。
type stubHealth struct{}

func (stubHealth) AllStatus() []health.Status { return nil }
func (stubHealth) Status(id int64) health.Status {
	return health.Status{RouteID: id, State: model.StateUnknown}
}

// withHealthView 给测试服务器接上健康视图，否则 /health 回 503。
func withHealthView(t *testing.T, s *Server) http.Handler {
	t.Helper()
	return s.WithHealth(stubHealth{}, nil, nil).Routes(testAdminPW)
}

// TestGetHealth_QueryCostUnderAutoRefresh 量化健康看板的数据库读开销。
//
// 起因：PR-B 的界面默认可开 3 秒一次的自动刷新，而 getHealth 每次要读
// 三张表（model_name / upstream / route），且**绕过 livecfg 的缓存**
// 直接打 s.st。
//
// livecfg 存在的全部理由就是「SQLite 被限制为单连接，一次转发要读 5 张表，
// 不缓存会与样本落库队头阻塞」（livecfg/source.go）。M3 时 getHealth 只被
// 冒烟脚本偶尔调，这个不一致无所谓；自动刷新把它变成了持续负载。
//
// 这条测试不断言「必须多快」——那会变成一个在慢机器上乱红的脆弱测试。
// 它测的是**量级**：一轮刷新的耗时应当远小于刷新间隔，否则界面开着的
// 时候数据库连接就一直被占着。
func TestGetHealth_QueryCostUnderAutoRefresh(t *testing.T) {
	s, _ := newTestServer(t)
	h := withHealthView(t, s)
	seedConfig(t, s, 5, 5) // 5 个站 × 5 个模型 = 25 条 Route，远超单人自用的规模

	// 预热，排除首次查询的一次性开销。
	do(t, h, "GET", "/admin/api/health", "", true)

	const rounds = 20
	start := time.Now()
	for i := 0; i < rounds; i++ {
		rec := do(t, h, "GET", "/admin/api/health", "", true)
		if rec.Code != http.StatusOK {
			t.Fatalf("第 %d 轮失败：%d %s", i, rec.Code, rec.Body.String())
		}
	}
	per := time.Since(start) / rounds
	t.Logf("25 条 Route 时，每轮 /health 耗时 %v（自动刷新间隔 3s）", per)

	// 一轮刷新占用连接的时间若接近刷新间隔，就说明界面一开着，
	// 这条 SQLite 连接基本被它占死了，转发路径的选路会排在后面。
	if per > 300*time.Millisecond {
		t.Errorf("每轮 /health 耗时 %v，占 3s 刷新间隔的 %.0f%% —— "+
			"界面开着时会持续占用那条单一的 SQLite 连接", per,
			float64(per)/float64(3*time.Second)*100)
	}
}

// seedConfig 造 n 个 Upstream × m 个 ModelName 的全连接配置。
func seedConfig(t *testing.T, s *Server, nUp, nMn int) {
	t.Helper()
	for i := 0; i < nUp; i++ {
		u := &model.Upstream{
			Name: fmt.Sprintf("up-%d", i), BaseURL: fmt.Sprintf("https://u%d.example.com", i),
			APIKey: "sk-seed-key-abcdefgh", Enabled: true,
		}
		u.Defaults()
		if err := s.st.CreateUpstream(u); err != nil {
			t.Fatal(err)
		}
	}
	for j := 0; j < nMn; j++ {
		m := &model.ModelName{
			Name: fmt.Sprintf("model-%d", j), Protocol: model.ProtoAnthropic, Enabled: true,
		}
		m.Defaults()
		if err := s.st.CreateModelName(m); err != nil {
			t.Fatal(err)
		}
	}
	ups, err := s.st.ListUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	mns, err := s.st.ListModelNames()
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range ups {
		for _, m := range mns {
			rt := &model.Route{ModelNameID: m.ID, UpstreamID: u.ID, Enabled: true}
			rt.Defaults()
			if err := s.st.CreateRoute(rt); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TestGetHealth_ReadsDatabaseEveryCall 记录一个**当前成立的事实**：
// getHealth 不走 livecfg 的缓存，每次调用都真的读库。
//
// 这不是缺陷判定，是把现状钉住 —— 若哪天有人给它接上 livecfg（那会让
// 界面最多看到 2 秒前的配置，对看板是可接受的），这条测试会红，
// 提醒去更新 §10.6 里关于「界面开着时的数据库压力」的说明。
func TestGetHealth_ReadsDatabaseEveryCall(t *testing.T) {
	s, _ := newTestServer(t)
	h := withHealthView(t, s)
	seedConfig(t, s, 1, 1)

	do(t, h, "GET", "/admin/api/health", "", true)

	// 直接改库（绕过 API），然后立刻查看板。
	// 走缓存的话这次新增在 2 秒内看不到。
	u := &model.Upstream{
		Name: "added-directly", BaseURL: "https://direct.example.com",
		APIKey: "sk-direct-abcdefgh", Enabled: true,
	}
	u.Defaults()
	if err := s.st.CreateUpstream(u); err != nil {
		t.Fatal(err)
	}
	mns, _ := s.st.ListModelNames()
	rt := &model.Route{ModelNameID: mns[0].ID, UpstreamID: u.ID, Enabled: true}
	rt.Defaults()
	if err := s.st.CreateRoute(rt); err != nil {
		t.Fatal(err)
	}

	rec := do(t, h, "GET", "/admin/api/health", "", true)
	body := decodeBody[map[string]any](t, rec)
	rows := body["routes"].([]any)
	if len(rows) != 2 {
		t.Errorf("看板应立刻看到新增的 Route（当前实现直读库），得到 %d 条", len(rows))
	}
}
