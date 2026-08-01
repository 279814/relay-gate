package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	c, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(filepath.Join(t.TempDir(), "test.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func mkUpstream(t *testing.T, st *Store, name string) *model.Upstream {
	t.Helper()
	u := &model.Upstream{Name: name, BaseURL: "https://" + name + ".example.com",
		APIKey: "sk-" + name + "-secret-value", Enabled: true}
	if err := st.CreateUpstream(u); err != nil {
		t.Fatal(err)
	}
	return u
}

func mkModelName(t *testing.T, st *Store, name string, p model.Protocol) *model.ModelName {
	t.Helper()
	m := &model.ModelName{Name: name, Protocol: p, Enabled: true}
	if err := st.CreateModelName(m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestUpstreamCRUD(t *testing.T) {
	st := testStore(t)
	u := mkUpstream(t, st, "sta")
	if u.ID == 0 {
		t.Fatal("创建后应回填 ID")
	}

	got, err := st.GetUpstream(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	// key 必须能原样解密回来，否则出站鉴权会失败
	if got.APIKey != "sk-sta-secret-value" {
		t.Errorf("api_key 应解密还原，得到 %q", got.APIKey)
	}
	if got.AuthStyle != model.AuthAuto || got.L1Path != "/v1/models" {
		t.Errorf("默认值未生效：auth=%q l1=%q", got.AuthStyle, got.L1Path)
	}

	got.Name = "sta-renamed"
	got.APIKey = "" // 空 = 不改 key
	if err := st.UpdateUpstream(got); err != nil {
		t.Fatal(err)
	}
	after, _ := st.GetUpstream(u.ID)
	if after.Name != "sta-renamed" {
		t.Errorf("name 未更新：%q", after.Name)
	}
	if after.APIKey != "sk-sta-secret-value" {
		t.Errorf("api_key 传空时应保持原值，得到 %q —— 否则一次编辑就会破坏 key", after.APIKey)
	}

	after.APIKey = "sk-rotated-key-value"
	if err := st.UpdateUpstream(after); err != nil {
		t.Fatal(err)
	}
	rotated, _ := st.GetUpstream(u.ID)
	if rotated.APIKey != "sk-rotated-key-value" {
		t.Errorf("显式传入新 key 时应更新，得到 %q", rotated.APIKey)
	}

	if err := st.DeleteUpstream(u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetUpstream(u.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("删除后应返回 ErrNotFound，得到 %v", err)
	}
}

func TestUpstreamRequiresKey(t *testing.T) {
	st := testStore(t)
	u := &model.Upstream{Name: "nokey", BaseURL: "https://a.com", Enabled: true}
	err := st.CreateUpstream(u)
	if err == nil {
		t.Fatal("创建时缺 api_key 应报错")
	}
	if !errors.Is(err, model.ErrValidation) {
		t.Errorf("应为校验错误（API 回 400），得到 %v", err)
	}
}

func TestDuplicateNamesRejected(t *testing.T) {
	st := testStore(t)
	mkUpstream(t, st, "dup")

	u2 := &model.Upstream{Name: "dup", BaseURL: "https://other.com", APIKey: "k", Enabled: true}
	err := st.CreateUpstream(u2)
	if !errors.Is(err, model.ErrValidation) {
		t.Fatalf("重名应报校验错误（可读信息），得到 %v", err)
	}
	if !contains(err.Error(), "已存在") {
		t.Errorf("错误信息应是人能看懂的中文，得到 %v", err)
	}
}

// 全局至多一个兜底 ModelName，由部分唯一索引在存储层保证。
func TestSingleFallbackModelName(t *testing.T) {
	st := testStore(t)
	m1 := &model.ModelName{Name: "fb1", Protocol: model.ProtoAnthropic, IsFallback: true, Enabled: true}
	if err := st.CreateModelName(m1); err != nil {
		t.Fatal(err)
	}
	m2 := &model.ModelName{Name: "fb2", Protocol: model.ProtoAnthropic, IsFallback: true, Enabled: true}
	err := st.CreateModelName(m2)
	if !errors.Is(err, model.ErrValidation) {
		t.Fatalf("第二个兜底应被拒绝，得到 %v", err)
	}

	// 非兜底的可以有多个
	for _, n := range []string{"a", "b", "c"} {
		if err := st.CreateModelName(&model.ModelName{
			Name: n, Protocol: model.ProtoAnthropic, Enabled: true}); err != nil {
			t.Fatalf("非兜底 ModelName 应可自由创建：%v", err)
		}
	}
}

func TestRouteCRUDAndUnique(t *testing.T) {
	st := testStore(t)
	u := mkUpstream(t, st, "sta")
	m := mkModelName(t, st, "claude-opus-5", model.ProtoAnthropic)

	r := &model.Route{ModelNameID: m.ID, UpstreamID: u.ID, Priority: 1, Enabled: true}
	if err := st.CreateRoute(r); err != nil {
		t.Fatal(err)
	}
	if r.Weight != 100 {
		t.Errorf("weight 默认应为 100，得到 %d", r.Weight)
	}

	// 同一 (model_name, upstream) 只能绑一次，否则选路会重复计权
	dup := &model.Route{ModelNameID: m.ID, UpstreamID: u.ID, Priority: 2, Enabled: true}
	err := st.CreateRoute(dup)
	if !errors.Is(err, model.ErrValidation) {
		t.Fatalf("重复绑定应被拒绝，得到 %v", err)
	}

	// 创建 Route 时应同时建好 health 行，UI 才能立刻显示 unknown
	var state string
	if err := st.DB().QueryRow(
		`SELECT state FROM route_health WHERE route_id = ?`, r.ID).Scan(&state); err != nil {
		t.Fatalf("route_health 行应随 Route 一起创建：%v", err)
	}
	if state != string(model.StateUnknown) {
		t.Errorf("初始状态应为 unknown（乐观可用），得到 %q", state)
	}
}

func TestRouteForeignKeyEnforced(t *testing.T) {
	st := testStore(t)
	r := &model.Route{ModelNameID: 999, UpstreamID: 999, Priority: 1, Enabled: true}
	err := st.CreateRoute(r)
	if err == nil {
		t.Fatal("引用不存在的 ModelName/Upstream 应报错（外键必须开启）")
	}
	if !errors.Is(err, model.ErrValidation) {
		t.Errorf("应为校验错误，得到 %v", err)
	}
}

// 删除 ModelName 应级联删掉它的 Route，否则会留下悬挂绑定。
func TestCascadeDelete(t *testing.T) {
	st := testStore(t)
	u := mkUpstream(t, st, "sta")
	m := mkModelName(t, st, "m1", model.ProtoAnthropic)
	r := &model.Route{ModelNameID: m.ID, UpstreamID: u.ID, Priority: 1, Enabled: true}
	if err := st.CreateRoute(r); err != nil {
		t.Fatal(err)
	}

	if err := st.DeleteModelName(m.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetRoute(r.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("ModelName 删除后其 Route 应级联消失，得到 %v", err)
	}
}

func TestListRoutesFilter(t *testing.T) {
	st := testStore(t)
	u1 := mkUpstream(t, st, "s1")
	u2 := mkUpstream(t, st, "s2")
	m1 := mkModelName(t, st, "m1", model.ProtoAnthropic)
	m2 := mkModelName(t, st, "m2", model.ProtoOpenAIChat)

	// m1 下两条，优先级刻意倒序插入，验证返回时按 priority 升序
	for _, spec := range []struct {
		mn, up   int64
		priority int
	}{
		{m1.ID, u1.ID, 2},
		{m1.ID, u2.ID, 1},
		{m2.ID, u1.ID, 1},
	} {
		if err := st.CreateRoute(&model.Route{
			ModelNameID: spec.mn, UpstreamID: spec.up,
			Priority: spec.priority, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}

	all, err := st.ListRoutes(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("应返回全部 3 条，得到 %d", len(all))
	}

	only, err := st.ListRoutes(m1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(only) != 2 {
		t.Fatalf("m1 下应有 2 条，得到 %d", len(only))
	}
	if only[0].Priority != 1 || only[1].Priority != 2 {
		t.Errorf("应按 priority 升序返回（与选路顺序一致），得到 %d,%d",
			only[0].Priority, only[1].Priority)
	}
}

func TestSettingsPersistence(t *testing.T) {
	st := testStore(t)

	// 未初始化时返回默认值，让首次启动不依赖初始化步骤
	got, err := st.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got.RealFirstTokenSec != 1200 {
		t.Errorf("首次读取应得默认 1200，得到 %d", got.RealFirstTokenSec)
	}

	got.RealFirstTokenSec = 900
	got.SampleEnabled = false
	if err := st.SaveSettings(got); err != nil {
		t.Fatal(err)
	}
	back, _ := st.GetSettings()
	if back.RealFirstTokenSec != 900 || back.SampleEnabled {
		t.Errorf("设置未正确持久化：%+v", back)
	}

	// 低于硬下限必须被拒，且库里的值保持不变
	bad := back
	bad.RealFirstTokenSec = 60
	if err := st.SaveSettings(bad); !errors.Is(err, model.ErrValidation) {
		t.Fatalf("低于 300s 应被拒绝，得到 %v", err)
	}
	unchanged, _ := st.GetSettings()
	if unchanged.RealFirstTokenSec != 900 {
		t.Errorf("校验失败不应写入，库中值变成了 %d", unchanged.RealFirstTokenSec)
	}
}

// 新增配置项后，老记录里缺失的字段必须拿到默认值而不是 0，
// 否则一次版本升级会把所有超时静默变成 0。
func TestSettingsMergesDefaultsForMissingFields(t *testing.T) {
	st := testStore(t)
	// 模拟旧版本只存了一个字段
	if _, err := st.DB().Exec(
		`INSERT INTO setting (key, value, updated_at) VALUES ('settings', '{"real_idle_sec":123}', 0)`,
	); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got.RealIdleSec != 123 {
		t.Errorf("已存字段应读出，得到 %d", got.RealIdleSec)
	}
	if got.RealFirstTokenSec != 1200 {
		t.Errorf("缺失字段应回落默认 1200，得到 %d（若为 0 说明升级会破坏配置）",
			got.RealFirstTokenSec)
	}
	if !got.SampleEnabled {
		t.Error("缺失的 bool 也应回落默认（true）")
	}
	// M6 新增项走的是同一条合并路径，但它的 0 值后果特别：
	// retry_max_attempts=0 不是「关闭重试」，而是「一次都不发」——
	// 升级后所有转发直接失败。这条单独断言一次。
	if got.RetryMaxAttempts != 3 {
		t.Errorf("升级时缺失的 retry_max_attempts 应回落默认 3，得到 %d"+
			"（若为 0，升级后每个请求都不会发出任何尝试）", got.RetryMaxAttempts)
	}
}

func TestRunStatePersistence(t *testing.T) {
	st := testStore(t)

	got, err := st.GetRunState()
	if err != nil {
		t.Fatal(err)
	}
	if got != StateRunning {
		t.Errorf("默认应为 running，得到 %q", got)
	}

	if err := st.SetRunState(StatePaused); err != nil {
		t.Fatal(err)
	}
	// 暂停状态必须持久化：暂停时重启不应自动跑起来（§4.8）
	if got, _ := st.GetRunState(); got != StatePaused {
		t.Errorf("暂停状态应持久化，得到 %q", got)
	}

	if err := st.SetRunState("bogus"); !errors.Is(err, model.ErrValidation) {
		t.Errorf("非法状态应被拒绝，得到 %v", err)
	}
}

func TestNotFoundOnMissingRows(t *testing.T) {
	st := testStore(t)
	if _, err := st.GetUpstream(999); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetUpstream: 得到 %v", err)
	}
	if _, err := st.GetModelName(999); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetModelName: 得到 %v", err)
	}
	if err := st.DeleteRoute(999); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteRoute: 得到 %v", err)
	}
	if err := st.UpdateUpstream(&model.Upstream{
		ID: 999, Name: "x", BaseURL: "https://a.com", APIKey: "k"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateUpstream: 得到 %v", err)
	}
}

// 空列表必须序列化成 [] 而不是 null，否则前端要多写一处判空。
func TestEmptyListsAreNotNil(t *testing.T) {
	st := testStore(t)
	ups, err := st.ListUpstreams()
	if err != nil || ups == nil {
		t.Errorf("ListUpstreams 空结果应为非 nil 切片，得到 %v %v", ups, err)
	}
	mns, err := st.ListModelNames()
	if err != nil || mns == nil {
		t.Errorf("ListModelNames 空结果应为非 nil 切片")
	}
	rts, err := st.ListRoutes(0)
	if err != nil || rts == nil {
		t.Errorf("ListRoutes 空结果应为非 nil 切片")
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// 回归测试：foreign_keys 必须在**每一条**连接上生效，不能只在跑过 schema.sql
// 的那条上生效。
//
// 曾经的隐患：pragma 写在 schema.sql 里，而 pragma 是连接级的。今天没出事
// 完全靠 MaxOpenConns(1) 恰好只有一条连接 —— 一旦 database/sql 判定连接坏了
// 并重建，外键就静默变成装饰：坏数据能插进去，ON DELETE CASCADE 也不再清理
// 子行。这类失效不报错，只能靠测试锁住。
//
// 用新开的 sql.DB 检验，等价于「连接池重建了一条没跑过 schema.sql 的连接」。
func TestForeignKeysOnEveryConn(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "fk.db")

	c, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(dsn, c)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	fresh, err := sql.Open("sqlite", dsn+connPragmas)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()

	var fk int
	if err := fresh.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil {
		t.Fatal(err)
	}
	if fk != 1 {
		t.Fatalf("新连接的 foreign_keys 应为 1，得到 %d —— "+
			"pragma 必须写在 DSN 里，写在 schema.sql 里只对首条连接有效", fk)
	}

	// 行为验证：光看 pragma 值不够，要确认约束真的拦得住
	_, err = fresh.Exec(`INSERT INTO route
		(model_name_id, upstream_id, priority, weight, upstream_model,
		 max_concurrency, enabled, created_at, updated_at)
		VALUES (99999, 88888, 1, 100, '', 0, 1, 0, 0)`)
	if err == nil {
		t.Error("指向不存在 ModelName/Upstream 的 Route 竟然插入成功了")
	}

	// WAL 是库级持久的，新连接不跑 schema.sql 也该是 wal
	var jm string
	if err := fresh.QueryRow("PRAGMA journal_mode").Scan(&jm); err != nil {
		t.Fatal(err)
	}
	if jm != "wal" {
		t.Errorf("journal_mode 应为 wal（库级持久），得到 %q", jm)
	}
}

// ON DELETE CASCADE 必须真的生效：删 ModelName 要连带清掉它的 Route。
// 这是上一条的另一面 —— 外键失效时级联也失效，而级联失效的症状是
// 「删了模型，选路里还留着一堆悬挂 Route」。
func TestDeleteModelNameCascadesRoutes(t *testing.T) {
	st := testStore(t)
	up := mkUpstream(t, st, "s1")
	mn := mkModelName(t, st, "m1", model.ProtoAnthropic)

	r := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID}
	r.Defaults()
	if err := st.CreateRoute(r); err != nil {
		t.Fatal(err)
	}

	if err := st.DeleteModelName(mn.ID); err != nil {
		t.Fatal(err)
	}
	rs, err := st.ListRoutes(0) // 0 = 不筛 ModelName，列全部
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range rs {
		if got.ID == r.ID {
			t.Fatal("删除 ModelName 后它的 Route 仍在（ON DELETE CASCADE 未生效）")
		}
	}
}
