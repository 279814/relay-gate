package store

import (
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// mkRoute 建一条完整的 Route（含它依赖的 ModelName 与 Upstream）。
// route_health 有外键指向 route，所以不能凭空插 route_id。
func mkRoute(t *testing.T, st *Store) *model.Route {
	t.Helper()
	mn := mkModelName(t, st, "claude-opus-5", model.ProtoAnthropic)
	up := mkUpstream(t, st, "sta")
	r := &model.Route{ModelNameID: mn.ID, UpstreamID: up.ID, Enabled: true}
	if err := st.CreateRoute(r); err != nil {
		t.Fatal(err)
	}
	return r
}

// 落库的是快照，不是权威来源（§2.4）。这组测试守的是「UI 能看到状态」这条链路。
func TestRouteHealth_SaveAndList(t *testing.T) {
	st := testStore(t)
	rt := mkRoute(t, st)

	// CreateRoute 应已建好初始行，让 UI 立刻能显示 unknown 而不是空白
	rows, err := st.ListRouteHealth()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("CreateRoute 应顺带建 health 行，得到 %d 条", len(rows))
	}
	if rows[0].State != model.StateUnknown {
		t.Errorf("初始状态应为 unknown，得到 %s", rows[0].State)
	}

	err = st.SaveRouteHealth([]*RouteHealth{{
		RouteID: rt.ID, State: model.StateDead,
		ConsecutiveOK: 0, ConsecutiveFail: 3,
		LastOKAt: 1000, LastErrAt: 2000,
		LastError: "HTTP 503", LastTTFTMS: 42,
	}})
	if err != nil {
		t.Fatal(err)
	}

	rows, err = st.ListRouteHealth()
	if err != nil {
		t.Fatal(err)
	}
	got := rows[0]
	if got.State != model.StateDead {
		t.Errorf("state 应落库，得到 %s", got.State)
	}
	if got.ConsecutiveFail != 3 || got.LastError != "HTTP 503" || got.LastTTFTMS != 42 {
		t.Errorf("字段落库不完整：%+v", got)
	}
	if got.UpdatedAt == 0 {
		t.Error("updated_at 应被刷新")
	}
}

// Route 可能在「采集快照」与「落库」之间被删掉。那不是错误，
// 静默跳过即可 —— 报错会让 Persister 每 5 秒刷一行无意义的日志。
func TestRouteHealth_SkipsDeletedRoute(t *testing.T) {
	st := testStore(t)

	err := st.SaveRouteHealth([]*RouteHealth{{
		RouteID: 99999, State: model.StateDead,
	}})
	if err != nil {
		t.Errorf("不存在的 route_id 应静默跳过，得到错误：%v", err)
	}
}

// 空列表不该开事务。Persister 在没有任何 Route 时也会周期性调用它，
// 每次都开一个空事务是白白磨 SQLite。
func TestRouteHealth_EmptyIsNoop(t *testing.T) {
	st := testStore(t)
	if err := st.SaveRouteHealth(nil); err != nil {
		t.Errorf("空列表应直接返回，得到 %v", err)
	}
}

// 删 Route 应级联删掉 health 行，否则表会随反复增删单调增长。
func TestRouteHealth_CascadeOnRouteDelete(t *testing.T) {
	st := testStore(t)
	rt := mkRoute(t, st)

	if err := st.DeleteRoute(rt.ID); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListRouteHealth()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("删 Route 应级联删 health 行，还剩 %d 条", len(rows))
	}
}
