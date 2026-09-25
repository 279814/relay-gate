package store

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// mkSample 造一条最简样本。
func mkSample(recvMS int64) *model.Sample {
	h := http.Header{}
	h.Set("X-Api-Key", "sk-ab…yz")
	h.Set("User-Agent", "claude-cli/2.1.220 (external, sdk-cli)")
	return &model.Sample{
		TSRecv: recvMS, TSSent: recvMS + 10,
		TSFirstByte: recvMS + 3000, TSDone: recvMS + 8000,
		Endpoint: "/v1/messages", ModelIn: "claude-opus-5", ModelOut: "claude-opus-5",
		ModelNameID: 1, RouteID: 100, UpstreamID: 10,
		InMethod: "POST", InPath: "/v1/messages", InQuery: "beta=true",
		InHeaders: h, InBody: []byte(`{"model":"claude-opus-5"}`),
		OutURL:     "https://s1.example.com/v1/messages",
		OutHeaders: h, OutBody: []byte(`{"model":"claude-opus-5"}`),
		RespStatus: 200, RespHeaders: http.Header{"Content-Type": {"text/event-stream"}},
		RespBody: []byte("event: message_start\ndata: {}\n\n"),
		Outcome:  model.OutcomeOK,
	}
}

func TestInsertAndGetSample(t *testing.T) {
	st := testStore(t)
	in := mkSample(time.Now().UnixMilli())

	if err := st.InsertSample(in); err != nil {
		t.Fatal(err)
	}
	if in.ID == 0 {
		t.Fatal("应回填 ID")
	}

	got, err := st.GetSample(in.ID)
	if err != nil {
		t.Fatal(err)
	}

	// body 必须逐字节往返 —— 整个功能的意义就在于「到底是哪些字节」
	if !bytes.Equal(got.InBody, in.InBody) {
		t.Errorf("in_body 往返不一致：%q vs %q", got.InBody, in.InBody)
	}
	if !bytes.Equal(got.OutBody, in.OutBody) {
		t.Errorf("out_body 往返不一致：%q vs %q", got.OutBody, in.OutBody)
	}
	if !bytes.Equal(got.RespBody, in.RespBody) {
		t.Errorf("resp_body 往返不一致：%q vs %q", got.RespBody, in.RespBody)
	}

	// 四个时间戳
	if got.TSRecv != in.TSRecv || got.TSSent != in.TSSent ||
		got.TSFirstByte != in.TSFirstByte || got.TSDone != in.TSDone {
		t.Errorf("时间戳往返不一致：%+v", got)
	}
	// 选路结果
	if got.RouteID != 100 || got.UpstreamID != 10 || got.ModelNameID != 1 {
		t.Errorf("选路结果往返不一致：%+v", got)
	}
	if got.InQuery != "beta=true" {
		t.Errorf("in_query 应往返，得到 %q", got.InQuery)
	}
	if got.Outcome != model.OutcomeOK {
		t.Errorf("outcome 应往返，得到 %q", got.Outcome)
	}
	// 头要保留多值结构
	if got.InHeaders.Get("User-Agent") != "claude-cli/2.1.220 (external, sdk-cli)" {
		t.Errorf("头往返不一致：%v", got.InHeaders)
	}
}

// 多值头必须保留成数组：Anthropic-Beta 常有多个，压成一个字符串
// 就分不清「一个头带逗号」与「多个同名头」，而上游看来可能不同。
func TestInsertSample_PreservesMultiValueHeaders(t *testing.T) {
	st := testStore(t)
	s := mkSample(time.Now().UnixMilli())
	s.InHeaders = http.Header{"Anthropic-Beta": {"feat-a", "feat-b", "feat-c"}}

	if err := st.InsertSample(s); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSample(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	vs := got.InHeaders.Values("Anthropic-Beta")
	if len(vs) != 3 || vs[0] != "feat-a" || vs[2] != "feat-c" {
		t.Errorf("多值头应保留顺序与个数，得到 %v", vs)
	}
}

func TestInsertSample_TruncFlagsAndPinned(t *testing.T) {
	st := testStore(t)
	s := mkSample(time.Now().UnixMilli())
	s.Truncated = model.TruncInBody | model.TruncRespBody
	s.Pinned = true
	s.Outcome = model.OutcomeTimeout
	s.Error = "首 Token 超过 5m0s"

	if err := st.InsertSample(s); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSample(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Truncated.Has(model.TruncInBody) || !got.Truncated.Has(model.TruncRespBody) {
		t.Errorf("截断标记应往返，得到 %d", got.Truncated)
	}
	if got.Truncated.Has(model.TruncOutBody) {
		t.Error("未设置的标记不该出现")
	}
	if !got.Pinned {
		t.Error("pinned 应往返")
	}
	if got.Error != "首 Token 超过 5m0s" {
		t.Errorf("error 应往返，得到 %q", got.Error)
	}
}

func TestGetSample_NotFound(t *testing.T) {
	st := testStore(t)
	if _, err := st.GetSample(999); err != ErrNotFound {
		t.Errorf("不存在应返回 ErrNotFound，得到 %v", err)
	}
}

// 列表页不返回 body：三个 body 加起来可达 300KB+，一页 50 条就是 15MB。
func TestListSamples_OmitsBodies(t *testing.T) {
	st := testStore(t)
	s := mkSample(time.Now().UnixMilli())
	if err := st.InsertSample(s); err != nil {
		t.Fatal(err)
	}

	list, err := st.ListSamples(SampleFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("应返回 1 条，得到 %d", len(list))
	}
	if len(list[0].InBody) != 0 || len(list[0].OutBody) != 0 || len(list[0].RespBody) != 0 {
		t.Error("列表页不该返回 body —— 一页 50 条会是十几 MB")
	}
	// 但元数据必须齐全，否则列表页没法用
	if list[0].Endpoint != "/v1/messages" || list[0].RespStatus != 200 {
		t.Errorf("元数据应完整，得到 %+v", list[0])
	}
}

// 倒序 + 游标翻页。用 id 游标而不是 OFFSET：
// OFFSET 在翻页期间有新样本写入时会漏记录。
func TestListSamples_OrderAndPaging(t *testing.T) {
	st := testStore(t)
	base := time.Now().UnixMilli()
	for i := 0; i < 10; i++ {
		if err := st.InsertSample(mkSample(base + int64(i))); err != nil {
			t.Fatal(err)
		}
	}

	page1, err := st.ListSamples(SampleFilter{Limit: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(page1) != 4 {
		t.Fatalf("第一页应 4 条，得到 %d", len(page1))
	}
	// 倒序：最新的在前
	if page1[0].ID <= page1[3].ID {
		t.Errorf("应按 id 倒序，得到 %d..%d", page1[0].ID, page1[3].ID)
	}

	page2, err := st.ListSamples(SampleFilter{Limit: 4, BeforeID: page1[3].ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(page2) != 4 {
		t.Fatalf("第二页应 4 条，得到 %d", len(page2))
	}
	if page2[0].ID >= page1[3].ID {
		t.Error("游标翻页应严格小于上一页最后一条的 id")
	}
}

// limit 越界要**截到上限**，而不是掉回默认值。
//
// 掉回默认值的话，limit=1000 会拿到 50 条 —— 而调用方据此以为
// 「一共就这么多」，翻页直接停在第 50 条，剩下的样本看不到也查不出原因。
func TestListSamples_LimitIsClampedNotReset(t *testing.T) {
	st := testStore(t)
	base := time.Now().UnixMilli()
	// 存 60 条：多于默认的 50，少于上限 500
	for i := 0; i < 60; i++ {
		if err := st.InsertSample(mkSample(base + int64(i))); err != nil {
			t.Fatal(err)
		}
	}

	over, err := st.ListSamples(SampleFilter{Limit: maxSampleLimit + 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(over) != 60 {
		t.Errorf("超上限的 limit 应截到 %d（此处数据只有 60 条，应全返回），得到 %d 条"+
			" —— 掉回默认值 %d 会让调用方以为没有更多数据了",
			maxSampleLimit, len(over), defaultSampleLimit)
	}

	// 不传 limit 时用默认值
	def, err := st.ListSamples(SampleFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(def) != defaultSampleLimit {
		t.Errorf("未指定 limit 应返回默认的 %d 条，得到 %d", defaultSampleLimit, len(def))
	}
}

func TestListSamples_Filters(t *testing.T) {
	st := testStore(t)
	base := time.Now().UnixMilli()

	s1 := mkSample(base)
	s1.RouteID, s1.UpstreamID, s1.Outcome = 100, 10, model.OutcomeOK
	s2 := mkSample(base + 1)
	s2.RouteID, s2.UpstreamID, s2.Outcome = 200, 20, model.OutcomeUpstreamError
	s3 := mkSample(base + 2)
	s3.RouteID, s3.UpstreamID, s3.Outcome = 100, 10, model.OutcomeTimeout
	for _, s := range []*model.Sample{s1, s2, s3} {
		if err := st.InsertSample(s); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name string
		f    SampleFilter
		want int
	}{
		{"按 route", SampleFilter{RouteID: 100}, 2},
		{"按 upstream", SampleFilter{UpstreamID: 20}, 1},
		{"按 outcome", SampleFilter{Outcome: model.OutcomeTimeout}, 1},
		{"组合", SampleFilter{RouteID: 100, Outcome: model.OutcomeOK}, 1},
		{"无匹配", SampleFilter{RouteID: 999}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := st.ListSamples(c.f)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != c.want {
				t.Errorf("应返回 %d 条，得到 %d", c.want, len(got))
			}
		})
	}
}

// §9.4：超 500 条被清理，pinned 的不被清。
func TestPruneSamples_ByCount(t *testing.T) {
	st := testStore(t)
	base := time.Now().UnixMilli()
	for i := 0; i < 20; i++ {
		if err := st.InsertSample(mkSample(base + int64(i))); err != nil {
			t.Fatal(err)
		}
	}

	n, err := st.PruneSamples(5, 0, 0) // 只留 5 条，天数/磁盘不限
	if err != nil {
		t.Fatal(err)
	}
	if n != 15 {
		t.Errorf("应删除 15 条，得到 %d", n)
	}
	cnt, err := st.CountSamples()
	if err != nil {
		t.Fatal(err)
	}
	if cnt != 5 {
		t.Errorf("应剩 5 条，得到 %d", cnt)
	}
	// 留下的必须是最新的
	list, _ := st.ListSamples(SampleFilter{Limit: 10})
	if len(list) != 5 || list[0].TSRecv != base+19 {
		t.Errorf("应保留最新的 5 条，最新一条 ts=%d", list[0].TSRecv)
	}
}

// §9.4：超 7 天被清理。
func TestPruneSamples_ByDays(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	old := now.Add(-10 * 24 * time.Hour).UnixMilli()
	fresh := now.Add(-1 * time.Hour).UnixMilli()

	for i := 0; i < 3; i++ {
		if err := st.InsertSample(mkSample(old + int64(i))); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := st.InsertSample(mkSample(fresh + int64(i))); err != nil {
			t.Fatal(err)
		}
	}

	n, err := st.PruneSamples(0, 7, 0) // 只留 7 天，条数/磁盘不限
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("应删除 3 条过期样本，得到 %d", n)
	}
	if cnt, _ := st.CountSamples(); cnt != 2 {
		t.Errorf("应剩 2 条，得到 %d", cnt)
	}
}

// §9.4：pinned 的不被清 —— 两个维度都要豁免。
func TestPruneSamples_PinnedExempt(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	oldMS := now.Add(-30 * 24 * time.Hour).UnixMilli()

	// 一条又老又该被条数挤掉的置顶样本
	pinned := mkSample(oldMS)
	pinned.Pinned = true
	if err := st.InsertSample(pinned); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if err := st.InsertSample(mkSample(now.UnixMilli() + int64(i))); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := st.PruneSamples(3, 7, 0); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetSample(pinned.ID)
	if err != nil {
		t.Fatalf("置顶样本被清掉了：%v", err)
	}
	if !got.Pinned {
		t.Error("置顶标记丢了")
	}
	// 置顶的不该占用条数配额：算进去会导致置顶几条就把正常样本挤掉
	if cnt, _ := st.CountSamples(); cnt != 4 { // 3 条正常 + 1 条置顶
		t.Errorf("应剩 3 条正常 + 1 条置顶 = 4，得到 %d", cnt)
	}
}

// §5.4：Sample Group 含 request_log；清理样本时必须删掉同 req_id 的日志，
// 置顶样本的日志保留；无对应样本的独立日志不动。
func TestPruneSamples_RemovesRequestLogsForDeletedGroups(t *testing.T) {
	st := testStore(t)
	now := time.Now().UnixMilli()

	gone := mkSample(now)
	gone.ReqID = "req-gone"
	keep := mkSample(now + 1)
	keep.ReqID = "req-keep"
	pinned := mkSample(now - 30*24*time.Hour.Milliseconds())
	pinned.ReqID = "req-pinned"
	pinned.Pinned = true
	for _, s := range []*model.Sample{gone, keep, pinned} {
		if err := st.InsertSample(s); err != nil {
			t.Fatal(err)
		}
	}

	// 每个 Group 两次 Attempt；另留一条无样本的独立日志。
	for _, l := range []*model.RequestLog{
		mkLog("req-gone", 1, 2, model.OutcomeUpstreamError),
		mkLog("req-gone", 2, 2, model.OutcomeOK),
		mkLog("req-keep", 1, 1, model.OutcomeOK),
		mkLog("req-pinned", 1, 1, model.OutcomeOK),
		mkLog("req-orphan", 1, 1, model.OutcomeOK),
	} {
		if err := st.InsertRequestLog(l); err != nil {
			t.Fatal(err)
		}
	}

	// 条数只留 1 条未置顶 → 删掉 req-gone 样本（更旧），保留 req-keep + 置顶。
	if _, err := st.PruneSamples(1, 0, 0); err != nil {
		t.Fatal(err)
	}

	goneLogs, err := st.ListRequestLogs(RequestLogFilter{ReqID: "req-gone", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(goneLogs) != 0 {
		t.Fatalf("已删样本的 request_log 应清空，仍剩 %d 行", len(goneLogs))
	}

	keepLogs, err := st.ListRequestLogs(RequestLogFilter{ReqID: "req-keep", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(keepLogs) != 1 {
		t.Fatalf("保留样本的 request_log 应仍在，得到 %d 行", len(keepLogs))
	}

	pinnedLogs, err := st.ListRequestLogs(RequestLogFilter{ReqID: "req-pinned", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(pinnedLogs) != 1 {
		t.Fatalf("置顶样本的 request_log 应保留，得到 %d 行", len(pinnedLogs))
	}

	orphanLogs, err := st.ListRequestLogs(RequestLogFilter{ReqID: "req-orphan", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(orphanLogs) != 1 {
		t.Fatalf("无样本的独立 request_log 不应被样本清理误删，得到 %d 行", len(orphanLogs))
	}
}

// 0 表示该维度不限，不能理解成「全删」。
func TestPruneSamples_ZeroMeansUnlimited(t *testing.T) {
	st := testStore(t)
	for i := 0; i < 5; i++ {
		if err := st.InsertSample(mkSample(time.Now().UnixMilli() + int64(i))); err != nil {
			t.Fatal(err)
		}
	}

	n, err := st.PruneSamples(0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("三个维度都不限时不该删任何东西，删了 %d 条", n)
	}
	if cnt, _ := st.CountSamples(); cnt != 5 {
		t.Errorf("应剩 5 条，得到 %d", cnt)
	}
}

// §5.4：总磁盘配额超限时优先删除最旧未置顶行；置顶豁免；明文与信封行同等计入。
func TestPruneSamples_ByDiskQuota(t *testing.T) {
	st := testStore(t)
	base := time.Now().UnixMilli()
	body := bytes.Repeat([]byte("x"), 2048)

	var ids []int64
	for i := 0; i < 5; i++ {
		s := mkSample(base + int64(i))
		s.InBody = body
		s.OutBody = body
		s.RespBody = body
		if err := st.InsertSample(s); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, s.ID)
	}

	used, err := st.SampleDiskBytes()
	if err != nil {
		t.Fatal(err)
	}
	if used <= 0 {
		t.Fatal("应有正的正文磁盘占用")
	}
	per := used / 5
	if per <= 0 {
		t.Fatalf("单行占用异常 used=%d", used)
	}

	// 只留约两行的配额，应删掉最旧的三条。
	maxBytes := per*2 + per/2
	n, err := st.PruneSamples(0, 0, maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("应删除 3 条，得到 %d (used=%d max=%d per≈%d)", n, used, maxBytes, per)
	}
	after, err := st.SampleDiskBytes()
	if err != nil {
		t.Fatal(err)
	}
	if after > maxBytes {
		t.Fatalf("清理后仍超配额：%d > %d", after, maxBytes)
	}
	for _, id := range ids[:3] {
		if _, err := st.GetSample(id); err != ErrNotFound {
			t.Fatalf("最旧样本 %d 应被删，err=%v", id, err)
		}
	}
	for _, id := range ids[3:] {
		if _, err := st.GetSample(id); err != nil {
			t.Fatalf("较新样本 %d 应保留：%v", id, err)
		}
	}

	// 置顶行占磁盘但不被删；配额无法靠删未置顶降到目标时停在只剩置顶。
	pinned := mkSample(base + 100)
	pinned.InBody = bytes.Repeat([]byte("p"), 4096)
	pinned.OutBody = pinned.InBody
	pinned.RespBody = pinned.InBody
	pinned.Pinned = true
	if err := st.InsertSample(pinned); err != nil {
		t.Fatal(err)
	}
	n, err = st.PruneSamples(0, 0, 1) // 极小配额
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("应至少删掉未置顶行，deleted=%d", n)
	}
	if _, err := st.GetSample(pinned.ID); err != nil {
		t.Fatalf("置顶样本不应被磁盘配额删除：%v", err)
	}
}

// 磁盘清理不得只删信封行或只删明文行——两种存盘形态都必须能进淘汰队列。
func TestPruneSamples_DiskQuotaDeletesPlaintextAndEnvelope(t *testing.T) {
	st := testStore(t)
	plain := bytes.Repeat([]byte("plain-legacy-body"), 128)
	res, err := st.db.Exec(`INSERT INTO sample (
		req_id, ts_recv, ts_sent, ts_first_byte, ts_done,
		endpoint, model_in, model_out, model_name_id, route_id, upstream_id,
		in_method, in_path, in_query, in_headers, in_body,
		out_url, out_headers, out_body,
		resp_status, resp_headers, resp_body,
		outcome, error, truncated, pinned
	) VALUES ('plain-1', ?,0,0,0, '/v1/messages','m','m',1,1,1,
		'POST','/v1/messages','','{}',?,
		'https://ex','{}',?,
		200,'{}',?,
		'ok','',0,0)`, time.Now().UnixMilli()-1000, plain, plain, plain)
	if err != nil {
		t.Fatal(err)
	}
	plainID, _ := res.LastInsertId()

	env := mkSample(time.Now().UnixMilli())
	env.InBody = bytes.Repeat([]byte("envelope-body"), 128)
	env.OutBody = env.InBody
	env.RespBody = env.InBody
	if err := st.InsertSample(env); err != nil {
		t.Fatal(err)
	}

	used, err := st.SampleDiskBytes()
	if err != nil {
		t.Fatal(err)
	}
	// 配额比当前占用少 1 字节：必须删最旧的明文行（证明不是「只删信封」）。
	n, err := st.PruneSamples(0, 0, used-1)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("应删除至少 1 条，got %d", n)
	}
	if _, err := st.GetSample(plainID); err != ErrNotFound {
		t.Fatalf("明文行应被配额删除，err=%v", err)
	}
	if _, err := st.GetSample(env.ID); err != nil {
		t.Fatalf("较新信封行应保留：%v", err)
	}
}

func TestSetSamplePinned(t *testing.T) {
	st := testStore(t)
	s := mkSample(time.Now().UnixMilli())
	if err := st.InsertSample(s); err != nil {
		t.Fatal(err)
	}

	if err := st.SetSamplePinned(s.ID, true); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetSample(s.ID)
	if !got.Pinned {
		t.Error("应置顶成功")
	}

	if err := st.SetSamplePinned(s.ID, false); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetSample(s.ID)
	if got.Pinned {
		t.Error("应取消置顶")
	}

	if err := st.SetSamplePinned(999, true); err != ErrNotFound {
		t.Errorf("不存在应返回 ErrNotFound，得到 %v", err)
	}
}

// UI 的「一键清空」（§3.6.3d）。
func TestClearSamples(t *testing.T) {
	st := testStore(t)
	base := time.Now().UnixMilli()
	pinned := mkSample(base)
	pinned.Pinned = true
	if err := st.InsertSample(pinned); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 5; i++ {
		if err := st.InsertSample(mkSample(base + int64(i))); err != nil {
			t.Fatal(err)
		}
	}

	n, err := st.ClearSamples(true) // 保留置顶
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Errorf("应删除 4 条非置顶，得到 %d", n)
	}
	if cnt, _ := st.CountSamples(); cnt != 1 {
		t.Errorf("应剩 1 条置顶，得到 %d", cnt)
	}

	if _, err := st.ClearSamples(false); err != nil { // 全清
		t.Fatal(err)
	}
	if cnt, _ := st.CountSamples(); cnt != 0 {
		t.Errorf("应全部清空，得到 %d", cnt)
	}
}

// 空 body（如 count_tokens 的响应）不能变成 NULL 扫描错误。
func TestInsertSample_EmptyBodies(t *testing.T) {
	st := testStore(t)
	s := mkSample(time.Now().UnixMilli())
	s.InBody, s.OutBody, s.RespBody = nil, nil, nil
	s.InHeaders, s.OutHeaders, s.RespHeaders = nil, nil, nil

	if err := st.InsertSample(s); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSample(s.ID)
	if err != nil {
		t.Fatalf("空 body 的样本读不回来：%v", err)
	}
	if len(got.InBody) != 0 || len(got.InHeaders) != 0 {
		t.Errorf("空值应读成空而不是报错：%+v", got)
	}
}

// 大 body 要能完整往返 —— BLOB 存的是原始字节，不该有长度问题。
func TestInsertSample_LargeBody(t *testing.T) {
	st := testStore(t)
	s := mkSample(time.Now().UnixMilli())
	s.InBody = bytes.Repeat([]byte("x"), 256*1024)

	if err := st.InsertSample(s); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSample(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.InBody, s.InBody) {
		t.Errorf("256KB body 往返失败：%d vs %d 字节", len(got.InBody), len(s.InBody))
	}
}

// body 里含 NUL 与非法 UTF-8 时也要逐字节往返。
// 用 BLOB 而不是 TEXT 正是为了这个：TEXT 列在某些驱动下会在 NUL 处截断。
func TestInsertSample_BinarySafeBody(t *testing.T) {
	st := testStore(t)
	s := mkSample(time.Now().UnixMilli())
	s.InBody = []byte{'{', 0x00, 0xff, 0xfe, '"', 'a', '"', '}'}

	if err := st.InsertSample(s); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSample(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.InBody, s.InBody) {
		t.Errorf("含 NUL 与非法 UTF-8 的 body 往返失败：%v vs %v", got.InBody, s.InBody)
	}
}

// 两条本可各自吃满「同一剩余配额」的样本，串行插入后合计不得超过配额。
// 回归：仅 tee 时 LimitToRemaining 读一次 used 时，两路在途会把磁盘写成约 2× remaining。
func TestInsertSampleWithinQuota_TwoSamplesShareBudget(t *testing.T) {
	st := testStore(t)
	body := bytes.Repeat([]byte("y"), 2048)

	probe := mkSample(1)
	probe.InBody, probe.OutBody = nil, nil
	probe.RespBody = body
	if err := st.InsertSample(probe); err != nil {
		t.Fatal(err)
	}
	oneCost, err := st.SampleDiskBytes()
	if err != nil {
		t.Fatal(err)
	}
	if oneCost <= 0 {
		t.Fatal("探测样本应占用正的正文磁盘")
	}
	if _, err := st.ClearSamples(false); err != nil {
		t.Fatal(err)
	}

	// 够装一条全文，不够装两条 —— 模拟两路采集都读到同一大块 remaining。
	quota := oneCost + oneCost/2

	s1 := mkSample(2)
	s1.InBody, s1.OutBody = nil, nil
	s1.RespBody = append([]byte(nil), body...)
	s2 := mkSample(3)
	s2.InBody, s2.OutBody = nil, nil
	s2.RespBody = append([]byte(nil), body...)

	ok1, err := st.InsertSampleWithinQuota(s1, quota)
	if err != nil {
		t.Fatal(err)
	}
	if !ok1 {
		t.Fatal("第一条应能完整落入配额")
	}
	ok2, err := st.InsertSampleWithinQuota(s2, quota)
	if err != nil {
		t.Fatal(err)
	}

	used, err := st.SampleDiskBytes()
	if err != nil {
		t.Fatal(err)
	}
	if used > quota {
		t.Fatalf("两条插入后磁盘 %d 超过配额 %d（ok2=%v）", used, quota, ok2)
	}
	if ok2 && !s2.Truncated.Has(model.TruncRespBody) && used > oneCost+oneCost/4 {
		// 第二条入且未截断时，占用约 2×oneCost，必然破配额；走到这里说明断言有洞。
		t.Fatalf("第二条未截断却仍声称插入成功：used=%d oneCost=%d", used, oneCost)
	}
}

// spill 正文大于内存窗口时，Insert 不得把全文读进一个 []byte；落库后内容完整且临时文件已删。
func TestInsertSampleWithinQuota_SpillFileChunkedNoAssemble(t *testing.T) {
	prevChunk := sampleBlobChunk
	sampleBlobChunk = 4 << 10 // 4 KiB
	defer func() { sampleBlobChunk = prevChunk }()

	st := testStore(t)
	dir := t.TempDir()
	spillPath := filepath.Join(dir, "spill.tmp")
	want := bytes.Repeat([]byte("abcdefghij"), 2000) // 20 KiB > 2 chunks
	if err := os.WriteFile(spillPath, want, 0o600); err != nil {
		t.Fatal(err)
	}

	s := mkSample(10)
	s.InBody, s.OutBody, s.RespBody = nil, nil, nil
	s.RespBodyFile = spillPath

	ok, err := st.InsertSampleWithinQuota(s, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("应写入 spill 样本")
	}
	if s.RespBodyFile != "" {
		t.Fatal("成功落库后应清理 RespBodyFile")
	}
	if _, err := os.Stat(spillPath); !os.IsNotExist(err) {
		t.Fatalf("spill 临时文件应已删除，stat=%v", err)
	}

	var raw []byte
	if err := st.db.QueryRow(`SELECT resp_body FROM sample WHERE id=?`, s.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if !isSampleMultipart(raw) {
		prefix := raw
		if len(prefix) > 16 {
			prefix = prefix[:16]
		}
		t.Fatalf("大于分块窗口的 spill 应存 v1m 分帧信封，got prefix %q", prefix)
	}

	got, err := st.GetSample(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.RespBody, want) {
		t.Fatalf("分块落库后正文应完整，want %d got %d", len(want), len(got.RespBody))
	}
}

// 剩余配额为正但连丢掉全部正文后仍无可用字节时，不得插入仅头空壳（占 Group 名额）。
// 回归：EncryptSampleBlob(空)=空 → need=0<=rem 曾误走 INSERT。
func TestInsertSampleWithinQuota_SkipEmptyShellWhenNothingFits(t *testing.T) {
	st := testStore(t)
	s := mkSample(20)
	// rem=1：明文截断后仍可能留 1 字节，但信封膨胀后三路都放不下，最终正文全丢。
	ok, err := st.InsertSampleWithinQuota(s, 1)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("正文全因配额放不下时不得插入空壳行")
	}
	cnt, err := st.CountSamples()
	if err != nil {
		t.Fatal(err)
	}
	if cnt != 0 {
		t.Fatalf("空壳不得占 Sample Group：count=%d", cnt)
	}
	if !s.Truncated.Has(model.TruncInBody) || !s.Truncated.Has(model.TruncOutBody) || !s.Truncated.Has(model.TruncRespBody) {
		t.Fatalf("应标记三路正文因配额丢弃，truncated=%v", s.Truncated)
	}
}

// 正文原本就空（真实空响应）且配额有余时，仍应入库头/状态元数据，不得被 need==0 误跳。
func TestInsertSampleWithinQuota_GenuinelyEmptyStillInserts(t *testing.T) {
	st := testStore(t)
	s := mkSample(22)
	s.InBody, s.OutBody, s.RespBody = nil, nil, nil
	s.RespStatus = 204

	ok, err := st.InsertSampleWithinQuota(s, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("配额有余时原本无正文的样本应插入")
	}
	cnt, err := st.CountSamples()
	if err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Fatalf("应插入 1 行，got %d", cnt)
	}
	got, err := st.GetSample(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RespStatus != 204 {
		t.Fatalf("status want 204, got %d", got.RespStatus)
	}
	if len(got.InBody) != 0 || len(got.OutBody) != 0 || len(got.RespBody) != 0 {
		t.Fatalf("正文应仍为空，in=%d out=%d resp=%d", len(got.InBody), len(got.OutBody), len(got.RespBody))
	}
	if s.Truncated != 0 {
		t.Fatalf("原本无正文不得标记截断，truncated=%v", s.Truncated)
	}
}

// 丢掉 resp（及必要时 out）后若 in 仍放得下，应插入缩小后的行，而非跳过。
func TestInsertSampleWithinQuota_PartialDropStillInserts(t *testing.T) {
	st := testStore(t)
	inPlain := []byte(`{"model":"keep-in"}`)
	encIn, err := st.encryptSampleBody(inPlain)
	if err != nil {
		t.Fatal(err)
	}
	// 配额刚好够加密后的 in，不够再加 out/resp。
	quota := int64(len(encIn))

	s := mkSample(21)
	s.InBody = append([]byte(nil), inPlain...)
	s.OutBody = bytes.Repeat([]byte("o"), 512)
	s.RespBody = bytes.Repeat([]byte("r"), 512)

	ok, err := st.InsertSampleWithinQuota(s, quota)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("丢掉超预算正文后 in 应能落库")
	}
	cnt, err := st.CountSamples()
	if err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Fatalf("应插入 1 行，got %d", cnt)
	}
	got, err := st.GetSample(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.InBody, inPlain) {
		t.Fatalf("in 应完整保留，got %q", got.InBody)
	}
	if len(got.OutBody) != 0 || len(got.RespBody) != 0 {
		t.Fatalf("out/resp 应已丢弃，out=%d resp=%d", len(got.OutBody), len(got.RespBody))
	}
	if !s.Truncated.Has(model.TruncOutBody) || !s.Truncated.Has(model.TruncRespBody) {
		t.Fatalf("应标记 out/resp 截断，truncated=%v", s.Truncated)
	}
}

// 配额跳过时也必须删掉 spill 临时文件。
func TestInsertSampleWithinQuota_SkipRemovesSpillFile(t *testing.T) {
	st := testStore(t)
	filler := mkSample(1)
	filler.InBody, filler.OutBody = nil, nil
	filler.RespBody = bytes.Repeat([]byte("x"), 4096)
	if err := st.InsertSample(filler); err != nil {
		t.Fatal(err)
	}
	used, err := st.SampleDiskBytes()
	if err != nil {
		t.Fatal(err)
	}

	spillPath := filepath.Join(t.TempDir(), "skip-spill.tmp")
	if err := os.WriteFile(spillPath, bytes.Repeat([]byte("y"), 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	s := mkSample(2)
	s.InBody, s.OutBody, s.RespBody = nil, nil, nil
	s.RespBodyFile = spillPath

	ok, err := st.InsertSampleWithinQuota(s, used) // rem == 0
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("配额已满时应跳过")
	}
	if s.RespBodyFile != "" {
		t.Fatal("跳过后应清理 RespBodyFile")
	}
	if _, err := os.Stat(spillPath); !os.IsNotExist(err) {
		t.Fatalf("跳过后 spill 应已删除，stat=%v", err)
	}
}
