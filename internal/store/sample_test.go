package store

import (
	"bytes"
	"net/http"
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

	n, err := st.PruneSamples(5, 0) // 只留 5 条，天数不限
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

	n, err := st.PruneSamples(0, 7) // 只留 7 天，条数不限
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

	if _, err := st.PruneSamples(3, 7); err != nil {
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

// 0 表示该维度不限，不能理解成「全删」。
func TestPruneSamples_ZeroMeansUnlimited(t *testing.T) {
	st := testStore(t)
	for i := 0; i < 5; i++ {
		if err := st.InsertSample(mkSample(time.Now().UnixMilli() + int64(i))); err != nil {
			t.Fatal(err)
		}
	}

	n, err := st.PruneSamples(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("两个维度都不限时不该删任何东西，删了 %d 条", n)
	}
	if cnt, _ := st.CountSamples(); cnt != 5 {
		t.Errorf("应剩 5 条，得到 %d", cnt)
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
