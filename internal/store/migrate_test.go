package store

import (
	"path/filepath"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

// 迁移必须能给**已存在**的库加列。
//
// 这是 CREATE TABLE IF NOT EXISTS 覆盖不到的场合：它对已存在的表是空操作，
// 于是老库会静默停在旧结构上，而症状是「新字段读出来永远是零值」——
// 不报错、不失败，只是功能悄悄不工作。
//
// 这里使用受支持的 M6 pre-column 精确 fixture，而不是从当前 schema 任意拆列。
// 任意部分结构现在必须 fail closed，只有已知历史指纹允许 normalization。
func TestMigrate_AddsReqIDToExistingSampleTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	c, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}

	legacy := openDatabaseAtPath(t, path)
	loadLegacyVariantFixture(t, legacy, legacySchemaM6PreColumn)
	if _, err := legacy.Exec(`INSERT INTO sample(ts_recv, endpoint, outcome) VALUES (1, '/v1/messages', 'ok')`); err != nil {
		t.Fatal(err)
	}
	if has, _ := hasColumn(legacy, "sample", "req_id"); has {
		t.Fatal("fixture 前提不成立：req_id 应不存在")
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	// 2. 正常 Open 先备份原 variant，再做 0→1 normalization 与 1→2 expand。
	st2, err := Open(path, c)
	if err != nil {
		t.Fatalf("打开老库应成功（迁移要能处理它）：%v", err)
	}
	defer st2.Close()

	// 3. 列加上了
	has, err := hasColumn(st2.db, "sample", "req_id")
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Error("迁移应给已存在的 sample 表加上 req_id —— " +
			"没加的话新功能静默不工作，且不报错")
	}

	// 4. 索引也要补上，否则按 req_id 查样本会全表扫
	var idx int
	if err := st2.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master
		WHERE type = 'index' AND name = 'idx_sample_req'`).Scan(&idx); err != nil {
		t.Fatal(err)
	}
	if idx != 1 {
		t.Error("迁移应补上 idx_sample_req")
	}

	// 5. 旧数据还在，且新列取到默认值（空串）而不是 NULL
	var n int
	var reqID string
	if err := st2.db.QueryRow(
		`SELECT COUNT(*), COALESCE(MAX(req_id), 'NULL!') FROM sample`).Scan(&n, &reqID); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("迁移不该丢数据，剩 %d 行", n)
	}
	if reqID != "" {
		t.Errorf("老行的 req_id 应是空串（DEFAULT ''），得到 %q", reqID)
	}

	// 6. 迁移后的库要能正常读写 —— 加列之后 scanSample 的列顺序必须仍然对得上
	if err := st2.InsertSample(&model.Sample{
		ReqID: "after-migrate", TSRecv: 2, Endpoint: "/v1/messages"}); err != nil {
		t.Fatalf("迁移后写入失败：%v", err)
	}
	got, err := st2.ListSamples(SampleFilter{ReqID: "after-migrate"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("迁移后应能按 req_id 查到新样本，得到 %d 条", len(got))
	}
}

// 迁移必须幂等：schema.sql 每次启动都跑，migrate 也一样。
//
// 不幂等的表现是**第二次启动直接失败**（duplicate column name），
// 也就是说升级后能跑，重启一次就起不来了。
func TestMigrate_IsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repeat.db")
	c, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}

	for i := 1; i <= 3; i++ {
		st, err := Open(path, c)
		if err != nil {
			t.Fatalf("第 %d 次打开失败：%v —— 迁移不幂等，重启就起不来", i, err)
		}
		st.Close()
	}
}

// 新库走 schema.sql 就该带 req_id，不依赖迁移补。
//
// 两条路径都要通：只靠迁移的话，schema.sql 与实际结构会越差越远，
// 而 schema.sql 是唯一能一眼看全表结构的地方。
func TestMigrate_FreshDBHasReqIDFromSchema(t *testing.T) {
	st := testStore(t)
	has, err := hasColumn(st.db, "sample", "req_id")
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Error("新库的 schema.sql 里就该有 req_id")
	}
}

// req_id 要能真的往返，并且能按它把样本与日志关联起来 ——
// 这是整条关联链存在的目的。
func TestSampleReqIDRoundTripAndFilter(t *testing.T) {
	st := testStore(t)

	smp := &model.Sample{
		ReqID: "abc123", TSRecv: 1, Endpoint: "/v1/messages",
		ModelIn: "claude-opus-5", Outcome: model.OutcomeOK,
	}
	if err := st.InsertSample(smp); err != nil {
		t.Fatal(err)
	}
	other := &model.Sample{ReqID: "zzz999", TSRecv: 2, Endpoint: "/v1/messages"}
	if err := st.InsertSample(other); err != nil {
		t.Fatal(err)
	}

	// 详情页读回来要带 req_id
	got, err := st.GetSample(smp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ReqID != "abc123" {
		t.Errorf("req_id 应往返，得到 %q", got.ReqID)
	}

	// 按组筛选：从日志的某一组跳到它的样本
	list, err := st.ListSamples(SampleFilter{ReqID: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("按 req_id 应筛出 1 条，得到 %d", len(list))
	}
	if list[0].ID != smp.ID {
		t.Errorf("筛出的不是目标样本")
	}
	// 列表页也要带 req_id，否则 UI 上没法给出跳转链接
	if list[0].ReqID != "abc123" {
		t.Errorf("列表页也应返回 req_id，得到 %q", list[0].ReqID)
	}
}
