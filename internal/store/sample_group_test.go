package store

import (
	"bytes"
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// §5.4：一个客户端请求 = 一条 sample_request + 每次实际发送的 sample_attempt。
// 入站 body 只存一次；两次上游联系各存一条尝试，按发送顺序返回。
func TestSampleGroup_TwoAttemptsOneInboundBody(t *testing.T) {
	st := testStore(t)
	now := time.Now().UnixMilli()
	in := []byte(`{"model":"claude-opus-5","messages":"hello"}`)
	smp := &model.Sample{
		ReqID: "req-two", TSRecv: now, Endpoint: "/v1/messages", ModelIn: "claude-opus-5",
		InMethod: "POST", InPath: "/v1/messages", InHeaders: http.Header{"X-Api-Key": {"rk-…ey"}},
		InBody: in,
		Attempts: []*model.SampleAttempt{
			{TSRecv: now, TSSent: now + 1, RouteID: 100, UpstreamID: 10,
				OutURL: "https://a.example/v1/messages", OutBody: []byte(`{"model":"a-model"}`),
				RespStatus: 502, RespBody: []byte(`down`), Outcome: model.OutcomeUpstreamError},
			{TSRecv: now, TSSent: now + 2, RouteID: 200, UpstreamID: 20,
				OutURL: "https://b.example/v1/messages", OutBody: []byte(`{"model":"b-model"}`),
				RespStatus: 200, RespBody: []byte(`{"id":"ok"}`), Outcome: model.OutcomeOK},
		},
	}
	if err := st.InsertSample(smp); err != nil {
		t.Fatal(err)
	}

	var requests, attempts int
	if err := st.db.QueryRow(`SELECT (SELECT COUNT(*) FROM sample_request), (SELECT COUNT(*) FROM sample_attempt)`).
		Scan(&requests, &attempts); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || attempts != 2 {
		t.Fatalf("requests=%d attempts=%d, want 1/2", requests, attempts)
	}
	var rawIn []byte
	if err := st.db.QueryRow(`SELECT in_body FROM sample_request WHERE id=?`, smp.ID).Scan(&rawIn); err != nil {
		t.Fatal(err)
	}
	if !IsSampleEnvelope(rawIn) {
		t.Fatal("inbound body must be enveloped")
	}
	var plainAttempts int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM sample_attempt WHERE request_id=? AND
		(CAST(out_body AS TEXT) LIKE '%model%' OR CAST(resp_body AS TEXT) LIKE '%down%')`, smp.ID).Scan(&plainAttempts); err != nil {
		t.Fatal(err)
	}
	if plainAttempts != 0 {
		t.Fatal("attempt bodies must be enveloped, found plaintext")
	}

	got, err := st.GetSample(smp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.InBody, in) || got.AttemptCount != 2 || len(got.Attempts) != 2 {
		t.Fatalf("group = in %q count %d attempts %d", got.InBody, got.AttemptCount, len(got.Attempts))
	}
	first, second := got.Attempts[0], got.Attempts[1]
	if first.RouteID != 100 || first.RespStatus != 502 || string(first.RespBody) != "down" ||
		string(first.OutBody) != `{"model":"a-model"}` {
		t.Fatalf("first attempt = %+v", first)
	}
	if second.RouteID != 200 || second.RespStatus != 200 || string(second.OutBody) != `{"model":"b-model"}` {
		t.Fatalf("second attempt = %+v", second)
	}
	if got.RouteID != 200 || got.RespStatus != 200 || string(got.RespBody) != `{"id":"ok"}` {
		t.Fatalf("flat view must be the final attempt, got route=%d status=%d", got.RouteID, got.RespStatus)
	}

	list, err := st.ListSamples(SampleFilter{ReqID: "req-two"})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].AttemptCount != 2 || list[0].RouteID != 200 || list[0].Outcome != model.OutcomeOK {
		t.Fatalf("list = %+v", list)
	}

	used, err := st.SampleDiskBytes()
	if err != nil {
		t.Fatal(err)
	}
	var want int64
	if err := st.db.QueryRow(`SELECT
		(SELECT SUM(LENGTH(in_body)) FROM sample_request) +
		(SELECT SUM(COALESCE(LENGTH(out_body),0)+COALESCE(LENGTH(resp_body),0)) FROM sample_attempt)`).Scan(&want); err != nil {
		t.Fatal(err)
	}
	if used != want {
		t.Fatalf("disk bytes = %d, want %d (request + every attempt)", used, want)
	}

	if _, err := st.ClearSamples(false); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM sample_attempt`).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 {
		t.Fatalf("deleting the group must delete its attempts, left %d", attempts)
	}
}

// 按条数清理删的是整组；置顶组连同它的全部尝试保留。
func TestSampleGroup_PruneKeepsPinnedGroupAttempts(t *testing.T) {
	st := testStore(t)
	now := time.Now().UnixMilli()
	mk := func(reqID string, pinned bool) *model.Sample {
		return &model.Sample{
			ReqID: reqID, TSRecv: now, Endpoint: "/v1/messages", InBody: []byte("in"), Pinned: pinned,
			Attempts: []*model.SampleAttempt{
				{RouteID: 1, RespStatus: 502, RespBody: []byte("x"), Outcome: model.OutcomeUpstreamError},
				{RouteID: 2, RespStatus: 200, RespBody: []byte("y"), Outcome: model.OutcomeOK},
			},
		}
	}
	pinned := mk("pinned", true)
	if err := st.InsertSample(pinned); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if err := st.InsertSample(mk(id, false)); err != nil {
			t.Fatal(err)
		}
	}
	n, err := st.PruneSamples(1, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("pruned groups = %d, want 2", n)
	}
	var requests, attempts int
	if err := st.db.QueryRow(`SELECT (SELECT COUNT(*) FROM sample_request), (SELECT COUNT(*) FROM sample_attempt)`).
		Scan(&requests, &attempts); err != nil {
		t.Fatal(err)
	}
	if requests != 2 || attempts != 4 {
		t.Fatalf("after prune requests=%d attempts=%d, want 2/4", requests, attempts)
	}
	got, err := st.GetSample(pinned.ID)
	if err != nil || len(got.Attempts) != 2 {
		t.Fatalf("pinned group must keep both attempts: err=%v got=%+v", err, got)
	}
}

// §5.7：旧 sample 每行迁成一条 sample_request 和一条代表旧最终尝试的
// sample_attempt；未保存的重试 body 不伪造。BLOB 原样复制，明文与信封都能读。
func TestSchemaSeven_MigratesLegacySampleAsSingleFinalAttempt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v6.db")
	cipher, err := NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	db := openDatabaseAtPath(t, path)
	if err := initializeEmptySchemaSix(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	encIn, err := cipher.EncryptSampleBlob([]byte(`{"model":"legacy-in"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sample (id, req_id, ts_recv, ts_sent, ts_first_byte, ts_done,
		endpoint, model_in, model_out, model_name_id, route_id, upstream_id,
		in_method, in_path, in_query, in_headers, in_body,
		out_url, out_headers, out_body, resp_status, resp_headers, resp_body,
		outcome, error, truncated, pinned)
		VALUES (41, 'legacy-req', 1000, 1010, 1500, 2000,
		'/v1/messages', 'claude-opus-5', 'upstream-model', 3, 300, 30,
		'POST', '/v1/messages', 'beta=true', '{"X-Api-Key":["rk-…ey"]}', ?,
		'https://final.example/v1/messages', '{}', ?, 200, '{"Content-Type":["application/json"]}', ?,
		'ok', '', 7, 1)`,
		encIn, []byte(`{"model":"upstream-model"}`), []byte(`{"id":"final"}`)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	state, err := inspectSchemaState(context.Background(), st.db)
	if err != nil || state.Version != 7 {
		t.Fatalf("state=%+v err=%v", state, err)
	}

	got, err := st.GetSample(41)
	if err != nil {
		t.Fatalf("legacy group must open under its old id: %v", err)
	}
	if got.LegacySampleID != 41 || got.ReqID != "legacy-req" || !got.Pinned || got.TSRecv != 1000 {
		t.Fatalf("legacy request metadata = %+v", got)
	}
	if len(got.Attempts) != 1 || got.AttemptCount != 1 {
		t.Fatalf("legacy group must have exactly the old final attempt, got %d", len(got.Attempts))
	}
	a := got.Attempts[0]
	if a.RouteID != 300 || a.UpstreamID != 30 || a.ModelOut != "upstream-model" || a.RespStatus != 200 ||
		a.TSSent != 1010 || a.TSFirstByte != 1500 || a.TSDone != 2000 ||
		string(a.OutBody) != `{"model":"upstream-model"}` || string(a.RespBody) != `{"id":"final"}` {
		t.Fatalf("legacy final attempt = %+v", a)
	}
	if string(got.InBody) != `{"model":"legacy-in"}` {
		t.Fatalf("enveloped legacy in_body = %q", got.InBody)
	}
	if got.InQuery != "beta=true" || got.InHeaders.Get("X-Api-Key") != "rk-…ey" {
		t.Fatalf("legacy inbound fields lost: query=%q headers=%v", got.InQuery, got.InHeaders)
	}
	if got.Truncated != model.TruncInBody|model.TruncOutBody|model.TruncRespBody {
		t.Fatalf("truncation = %v, want all three bits preserved", got.Truncated)
	}
	var reqTrunc, attTrunc int
	if err := st.db.QueryRow(`SELECT r.truncated, a.truncated FROM sample_request r
		JOIN sample_attempt a ON a.request_id = r.id WHERE r.id = 41`).Scan(&reqTrunc, &attTrunc); err != nil {
		t.Fatal(err)
	}
	if reqTrunc != int(model.TruncInBody) || attTrunc != int(model.TruncOutBody|model.TruncRespBody) {
		t.Fatalf("truncation split request=%d attempt=%d", reqTrunc, attTrunc)
	}

	// New groups continue after the migrated id and do not collide with it.
	fresh := mkSample(time.Now().UnixMilli())
	if err := st.InsertSample(fresh); err != nil {
		t.Fatal(err)
	}
	if fresh.ID <= 41 {
		t.Fatalf("new group id %d must follow migrated ids", fresh.ID)
	}
	gotFresh, err := st.GetSample(fresh.ID)
	if err != nil || gotFresh.LegacySampleID != 0 {
		t.Fatalf("fresh group legacy id = %d err=%v", gotFresh.LegacySampleID, err)
	}
}
