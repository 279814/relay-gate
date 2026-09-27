package proxy

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

// §5.4 / §16.3：一次客户端请求 = 一个 Sample Group —— 入站请求只存一次，
// 每次实际联系上游都存一条尝试（出站请求 + 上游响应），按发送顺序。
// route-local 跳过（这里是空上游 key）从未出网，不得产生尝试。
func TestRetry_SampleGroupStoresEverySendOnce(t *testing.T) {
	hs := newMultiHarness(t,
		respondStatus(502, `down-from-first`),
		respondOK(`{"id":"never-contacted"}`),
		respondOK(`{"id":"ok"}`))
	hs.cfg.settings.RealTotalSec = 30
	hs.cfg.settings.RetryMaxAttempts = 3
	hs.cfg.snap.Upstreams[11].APIKey = ""
	hs.h.WithCountTokensCapability(&routeConfigCaps{})

	body := `{"model":"claude-opus-5","max_tokens":1,"messages":[{"role":"user","content":"inbound-once"}]}`
	if rec := hs.serve(body); rec.Code != 200 {
		t.Fatalf("应在第三站成功，得到 %d: %s", rec.Code, rec.Body.String())
	}
	hs.assertHits(t, 1, 0, 1)

	smp := hs.sink.one(t)
	if string(smp.InBody) != body {
		t.Fatalf("入站 body 应原样存一次，得到 %q", smp.InBody)
	}
	if smp.AttemptCount != 2 || len(smp.Attempts) != 2 {
		t.Fatalf("两次上游联系应有 2 条尝试（本地跳过不算），得到 count=%d len=%d",
			smp.AttemptCount, len(smp.Attempts))
	}
	first, final := smp.Attempts[0], smp.Attempts[1]
	if first.RouteID != 100 || first.RespStatus != 502 || !strings.Contains(string(first.RespBody), "down-from-first") {
		t.Fatalf("第一条尝试应是被丢弃的 502 及其响应体，得到 route=%d status=%d body=%q",
			first.RouteID, first.RespStatus, first.RespBody)
	}
	if !strings.Contains(string(first.OutBody), "inbound-once") || first.OutURL == "" {
		t.Fatalf("第一条尝试应保留实际发出的请求，得到 url=%q body=%q", first.OutURL, first.OutBody)
	}
	if final.RouteID != 300 || final.RespStatus != 200 || string(final.RespBody) != `{"id":"ok"}` {
		t.Fatalf("最终尝试应是第三站的 200，得到 route=%d status=%d body=%q",
			final.RouteID, final.RespStatus, final.RespBody)
	}
	for i, a := range smp.Attempts {
		if a.RouteID == 200 {
			t.Fatalf("本地跳过的 Route 200 不得产生尝试（attempt %d）", i)
		}
		for _, key := range []string{"sk-station-0-secret", "sk-station-2-secret", hs.relayPW} {
			for _, v := range a.OutHeaders {
				if strings.Contains(strings.Join(v, ","), key) {
					t.Fatalf("attempt %d 出站头含明文凭据", i)
				}
			}
		}
	}
	if smp.RouteID != 300 || smp.RespStatus != 200 {
		t.Fatalf("平铺视图应是最终尝试，得到 route=%d status=%d", smp.RouteID, smp.RespStatus)
	}

	// 落库：一条 sample_request，两条 sample_attempt，入站 body 只存一份。
	cipher, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "samples.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.InsertSample(smp); err != nil {
		t.Fatal(err)
	}
	var requests, attempts int
	if err := st.DB().QueryRow(`SELECT (SELECT COUNT(*) FROM sample_request),
		(SELECT COUNT(*) FROM sample_attempt WHERE request_id = ?)`, smp.ID).Scan(&requests, &attempts); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || attempts != 2 {
		t.Fatalf("stored requests=%d attempts=%d, want 1/2", requests, attempts)
	}
	got, err := st.GetSample(smp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.InBody) != body || len(got.Attempts) != 2 ||
		got.Attempts[0].RespStatus != 502 || got.Attempts[1].RespStatus != 200 {
		t.Fatalf("stored group = in %q attempts %d", got.InBody, len(got.Attempts))
	}
	if !strings.Contains(string(got.Attempts[0].RespBody), "down-from-first") {
		t.Fatalf("stored discarded response = %q", got.Attempts[0].RespBody)
	}
}

// 没有重试时仍是一组一条尝试。
func TestRetry_SampleGroupSingleSendHasOneAttempt(t *testing.T) {
	hs := newMultiHarness(t, respondOK(`{"id":"ok"}`))
	if rec := hs.serve(hs.req()); rec.Code != 200 {
		t.Fatalf("got %d", rec.Code)
	}
	smp := hs.sink.one(t)
	if smp.AttemptCount != 1 || len(smp.Attempts) != 1 || smp.Attempts[0].RouteID != 100 {
		t.Fatalf("single send attempts = %+v", smp.Attempts)
	}
	if smp.Attempts[0].Outcome != model.OutcomeOK {
		t.Fatalf("outcome = %q", smp.Attempts[0].Outcome)
	}
}
