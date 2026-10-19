package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

type recentErrorResponse struct {
	FailedCount int64  `json:"failed_count"`
	NextCursor  string `json:"next_cursor"`
	Logs        []struct {
		model.RequestLog
		SampleID int64 `json:"sample_id"`
	} `json:"logs"`
}

func TestRecentErrorsFiltersRecordedErrorClassWithoutOutcomeGuess(t *testing.T) {
	s, h := newTestServer(t)
	for i, class := range []model.ErrorClass{model.ErrorAuthRejected, model.ErrorRateLimited, "unknown"} {
		row := &model.RequestLog{ReqID: fmt.Sprint(i), Outcome: model.OutcomeUpstreamError, Metadata: model.AttemptMetadata{Version: 1, ErrorClass: class}}
		if err := s.st.InsertRequestLog(row); err != nil {
			t.Fatal(err)
		}
	}
	for _, class := range []string{"auth_rejected", "rate_limited", "unknown"} {
		rec := do(t, h, "GET", "/admin/api/recent-errors?error_class="+class, "", true)
		if rec.Code != 200 {
			t.Fatalf("class %s status=%d body=%s", class, rec.Code, rec.Body.String())
		}
		var page recentErrorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if page.FailedCount != 1 || len(page.Logs) != 1 || string(page.Logs[0].Metadata.ErrorClass) != class {
			t.Fatalf("coarse outcome substituted class %s: %+v", class, page)
		}
	}
	if rec := do(t, h, "GET", "/admin/api/recent-errors?error_class=timeout", "", true); rec.Code != 400 {
		t.Fatalf("accepted invented ErrorClass: %d", rec.Code)
	}
}

func TestRecentErrorsFiltersBoundCursorAndNeverReturnSuccess(t *testing.T) {
	s, h := newTestServer(t)
	insert := func(route, upstream, ts int64, path string, outcome model.Outcome) {
		t.Helper()
		if err := s.st.InsertRequestLog(&model.RequestLog{RouteID: route, UpstreamID: upstream, TSRecv: ts,
			ReqID: fmt.Sprintf("fixture-%d-%d-%d-%s", route, upstream, ts, path), Endpoint: path, Outcome: outcome}); err != nil {
			t.Fatal(err)
		}
	}
	for i := int64(0); i < 205; i++ {
		insert(10, 20, 1000+i, "/v1/messages", model.OutcomeTimeout)
	}
	insert(11, 20, 1100, "/v1/messages", model.OutcomeTimeout)
	insert(10, 21, 1100, "/v1/messages", model.OutcomeTimeout)
	insert(10, 20, 1100, "/v1/chat/completions", model.OutcomeTimeout)
	insert(10, 20, 1100, "/v1/messages", model.OutcomeUpstreamError)
	insert(10, 20, 1100, "/v1/messages", model.OutcomeOK)
	insert(10, 20, 999, "/v1/messages", model.OutcomeTimeout)
	base := "/admin/api/recent-errors?route_id=10&upstream_id=20&protocol=anthropic&outcome=timeout&from_ms=1000&to_ms=1204&limit=200"
	first := do(t, h, "GET", base, "", true)
	if first.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", first.Code, first.Body.String())
	}
	var page recentErrorResponse
	if err := json.Unmarshal(first.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.FailedCount != 205 || len(page.Logs) != 200 || page.NextCursor == "" {
		t.Fatalf("filtered page must contain 200 of 205 failures with a cursor: count=%d rows=%d cursor=%t", page.FailedCount, len(page.Logs), page.NextCursor != "")
	}
	seen := map[int64]bool{}
	for _, row := range page.Logs {
		if row.Outcome != model.OutcomeTimeout {
			t.Fatal("unmatched outcome")
		}
		seen[row.ID] = true
	}
	cursor := page.NextCursor
	insert(10, 20, 1100, "/v1/messages", model.OutcomeTimeout)
	second := do(t, h, "GET", base+"&cursor="+url.QueryEscape(cursor), "", true)
	if second.Code != 200 {
		t.Fatalf("second page: %d %s", second.Code, second.Body.String())
	}
	if err := json.Unmarshal(second.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Logs) != 5 || page.NextCursor != "" || page.FailedCount != 206 {
		t.Fatalf("unstable second page: count=%d rows=%d cursor=%q", page.FailedCount, len(page.Logs), page.NextCursor)
	}
	for _, row := range page.Logs {
		if seen[row.ID] {
			t.Fatal("duplicate row across pages")
		}
		seen[row.ID] = true
	}
	changed := strings.Replace(base, "route_id=10", "route_id=11", 1) + "&cursor=" + url.QueryEscape(cursor)
	if rec := do(t, h, "GET", changed, "", true); rec.Code != 400 {
		t.Fatalf("changed filter accepted cursor: %d", rec.Code)
	}
}

func TestRecentErrorsRejectInvalidFiltersAndRequireAuth(t *testing.T) {
	_, h := newTestServer(t)
	for _, query := range []string{"limit=0", "limit=201", "limit=bad", "route_id=-1", "upstream_id=0", "protocol=unknown", "outcome=ok", "from_ms=bad", "from_ms=20&to_ms=10", "route_id=1&route_id=2", "cursor=bad", "before_id=20", "unexpected=SQL"} {
		t.Run(query, func(t *testing.T) {
			rec := do(t, h, "GET", "/admin/api/recent-errors?"+query, "", true)
			if rec.Code != 400 {
				t.Fatalf("invalid filter accepted: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
	if rec := do(t, h, "GET", "/admin/api/recent-errors", "", false); rec.Code != 401 {
		t.Fatalf("unauthorized status=%d", rec.Code)
	}
}

func TestRecentErrorsCountDoesNotDecodeEveryHistoricalLog(t *testing.T) {
	s, h := newTestServer(t)
	old := &model.RequestLog{ReqID: "old", Outcome: model.OutcomeTimeout}
	if err := s.st.InsertRequestLog(old); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB().Exec(`UPDATE request_log SET attempt='unreadable-legacy-integer' WHERE id=?`, old.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 205; i++ {
		if err := s.st.InsertRequestLog(&model.RequestLog{ReqID: fmt.Sprint(i), Outcome: model.OutcomeTimeout}); err != nil {
			t.Fatal(err)
		}
	}
	rec := do(t, h, "GET", "/admin/api/recent-errors?limit=1", "", true)
	if rec.Code != 200 {
		t.Fatalf("count must aggregate in SQL without decoding unrelated rows: %d %s", rec.Code, rec.Body.String())
	}
	var page recentErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.FailedCount != 206 || len(page.Logs) != 1 {
		t.Fatalf("count=%d rows=%d", page.FailedCount, len(page.Logs))
	}
}

func TestRecentErrorsRedactTextAndLinkSampleWithoutLoadingBody(t *testing.T) {
	s, h := newTestServer(t)
	const key = "synthetic-recent-error-upstream-secret"
	up := metadataUpstream(t, s, "recent-error-upstream", key)
	smp := &model.Sample{ReqID: "linked-request", InBody: []byte("private-business-text"), Outcome: model.OutcomeOK}
	if err := s.st.InsertSample(smp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB().Exec(`UPDATE sample_request SET in_body='broken-ciphertext' WHERE id=?`, smp.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.st.InsertRequestLog(&model.RequestLog{ReqID: smp.ReqID, UpstreamID: up.ID, Outcome: model.OutcomeUpstreamError, Error: "<img src=x> " + key}); err != nil {
		t.Fatal(err)
	}
	rec := do(t, h, "GET", "/admin/api/recent-errors", "", true)
	if rec.Code != 200 {
		t.Fatalf("metadata link must not decrypt a sample: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), key) || strings.Contains(rec.Body.String(), "private-business-text") {
		t.Fatal("private text escaped diagnostics")
	}
	var page recentErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Logs) != 1 || page.Logs[0].SampleID != smp.ID || !strings.Contains(page.Logs[0].Error, "<img src=x>") {
		t.Fatalf("missing exact metadata link or plain text: %+v", page)
	}
	if _, err := s.st.DB().Exec(`UPDATE upstream SET api_key_enc='unreadable' WHERE id=?`, up.ID); err != nil {
		t.Fatal(err)
	}
	if rec = do(t, h, "GET", "/admin/api/recent-errors", "", true); rec.Code != 503 || strings.Contains(rec.Body.String(), key) {
		t.Fatalf("unreadable redaction keys must fail closed: %d", rec.Code)
	}
}

func TestRecentErrorsAndRequestLogLinkRedactCurrentProbeSecret(t *testing.T) {
	s, h := newTestServer(t)
	const key = "synthetic-recent-error-probe-secret"
	secret, err := s.st.CreateProbeSecret("recent-error-probe", []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.st.InsertRequestLog(&model.RequestLog{ReqID: "probe-linked", Outcome: model.OutcomeTimeout, Error: "legacy opaque value " + key}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/admin/api/recent-errors", "/admin/api/request-logs?req_id=probe-linked"} {
		rec := do(t, h, "GET", path, "", true)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), key) {
			t.Fatalf("ProbeSecret escaped diagnostic read at %s, status=%d", path, rec.Code)
		}
	}
	if _, err := s.st.DB().Exec(`UPDATE probe_secret SET value_enc='broken-envelope' WHERE id=?`, secret.ID); err != nil {
		t.Fatal(err)
	}
	if rec := do(t, h, "GET", "/admin/api/recent-errors", "", true); rec.Code != 503 {
		t.Fatalf("bad ProbeSecret must fail closed: %d", rec.Code)
	}
}
