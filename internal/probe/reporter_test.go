package probe

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/proxy"
)

// §6.8 / §8.12：HTTP 200 结构化 error 不得按 200 判活，也不得 piggyback。
func TestClassifyReal_HTTP200StructuredErrorNotOK(t *testing.T) {
	tests := []struct {
		name string
		body string
		ct   string
		want health.Verdict
	}{
		{
			name: "type error object",
			body: `{"type":"error","error":{"type":"server_error","message":"boom"}}`,
			want: health.VerdictUnavailable,
		},
		{
			name: "top-level error key",
			body: `{"error":{"type":"api_error","message":"fail"}}`,
			want: health.VerdictUnavailable,
		},
		{
			name: "SSE error event",
			body: "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n",
			ct:   "text/event-stream",
			want: health.VerdictRateLimited,
		},
		{
			name: "rate_limit in JSON body",
			body: `{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`,
			want: health.VerdictRateLimited,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.ct != "" {
				h.Set("Content-Type", tc.ct)
			}
			out := classifyReal(&proxy.ResultView{
				Status:       200,
				ErrBody:      []byte(tc.body),
				Header:       h,
				BytesWritten: int64(len(tc.body)),
			})
			if out.Verdict != tc.want {
				t.Fatalf("verdict=%s want %s (err=%v)", out.Verdict, tc.want, out.Err)
			}
		})
	}
}

func TestClassifyReal_HTTP200WithContentStillOK(t *testing.T) {
	out := classifyReal(&proxy.ResultView{
		Status:       200,
		ErrBody:      nil,
		BytesWritten: 120,
		SemanticSeen: true,
	})
	if out.Verdict != health.VerdictOK {
		t.Fatalf("normal 200 with semantic evidence should be OK, got %s", out.Verdict)
	}
}

func TestClassifyReal_HTTP200BytesWithoutSemanticIsFakeAlive(t *testing.T) {
	out := classifyReal(&proxy.ResultView{
		Status:       200,
		BytesWritten: 512,
		SemanticSeen: false,
	})
	if out.Verdict != health.VerdictUnavailable {
		t.Fatalf("200 with bytes but no semantic evidence should be unavailable, got %s", out.Verdict)
	}
}

func TestClassifyReal_HTTP200EmptyIsFakeAlive(t *testing.T) {
	out := classifyReal(&proxy.ResultView{Status: 200, BytesWritten: 0})
	if out.Verdict != health.VerdictUnavailable {
		t.Fatalf("empty 200 should be unavailable, got %s", out.Verdict)
	}
}

func TestReportResult_HTML200DoesNotRefreshLastRealOK(t *testing.T) {
	tr := health.NewTracker(nil)
	tr.Report(health.Report{RouteID: 9, Verdict: health.VerdictOK, Source: health.SourceReal})
	seeded := tr.Status(9).LastRealOKAt
	if seeded == 0 {
		t.Fatal("seed real OK should set lastRealOKAt")
	}

	rep := NewReporter(tr)
	rep.ReportResult(9, 0, &proxy.ResultView{
		Status:       200,
		BytesWritten: 240,
		SemanticSeen: false, // HTML / 空壳 200：有字节但无语义证据
	})

	after := tr.Status(9)
	if after.LastRealOKAt != seeded {
		t.Fatalf("HTML 200 must not refresh lastRealOKAt: before=%d after=%d",
			seeded, after.LastRealOKAt)
	}
	if after.ConsecutiveFail < 1 {
		t.Fatalf("HTML 200 should count as failure, consecutive_fail=%d", after.ConsecutiveFail)
	}
}

func TestReportResult_TextDeltaStillPiggybacks(t *testing.T) {
	tr := health.NewTracker(nil)
	tr.Report(health.Report{RouteID: 10, Verdict: health.VerdictOK, Source: health.SourceReal})
	seeded := tr.Status(10).LastRealOKAt

	// LastRealOKAt 精度是毫秒；同毫秒内两次 OK 看不出刷新。
	time.Sleep(2 * time.Millisecond)

	rep := NewReporter(tr)
	rep.ReportResult(10, 0, &proxy.ResultView{
		Status:       200,
		BytesWritten: 180,
		SemanticSeen: true,
	})

	after := tr.Status(10)
	if after.LastRealOKAt == seeded {
		t.Fatal("normal text delta must refresh lastRealOKAt for piggyback")
	}
	if after.ConsecutiveFail != 0 {
		t.Fatalf("semantic 200 should reset failure streak, fail=%d", after.ConsecutiveFail)
	}
}

func TestReportResult_Structured200DoesNotRefreshLastRealOK(t *testing.T) {
	tr := health.NewTracker(nil)
	tr.Report(health.Report{RouteID: 7, Verdict: health.VerdictOK, Source: health.SourceReal})
	seeded := tr.Status(7).LastRealOKAt
	if seeded == 0 {
		t.Fatal("seed real OK should set lastRealOKAt")
	}

	rep := NewReporter(tr)
	rep.ReportResult(7, 0, &proxy.ResultView{
		Status:       200,
		ErrBody:      []byte(`{"type":"error","error":{"type":"server_error"}}`),
		BytesWritten: 48,
	})

	after := tr.Status(7)
	if after.LastRealOKAt != seeded {
		t.Fatalf("structured 200 must not refresh lastRealOKAt: before=%d after=%d",
			seeded, after.LastRealOKAt)
	}
	if after.ConsecutiveFail < 1 {
		t.Fatalf("structured 200 should count as failure, consecutive_fail=%d reason=%s",
			after.ConsecutiveFail, after.Reason)
	}
	if after.Reason == health.VerdictOK.String() {
		t.Fatal("last reason must not remain OK after structured 200 error")
	}
}

// §6.8：已有语义输出后的 SSE error 事件是 partial_failure —— 不得 piggyback。
func TestReportResult_MidStreamSSEErrorDoesNotPiggyback(t *testing.T) {
	tr := health.NewTracker(nil)
	tr.Report(health.Report{RouteID: 11, Verdict: health.VerdictOK, Source: health.SourceReal})
	seeded := tr.Status(11).LastRealOKAt

	h := http.Header{}
	h.Set("Content-Type", "text/event-stream")
	// streamBody 嗅探后只留下最小错误帧（不是整段流）。
	errFrame := "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"server_error\"}}\n\n"
	rep := NewReporter(tr)
	rep.ReportResult(11, 0, &proxy.ResultView{
		Status:       200,
		Header:       h,
		ErrBody:      []byte(errFrame),
		BytesWritten: 400,
	})

	after := tr.Status(11)
	if after.LastRealOKAt != seeded {
		t.Fatalf("mid-stream SSE error must not refresh lastRealOKAt")
	}
	if after.ConsecutiveFail < 1 {
		t.Fatalf("mid-stream SSE error should count as failure, fail=%d", after.ConsecutiveFail)
	}
}

type recordingSched struct {
	n int
}

func (r *recordingSched) ObserveRealSuccess(ScheduleKey, time.Time) { r.n++ }

func TestTrafficFinish_DoesNotPiggybackOnStatusAlone(t *testing.T) {
	sched := &recordingSched{}
	m := NewTrafficObserverManager(stubProbeSnap{}, nil, nil, discardLogger()).WithScheduler(sched)
	instr := m.PrepareAttempt(context.Background(), health.AttemptTarget{
		RouteID: 9, UpstreamID: 1, Endpoint: model.EndpointMessages,
	}, health.AttemptRequestView{})
	instr.Observer.TryHeaders(200, nil, time.Now())
	instr.Observer.Finish(health.AttemptFinish{})
	if sched.n != 0 {
		t.Fatalf("Finish must not ObserveRealSuccess on 2xx alone, got %d calls", sched.n)
	}
}
