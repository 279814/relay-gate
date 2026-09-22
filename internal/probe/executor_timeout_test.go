package probe

import (
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
)

// gatedBody 是一个受控响应体：第一次 Read 时发出信号，然后阻塞到被 Close，
// 用来模拟「响应头已回、流内迟迟不出内容」。Close 幂等。
type gatedBody struct {
	entered   chan struct{}
	release   chan struct{}
	enterOnce sync.Once
	closeOnce sync.Once
}

func newGatedBody() *gatedBody {
	return &gatedBody{entered: make(chan struct{}), release: make(chan struct{})}
}

func (b *gatedBody) Read(_ []byte) (int, error) {
	b.enterOnce.Do(func() { close(b.entered) })
	<-b.release
	return 0, io.EOF
}

func (b *gatedBody) Close() error {
	b.closeOnce.Do(func() { close(b.release) })
	return nil
}

type executeResult struct {
	result ExecutionResult
	err    error
}

// 响应头超时：RoundTrip 迟迟不返回，拨过 ResponseHead 截止即取消。
// 用 ManualClock 拨快，不睡真实时间（§P0-09 第 7 条）。
func TestExecutorTimeout_ResponseHeader(t *testing.T) {
	entered := make(chan struct{})
	rt := &countingRoundTripper{fn: func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-r.Context().Done() // 一直等到被 cancel
		return nil, r.Context().Err()
	}}
	clock := NewManualClock(time.Now())
	up := upstreamFor("https://example.test")
	exec := newTestExecutorFor(up, rt, &captureRecorder{}, AlwaysOpenAdmission(), clock)

	req := l2RequestFor(up)
	// 显式预算：ResponseHead 1s、Total 30s，拨 2s 只触发响应头超时而非 total。
	req.Budget = outbound.Budget{ResponseHead: time.Second, Total: 30 * time.Second}

	done := make(chan executeResult, 1)
	go func() {
		result, err := exec.Execute(context.Background(), req)
		done <- executeResult{result, err}
	}()

	<-entered
	clock.Advance(2 * time.Second)

	got := <-done
	if got.err != nil {
		t.Fatalf("超时是站点结果，不该是 Go error: %v", got.err)
	}
	if rt.count() != 1 {
		t.Fatalf("必须恰好一次 RoundTrip，实际 %d", rt.count())
	}
	if got.result.Outcome.Verdict != health.VerdictUnavailable {
		t.Errorf("响应头超时应为 unavailable，实际 %s", got.result.Outcome.Verdict)
	}
	if got.result.Decision.Reachable {
		t.Error("连响应头都没拿到应判 unreachable")
	}
	if got.result.Decision.StatusCode != 0 {
		t.Errorf("status 应为 0，实际 %d", got.result.Decision.StatusCode)
	}
}

// 首语义超时：响应头已回但流内不出语义证据，拨过 FirstSemantic 截止即取消。
func TestExecutorTimeout_FirstSemantic(t *testing.T) {
	body := newGatedBody()
	rt := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		header := http.Header{}
		header.Set("Content-Type", "text/event-stream")
		return &http.Response{StatusCode: 200, Header: header, Body: body}, nil
	}}
	clock := NewManualClock(time.Now())
	up := upstreamFor("https://example.test")
	exec := newTestExecutorFor(up, rt, &captureRecorder{}, AlwaysOpenAdmission(), clock)

	req := l2RequestFor(up)
	// ResponseHead 大到不触发；FirstSemantic 1s；Total 30s。拨 2s 只触发首语义超时。
	req.Budget = outbound.Budget{ResponseHead: 30 * time.Second, FirstSemantic: time.Second, Total: 30 * time.Second}

	done := make(chan executeResult, 1)
	go func() {
		result, err := exec.Execute(context.Background(), req)
		done <- executeResult{result, err}
	}()

	<-body.entered // 读流已开始，阶段定时器已建立
	clock.Advance(2 * time.Second)

	got := <-done
	if got.err != nil {
		t.Fatalf("超时是站点结果，不该是 Go error: %v", got.err)
	}
	if got.result.Decision.Success {
		t.Error("首语义超时不该判成功")
	}
	if got.result.Decision.SemanticSeen {
		t.Error("没有语义证据，SemanticSeen 应为 false")
	}
	if got.result.Outcome.Verdict != health.VerdictUnavailable {
		t.Errorf("首语义超时应为 unavailable，实际 %s", got.result.Outcome.Verdict)
	}
	if got.result.Decision.StatusCode != 200 {
		t.Errorf("响应头已回，status 应为 200，实际 %d", got.result.Decision.StatusCode)
	}
}

// 外层总预算是硬上限：拨过 Total（且不出语义）必然收尾（§7.4：阶段不得越过 total）。
func TestExecutorTimeout_TotalIsHardCap(t *testing.T) {
	body := newGatedBody()
	rt := &countingRoundTripper{fn: func(*http.Request) (*http.Response, error) {
		header := http.Header{}
		header.Set("Content-Type", "application/json")
		return &http.Response{StatusCode: 200, Header: header, Body: body}, nil
	}}
	clock := NewManualClock(time.Now())
	up := upstreamFor("https://example.test")
	req := l2RequestFor(up)
	// 关掉响应头与首语义阶段，只留 total，验证 total 单独兜底。
	req.Budget = outbound.Budget{Total: 2 * time.Second}
	exec := newTestExecutorFor(up, rt, &captureRecorder{}, AlwaysOpenAdmission(), clock)

	done := make(chan executeResult, 1)
	go func() {
		result, err := exec.Execute(context.Background(), req)
		done <- executeResult{result, err}
	}()

	<-body.entered
	clock.Advance(3 * time.Second) // > Total(2s)

	got := <-done
	if got.err != nil {
		t.Fatalf("超时是站点结果，不该是 Go error: %v", got.err)
	}
	if got.result.Outcome.Verdict != health.VerdictUnavailable {
		t.Errorf("越过 total 应为 unavailable，实际 %s", got.result.Outcome.Verdict)
	}
	if got.result.Decision.ErrorClass == model.ErrorNone {
		t.Error("越过 total 不该判成功")
	}
}
