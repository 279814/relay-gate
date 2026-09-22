package outbound

import (
	"context"
	"sync"
	"time"
)

// attemptTraceKey 是 request context 上挂 AttemptTrace 的私有键。
type attemptTraceKey struct{}

// AttemptTrace 记录一次真实 Attempt 的连接阶段时刻（§4.4 / P0-13）。
//
// proxy 只负责 WithAttemptTrace；Observer 在 Finish 后 Snapshot。
// 所有写入经锁保护；零值表示该阶段未观测到。
type AttemptTrace struct {
	mu sync.Mutex

	SentAt           time.Time
	TLSStartAt       time.Time
	TLSDoneAt        time.Time
	GotConnAt        time.Time
	ResponseHeaderAt time.Time
	DoneAt           time.Time
	Reused           bool
}

// WithAttemptTrace 把 trace 挂到 ctx，供 dialer/transport 钩子写入。
func WithAttemptTrace(ctx context.Context, trace *AttemptTrace) context.Context {
	if trace == nil {
		return ctx
	}
	return context.WithValue(ctx, attemptTraceKey{}, trace)
}

// TraceFromContext 取出挂载的 AttemptTrace；未挂载返回 nil。
func TraceFromContext(ctx context.Context) *AttemptTrace {
	if ctx == nil {
		return nil
	}
	trace, _ := ctx.Value(attemptTraceKey{}).(*AttemptTrace)
	return trace
}

func (t *AttemptTrace) mark(fn func(*AttemptTrace)) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	fn(t)
}

// MarkSent 记录写 socket 时刻。
func (t *AttemptTrace) MarkSent(at time.Time) {
	t.mark(func(x *AttemptTrace) {
		if x.SentAt.IsZero() {
			x.SentAt = at
		}
	})
}

// MarkGotConn 记录拿到连接。
func (t *AttemptTrace) MarkGotConn(at time.Time, reused bool) {
	t.mark(func(x *AttemptTrace) {
		if x.GotConnAt.IsZero() {
			x.GotConnAt = at
			x.Reused = reused
		}
	})
}

// MarkTLSStart / MarkTLSDone 记录 TLS 握手窗口。
func (t *AttemptTrace) MarkTLSStart(at time.Time) {
	t.mark(func(x *AttemptTrace) {
		if x.TLSStartAt.IsZero() {
			x.TLSStartAt = at
		}
	})
}

func (t *AttemptTrace) MarkTLSDone(at time.Time) {
	t.mark(func(x *AttemptTrace) {
		if x.TLSDoneAt.IsZero() {
			x.TLSDoneAt = at
		}
	})
}

// MarkResponseHeader 记录收到响应头。
func (t *AttemptTrace) MarkResponseHeader(at time.Time) {
	t.mark(func(x *AttemptTrace) {
		if x.ResponseHeaderAt.IsZero() {
			x.ResponseHeaderAt = at
		}
	})
}

// MarkDone 记录 Attempt 结束。
func (t *AttemptTrace) MarkDone(at time.Time) {
	t.mark(func(x *AttemptTrace) {
		x.DoneAt = at
	})
}

// Snapshot 返回深拷贝（Finish 后读）。
func (t *AttemptTrace) Snapshot() AttemptTraceSnapshot {
	if t == nil {
		return AttemptTraceSnapshot{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return AttemptTraceSnapshot{
		SentAt:           t.SentAt,
		TLSStartAt:       t.TLSStartAt,
		TLSDoneAt:        t.TLSDoneAt,
		GotConnAt:        t.GotConnAt,
		ResponseHeaderAt: t.ResponseHeaderAt,
		DoneAt:           t.DoneAt,
		Reused:           t.Reused,
	}
}

// AttemptTraceSnapshot 是无锁的只读副本。
type AttemptTraceSnapshot struct {
	SentAt           time.Time
	TLSStartAt       time.Time
	TLSDoneAt        time.Time
	GotConnAt        time.Time
	ResponseHeaderAt time.Time
	DoneAt           time.Time
	Reused           bool
}

// LastConnectMS / LastTLSMS 按 §4.4 规则重建；非法次序归零。
func (s AttemptTraceSnapshot) LastConnectMS() int64 {
	if s.SentAt.IsZero() || s.GotConnAt.IsZero() || s.GotConnAt.Before(s.SentAt) {
		return 0
	}
	return s.GotConnAt.Sub(s.SentAt).Milliseconds()
}

func (s AttemptTraceSnapshot) LastTLSMS() int64 {
	if s.Reused {
		return 0
	}
	if s.TLSStartAt.IsZero() || s.TLSDoneAt.IsZero() || s.TLSDoneAt.Before(s.TLSStartAt) {
		return 0
	}
	return s.TLSDoneAt.Sub(s.TLSStartAt).Milliseconds()
}
