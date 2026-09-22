package outbound

import (
	"context"
	"testing"
	"time"
)

func TestAttemptTrace_SnapshotAndTLS(t *testing.T) {
	tr := &AttemptTrace{}
	ctx := WithAttemptTrace(context.Background(), tr)
	if TraceFromContext(ctx) != tr {
		t.Fatal("WithAttemptTrace 应可取回同一指针")
	}
	base := time.Unix(100, 0).UTC()
	tr.MarkSent(base)
	tr.MarkGotConn(base.Add(10*time.Millisecond), false)
	tr.MarkTLSStart(base.Add(2 * time.Millisecond))
	tr.MarkTLSDone(base.Add(8 * time.Millisecond))
	tr.MarkResponseHeader(base.Add(20 * time.Millisecond))
	tr.MarkDone(base.Add(30 * time.Millisecond))
	snap := tr.Snapshot()
	if snap.LastConnectMS() != 10 {
		t.Fatalf("LastConnectMS=%d want 10", snap.LastConnectMS())
	}
	if snap.LastTLSMS() != 6 {
		t.Fatalf("LastTLSMS=%d want 6", snap.LastTLSMS())
	}
	tr.MarkGotConn(base.Add(50*time.Millisecond), true) // ignored after first
	if tr.Snapshot().Reused {
		t.Fatal("首次 GotConn 后不得被覆盖为 reused")
	}
}
