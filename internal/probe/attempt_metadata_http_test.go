package probe

import (
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

type attemptHTTPLogs struct {
	mu   sync.Mutex
	rows []*model.RequestLog
}

func (l *attemptHTTPLogs) Record(row *model.RequestLog) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rows = append(l.rows, row)
}

func TestTrafficHTTPAttemptCorrelationUsesCapturedRootAndCommittedFacts(t *testing.T) {
	h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"done"}],"stop_reason":"end_turn"}`)
	})
	logs := &attemptHTTPLogs{}
	h.handler.WithLogSink(logs)
	settings, revision, err := h.store.GetSettingsWithRevision()
	if err != nil {
		t.Fatal(err)
	}
	settings.RequestLogEnabled = true
	if _, err := h.store.SaveSettingsWithRevision(settings, revision); err != nil {
		t.Fatal(err)
	}
	if err := h.manager.cfg.(interface{ Refresh() error }).Refresh(); err != nil {
		t.Fatal(err)
	}
	// The proxy's request root remains valid even if the Observer's current
	// source no longer has it. Looking up that source would lose exact evidence.
	h.manager.cfg = stubProbeSnap{gen: 999}
	h.request(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	release, err := h.handler.Quiesce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := h.manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	exec := h.execution(t)
	logs.mu.Lock()
	defer logs.mu.Unlock()
	if len(logs.rows) != 1 {
		t.Fatalf("logs=%d", len(logs.rows))
	}
	row := logs.rows[0]
	if row.Metadata.ExecutionID != exec.ID {
		t.Fatalf("correlation guessed/generated independently: log=%s execution=%s", row.Metadata.ExecutionID, exec.ID)
	}
	if row.Metadata.ConfigGeneration == 0 || row.Metadata.EndpointRevision != exec.EndpointRevision || row.Metadata.AuthProfileRevision != exec.AuthProfileRevision || row.Metadata.RouteCapabilityRevision != exec.RouteCapabilityRevision {
		t.Fatalf("snapshot mismatch log=%+v execution=%+v", row.Metadata, exec)
	}
	if err := h.store.InsertRequestLog(row); err != nil {
		t.Fatal(err)
	}
	rows, err := h.store.ListRequestLogs(store.RequestLogFilter{ReqID: row.ReqID})
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	m := rows[0].Metadata
	if !m.ExecutionStored || m.CapabilityEffect != string(exec.CapabilityDisposition) || m.ErrorClass != exec.ErrorClass || m.FirstEventAtMS != exec.FirstEventAtMS || m.FirstSemanticAtMS != exec.FirstSemanticAtMS || m.RequestWriteState != "written" {
		t.Fatalf("facts not from actual commit: metadata=%+v execution=%+v", m, exec)
	}
}
