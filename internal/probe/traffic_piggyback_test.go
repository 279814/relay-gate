package probe

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

type storePiggybackRecorder struct {
	store CostDailyStore
	t     *testing.T
}

func TestTrafficHTTP_DueSchedulerSkipsAndPersistsExactlyOneSaving(t *testing.T) {
	var requests atomic.Int64
	h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"message","content":[{"type":"text","text":"ok"}]}`))
	})
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
	cfg := h.manager.cfg.(ConfigSource)
	snap, err := cfg.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	settings, err := cfg.Settings()
	if err != nil {
		t.Fatal(err)
	}
	h.manager.WithPiggybackStore(h.store)
	scheduler := NewScheduler(cfg, newFakeTransport(), h.tracker, health.NewUpstreamGate(), discardLogger()).WithCapabilityRegistry(h.caps).WithPiggybackRecorder(h.manager)
	// L1 is an independent schedule; reserve it so this checks the actual
	// due-L2 path, rather than the private token predicate alone.
	h.tracker.ClaimL1(h.route.ID)
	h.tracker.TriggerL2(h.route.ID)
	name := findModelName(snap, h.route.ModelNameID)
	for i := 0; i < 2; i++ {
		scheduler.maybeProbe(ctx, h.up, name, h.route, settings)
	}
	scheduler.wg.Wait()
	if err := h.manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("due L2 sent despite current real evidence: requests=%d", requests.Load())
	}
	day := time.Now().UTC().Format("2006-01-02")
	page, err := h.store.ListProbeCostDaily(ctx, model.ProbeCostFilter{DayFrom: day, DayTo: day})
	if err != nil {
		t.Fatal(err)
	}
	var saved, charged int64
	for _, row := range page.Items {
		saved += row.PiggybackL2Saved
		charged += row.Requests
	}
	if saved != 1 || charged != 0 {
		t.Fatalf("due skip accounting: saved=%d charged=%d", saved, charged)
	}
}

func (r storePiggybackRecorder) RecordPiggybackSkip(id string, value model.ProbeCostDaily) bool {
	r.t.Helper()
	if err := r.store.RecordProbePiggybackSaving(context.Background(), id, value); err != nil {
		r.t.Fatal(err)
	}
	return true
}

func TestTrafficHTTP_RealSuccessMetadataRestoresWithoutPromotingHealth(t *testing.T) {
	body := `{"type":"message","content":[{"type":"text","text":"ok"}]}`
	h := newTrafficHTTPHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	h.request(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	cfg, recipes := restoreTestDeps(h.store)
	caps := NewCapabilityRegistry(cfg)
	restorer, ok := any(caps).(interface {
		RestoreRealSuccesses(context.Context, CapabilityRowSource, PublishedConfigSource, *RecipeResolver) (int, error)
	})
	if !ok {
		t.Fatal("real success has no startup restoration path")
	}
	n, err := restorer.RestoreRealSuccesses(ctx, h.store, cfg, recipes)
	if err != nil || n != 1 {
		t.Fatalf("restore real metadata count=%d err=%v", n, err)
	}
	row := caps.Snapshot(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages)
	if row == nil || row.LastRealOKAt == 0 || row.LastRealOKToken == "" {
		t.Fatal("real success metadata lost on restart")
	}
	if state := caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages, ""); state != model.CapabilityUnknown {
		t.Fatalf("restart promoted old positive health: %s", state)
	}
	tracker := health.NewTracker(cfg)
	generation := tracker.EnsureGeneration(h.route.ID)
	scheduler := NewScheduler(cfg, nil, tracker, nil, discardLogger()).WithCapabilityRegistry(caps).WithPiggybackRecorder(storePiggybackRecorder{h.store, t})
	if !scheduler.tryPiggyback(h.route.ID, generation, time.Now()) {
		t.Fatal("current persisted real success did not suppress due synthetic L2")
	}
	if !scheduler.tryPiggyback(h.route.ID, generation, time.Now()) {
		t.Fatal("same evidence unexpectedly became invalid")
	}
	day := time.Now().UTC().Format("2006-01-02")
	cost, err := h.store.ListProbeCostDaily(context.Background(), model.ProbeCostFilter{DayFrom: day, DayTo: day})
	if err != nil {
		t.Fatal(err)
	}
	saved := int64(0)
	for _, row := range cost.Items {
		saved += row.PiggybackL2Saved
		if row.Requests != 0 {
			t.Fatal("real traffic was charged as synthetic")
		}
	}
	if saved != 1 {
		t.Fatalf("piggyback skip not idempotent: saved=%d", saved)
	}
	settings, err := h.store.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	settings.RealTotalSec++
	if err := h.store.SaveSettings(settings); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Refresh(); err != nil {
		t.Fatal(err)
	}
	if scheduler.tryPiggyback(h.route.ID, generation, time.Now()) {
		t.Fatal("old real policy token suppressed a new configuration")
	}
}
