package probe

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

type storePiggybackRecorder struct {
	store CostDailyStore
	t     *testing.T
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
