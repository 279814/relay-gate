package proxy

import (
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
)

func TestNoRouteRetryAfterUsesShortestMatchingCooldown(t *testing.T) {
	hs := newMultiHarness(t, respondOK(`{}`), respondOK(`{}`))
	tracker := health.NewTracker(hs.cfg)
	hs.h.health = tracker
	for routeID, seconds := range map[int64]int{100: 5, 200: 9, 300: 1} {
		tracker.Report(health.Report{RouteID: routeID, Verdict: health.VerdictRateLimited, RetryAfter: time.Duration(seconds) * time.Second})
	}
	// A shorter cooldown for an unrelated logical model must not leak into
	// this client's recovery advice.
	hs.cfg.snap.ModelNames = append(hs.cfg.snap.ModelNames, &model.ModelName{ID: 2, Name: "unrelated", Protocol: model.ProtoAnthropic, MatchMode: model.MatchExact, Enabled: true})
	hs.cfg.snap.RoutesByModelName[2] = []*model.Route{{ID: 300, ModelNameID: 2, UpstreamID: 10, Enabled: true}}
	response := hs.serve(hs.req())
	if response.Code != 503 || response.Header().Get("Retry-After") != "5" {
		t.Fatalf("no-route response=%d retry=%s", response.Code, response.Header().Get("Retry-After"))
	}
	hs.assertHits(t, 0, 0)
}
