package probe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/router"
)

func aliveL2Handler(w http.ResponseWriter, r *http.Request) {
	drainBody(r)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(aliveSSE))
}

func routeOn(t *testing.T, snap *router.Snapshot, upstreamID int64) *model.Route {
	t.Helper()
	for _, rts := range snap.RoutesByModelName {
		for _, rt := range rts {
			if rt.UpstreamID == upstreamID {
				return rt
			}
		}
	}
	t.Fatalf("no route on upstream %d", upstreamID)
	return nil
}

func reportsFor(track *recordingTracker, routeID int64) []health.Report {
	_, _, reports, _, _ := track.snapshot()
	var out []health.Report
	for _, rep := range reports {
		if rep.RouteID == routeID {
			out = append(out, rep)
		}
	}
	return out
}

// §8.6 表格：模板、URL、Secret、受保护头错误是 config_error，不改变 RouteHealth。
// 一个写错的 base_url 在 L2（定时与手动）都不得给 Route 报失败；同站另一条
// 连不上的 Route 仍按连接失败计入 RouteHealth。
func TestScheduler_L2URLConfigErrorLeavesRouteHealth(t *testing.T) {
	for _, withExecutor := range []bool{true, false} {
		name := "legacy prober"
		if withExecutor {
			name = "executor"
		}
		t.Run(name, func(t *testing.T) {
			hs := newSchedHarness(t, 2, aliveL2Handler)
			recorder := &captureRecorder{}
			if withExecutor {
				hs.sched.WithExecutor(NewExecutor(testTargets(), nil, nil,
					ManagerTransports{Manager: outbound.NewManager()},
					recorder, AlwaysOpenAdmission(), WallClock(), discardLogger()))
			}

			snap, _ := hs.cfg.Snapshot()
			mn := findModelName(snap, 1)

			badURL := snap.Upstreams[10]
			badURL.BaseURL = "not-a-url"
			badRoute := routeOn(t, snap, badURL.ID)

			refused := httptest.NewServer(http.NotFoundHandler())
			refusedURL := refused.URL
			refused.Close()
			down := snap.Upstreams[20]
			down.BaseURL = refusedURL
			downRoute := routeOn(t, snap, down.ID)

			hs.sched.runL2(context.Background(), badURL, mn, badRoute, fastSettings(), 1)
			if got := reportsFor(hs.track, badRoute.ID); len(got) != 0 {
				t.Fatalf("bad base_url L2 must not report RouteHealth, got %+v", got)
			}
			if withExecutor {
				if recorder.obs == nil || recorder.obs.Execution.ErrorClass != model.ErrorConfig ||
					recorder.obs.Execution.SentAtMS != 0 {
					t.Fatalf("bad base_url must still record an unsent config_error execution, got %+v", recorder.obs)
				}
			}

			_, l2, err := hs.sched.ProbeNow(context.Background(), snap, badRoute)
			if err != nil {
				t.Fatal(err)
			}
			if l2.Verdict != health.VerdictIgnore || !errors.Is(l2.Err, outbound.ErrURLConfig) {
				t.Fatalf("manual L2 with bad base_url: verdict=%s err=%v, want ignore + ErrURLConfig",
					l2.Verdict, l2.Err)
			}
			if got := reportsFor(hs.track, badRoute.ID); len(got) != 0 {
				t.Fatalf("manual bad base_url L2 must not report RouteHealth, got %+v", got)
			}

			hs.sched.runL2(context.Background(), down, mn, downRoute, fastSettings(), 1)
			got := reportsFor(hs.track, downRoute.ID)
			if len(got) != 1 || got[0].Verdict != health.VerdictUnavailable {
				t.Fatalf("connection refused L2 must report unavailable, got %+v", got)
			}
			if other := reportsFor(hs.track, badRoute.ID); len(other) != 0 {
				t.Fatalf("another route's failure leaked into the bad-URL route: %+v", other)
			}
		})
	}
}

// 缺失的 Secret、错误模板、空 key 等 prepare 阶段的失败同样不改变 RouteHealth。
func TestProbeConfigOutcome_PreSendErrorsAreIgnored(t *testing.T) {
	cases := map[string]error{
		"url config":      outbound.ErrURLConfig,
		"auth config":     outbound.ErrAuthConfig,
		"empty key":       outbound.ErrUpstreamAPIKeyEmpty,
		"secret read":     outbound.ErrSecretSourceRead,
		"legacy review":   outbound.ErrLegacyNeedsReview,
		"template value":  ErrTemplateValue,
		"no recipe":       ErrNoRecipe,
		"wrapped missing": errors.Join(errors.New("SECRET:site-token"), outbound.ErrURLConfig),
	}
	for name, cause := range cases {
		out := probeConfigOutcome(cause)
		if out.Verdict != health.VerdictIgnore {
			t.Errorf("%s: verdict=%s, want ignore", name, out.Verdict)
		}
		if !errors.Is(out.Err, cause) {
			t.Errorf("%s: Err must keep the cause, got %v", name, out.Err)
		}
	}
}
