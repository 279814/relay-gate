package probe

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/store"
)

type settingsSnap struct{}

func (settingsSnap) Snapshot() (*router.Snapshot, error) { return &router.Snapshot{}, nil }
func (settingsSnap) Settings() (model.Settings, error)   { return model.DefaultSettings(), nil }

func newManualProbeService(t *testing.T, st *store.Store,
	respond func(*http.Request) (*http.Response, error)) (*Service, *countingRoundTripper) {

	t.Helper()
	rt := &countingRoundTripper{fn: respond}
	targets := outbound.NewProvider(
		storeEndpointSource{store: st}, nil, outbound.NewResolver(testHasher{}))
	recipes := NewRecipeResolver(st).WithNotFound(func(err error) bool {
		return errors.Is(err, store.ErrNotFound)
	})
	executor := NewExecutor(targets, st, recipes, fakeTransports{rt: rt},
		NewExecutionOnlyRecorder(st), AlwaysOpenAdmission(), WallClock(), nil)
	svc := NewService(st, executor, nil, settingsSnap{}, nil, nil)
	return svc, rt
}

func TestRunManual_RejectsDisabledUpstream(t *testing.T) {
	st := calibrationTestStore(t)
	up, _, rt := seedCalibrationRoute(t, st)
	up.Enabled = false
	if err := st.UpdateUpstream(up); err != nil {
		t.Fatal(err)
	}
	svc, counter := newManualProbeService(t, st, func(*http.Request) (*http.Response, error) {
		t.Fatal("停用 Upstream 的手动探活不得 RoundTrip")
		return nil, nil
	})

	_, err := svc.RunManual(context.Background(), rt.ID)
	if err == nil {
		t.Fatal("停用 Upstream 的 RunManual 必须拒绝")
	}
	if !errors.Is(err, model.ErrValidation) || !strings.Contains(err.Error(), "Upstream") {
		t.Fatalf("应为配置校验错误且点名 Upstream: %v", err)
	}
	if counter.count() != 0 {
		t.Fatalf("拒绝后不得出网，RoundTrip=%d", counter.count())
	}
}

func TestRunManual_RejectsDisabledRoute(t *testing.T) {
	st := calibrationTestStore(t)
	up, _, rt := seedCalibrationRoute(t, st)
	rt.Enabled = false
	if err := st.UpdateRoute(rt); err != nil {
		t.Fatal(err)
	}
	svc, counter := newManualProbeService(t, st, func(*http.Request) (*http.Response, error) {
		t.Fatal("停用 Route 的手动探活不得 RoundTrip")
		return nil, nil
	})
	_ = up

	_, err := svc.RunManual(context.Background(), rt.ID)
	if err == nil {
		t.Fatal("停用 Route 的 RunManual 必须拒绝")
	}
	if !errors.Is(err, model.ErrValidation) || !strings.Contains(err.Error(), "Route") {
		t.Fatalf("应为配置校验错误且点名 Route: %v", err)
	}
	if counter.count() != 0 {
		t.Fatalf("拒绝后不得出网，RoundTrip=%d", counter.count())
	}
}
