package api

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"sync"
	"testing"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/store"
)

// alwaysHealthy lets Select exercise routing without a real Tracker.
type alwaysHealthy struct{}

func (alwaysHealthy) State(int64) model.HealthState { return model.StateAlive }
func (alwaysHealthy) CoolingDown(int64) bool        { return false }
func (alwaysHealthy) TryAcquire(int64, int) (func(), uint64, bool) {
	return func() {}, 1, true
}

type recordingPublisher struct {
	mu               sync.Mutex
	invalidates      int
	refreshes        int
	inner            ConfigPublisher
	refreshErr       error
	skipInnerRefresh bool
}

func (p *recordingPublisher) Invalidate() {
	p.mu.Lock()
	p.invalidates++
	p.mu.Unlock()
	if p.inner != nil {
		p.inner.Invalidate()
	}
}

func (p *recordingPublisher) Refresh() error {
	p.mu.Lock()
	p.refreshes++
	errInject := p.refreshErr
	skip := p.skipInnerRefresh
	p.mu.Unlock()
	if errInject != nil {
		if !skip && p.inner != nil {
			_ = p.inner.Refresh()
		}
		return errInject
	}
	if p.inner != nil {
		return p.inner.Refresh()
	}
	return nil
}

func (p *recordingPublisher) counts() (inv, ref int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.invalidates, p.refreshes
}

func newLivecfgServer(t *testing.T) (*Server, http.Handler, *livecfg.Source, *recordingPublisher) {
	t.Helper()
	c, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "api.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	src := livecfg.New(st, log)
	pub := &recordingPublisher{inner: src}
	s := New(st, log).WithConfigPublisher(pub)
	return s, s.Routes(testAdminPW), src, pub
}

func mkModelNameViaAPI(t *testing.T, h http.Handler, name string) int64 {
	t.Helper()
	rec := do(t, h, "POST", "/admin/api/model-names",
		`{"name":"`+name+`","protocol":"anthropic"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("建 model_name 失败 %d：%s", rec.Code, rec.Body.String())
	}
	return int64(decodeBody[map[string]any](t, rec)["id"].(float64))
}

func mkRouteViaAPI(t *testing.T, h http.Handler, mnID, upID int64) int64 {
	t.Helper()
	rec := do(t, h, "POST", "/admin/api/routes",
		`{"model_name_id":`+itoa(mnID)+`,"upstream_id":`+itoa(upID)+`}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("建 route 失败 %d：%s", rec.Code, rec.Body.String())
	}
	return int64(decodeBody[map[string]any](t, rec)["id"].(float64))
}

func routeIDsInSnap(snap *router.Snapshot, mnID int64) map[int64]bool {
	out := map[int64]bool{}
	for _, rt := range snap.RoutesByModelName[mnID] {
		if rt != nil {
			out[rt.ID] = true
		}
	}
	return out
}

func selectRouteID(t *testing.T, snap *router.Snapshot, modelName string) int64 {
	t.Helper()
	cand, err := router.Select(snap, alwaysHealthy{}, modelName, model.ProtoAnthropic)
	if err != nil {
		t.Fatalf("Select(%q): %v", modelName, err)
	}
	defer cand.Release()
	return cand.Route.ID
}

func assertPublished(t *testing.T, pub *recordingPublisher, beforeInv, beforeRef int) {
	t.Helper()
	afterInv, afterRef := pub.counts()
	if afterInv != beforeInv+1 || afterRef != beforeRef+1 {
		t.Fatalf("delete must Invalidate+Refresh once: inv=%d ref=%d", afterInv-beforeInv, afterRef-beforeRef)
	}
}

// After a successful delete, the next select/preamble snapshot must omit the
// deleted row without waiting out livecfg's TTL. Sibling routes stay selectable;
// cascaded children of a deleted parent must also be gone.
func TestDelete_PublishesSnapshotBeforeHandlerReturns(t *testing.T) {
	_, h, src, pub := newLivecfgServer(t)

	mnKeep := mkModelNameViaAPI(t, h, "keep-model")
	mnDrop := mkModelNameViaAPI(t, h, "drop-model")
	mnCasc := mkModelNameViaAPI(t, h, "casc-model")
	upKeep := mkUpstreamViaAPI(t, h,
		`{"name":"keep-up","base_url":"https://keep.example.com","api_key":"sk-aaaaaaaaaaaa"}`)
	upDrop := mkUpstreamViaAPI(t, h,
		`{"name":"drop-up","base_url":"https://drop.example.com","api_key":"sk-bbbbbbbbbbbb"}`)

	rtKeep := mkRouteViaAPI(t, h, mnKeep, upKeep)
	rtSibling := mkRouteViaAPI(t, h, mnKeep, upDrop)
	rtCascaded := mkRouteViaAPI(t, h, mnCasc, upDrop)  // dies with upDrop
	rtDropModel := mkRouteViaAPI(t, h, mnDrop, upKeep) // dies with mnDrop

	warm, err := src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	warmed := routeIDsInSnap(warm, mnKeep)
	if !warmed[rtKeep] || !warmed[rtSibling] {
		t.Fatalf("warm snapshot missing keep-model routes: %+v", warmed)
	}
	if warm.Upstreams[upDrop] == nil || len(warm.RoutesByModelName[mnCasc]) == 0 {
		t.Fatal("warm snapshot should contain drop-up and cascaded route")
	}

	// ── delete one route: sibling must remain selectable within TTL ──
	beforeInv, beforeRef := pub.counts()
	rec := do(t, h, "DELETE", "/admin/api/routes/"+itoa(rtSibling), "", true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete route %d：%s", rec.Code, rec.Body.String())
	}
	assertPublished(t, pub, beforeInv, beforeRef)

	snap, err := src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	got := routeIDsInSnap(snap, mnKeep)
	if got[rtSibling] {
		t.Fatalf("deleted route %d still in snapshot within TTL", rtSibling)
	}
	if !got[rtKeep] {
		t.Fatal("sibling route must remain selectable after peer delete")
	}
	if id := selectRouteID(t, snap, "keep-model"); id != rtKeep {
		t.Fatalf("Select keep-model got route %d want %d", id, rtKeep)
	}

	// ── delete upstream: cascaded child routes must vanish; unrelated stay ──
	beforeInv, beforeRef = pub.counts()
	rec = do(t, h, "DELETE", "/admin/api/upstreams/"+itoa(upDrop), "", true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete upstream %d：%s", rec.Code, rec.Body.String())
	}
	assertPublished(t, pub, beforeInv, beforeRef)

	snap, err = src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap.Upstreams[upDrop] != nil {
		t.Fatalf("deleted upstream %d still in snapshot", upDrop)
	}
	if snap.Upstreams[upKeep] == nil {
		t.Fatal("sibling upstream must remain")
	}
	if routeIDsInSnap(snap, mnCasc)[rtCascaded] {
		t.Fatal("cascaded child route of deleted upstream must be gone")
	}
	if !routeIDsInSnap(snap, mnKeep)[rtKeep] {
		t.Fatal("route on kept upstream must remain")
	}

	// ── delete model_name: its routes cascade out; other models stay ──
	beforeInv, beforeRef = pub.counts()
	rec = do(t, h, "DELETE", "/admin/api/model-names/"+itoa(mnDrop), "", true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete model_name %d：%s", rec.Code, rec.Body.String())
	}
	assertPublished(t, pub, beforeInv, beforeRef)

	snap, err = src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, mn := range snap.ModelNames {
		if mn != nil && mn.ID == mnDrop {
			t.Fatalf("deleted model_name %d still in snapshot", mnDrop)
		}
	}
	if routeIDsInSnap(snap, mnDrop)[rtDropModel] || len(snap.RoutesByModelName[mnDrop]) != 0 {
		t.Fatalf("cascaded routes of deleted model_name still present: %+v", snap.RoutesByModelName[mnDrop])
	}
	if !routeIDsInSnap(snap, mnKeep)[rtKeep] {
		t.Fatal("unrelated model route must remain selectable")
	}
	if id := selectRouteID(t, snap, "keep-model"); id != rtKeep {
		t.Fatalf("Select keep-model after model delete got %d want %d", id, rtKeep)
	}
}

func TestDelete_FailedStoreDoesNotPublish(t *testing.T) {
	s, h, _, pub := newLivecfgServer(t)

	upID := mkUpstreamViaAPI(t, h,
		`{"name":"fail-del-u","base_url":"https://fail.example.com","api_key":"sk-aaaaaaaaaaaa"}`)
	mnID := mkModelNameViaAPI(t, h, "fail-del-m")
	rtID := mkRouteViaAPI(t, h, mnID, upID)

	forceTableDeleteFail(t, s, "route")
	rec := do(t, h, "DELETE", "/admin/api/routes/"+itoa(rtID), "", true)
	if rec.Code == http.StatusNoContent {
		t.Fatal("expected delete failure, got 204")
	}
	inv, ref := pub.counts()
	if inv != 0 || ref != 0 {
		t.Fatalf("failed delete must not publish: inv=%d ref=%d", inv, ref)
	}
}

// Refresh failure after a successful SQL delete must not return 204 while the
// pre-delete routing pointer is still live. Re-Invalidate keeps the TTL open
// so the next Snapshot() reloads from Store and omits the removed row.
func TestDelete_RefreshFailureDoesNotReturnSuccessWithStaleSnapshot(t *testing.T) {
	c, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "api.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	src := livecfg.New(st, log)
	pub := &recordingPublisher{
		inner:            src,
		refreshErr:       errRefreshBoom,
		skipInnerRefresh: true,
	}
	s := New(st, log).WithConfigPublisher(pub)
	h := s.Routes(testAdminPW)

	mnID := mkModelNameViaAPI(t, h, "refresh-fail-m")
	upKeep := mkUpstreamViaAPI(t, h,
		`{"name":"rf-keep-u","base_url":"https://rf-keep.example.com","api_key":"sk-aaaaaaaaaaaa"}`)
	upDrop := mkUpstreamViaAPI(t, h,
		`{"name":"rf-drop-u","base_url":"https://rf-drop.example.com","api_key":"sk-bbbbbbbbbbbb"}`)
	rtKeep := mkRouteViaAPI(t, h, mnID, upKeep)
	rtDrop := mkRouteViaAPI(t, h, mnID, upDrop)

	warm, err := src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !routeIDsInSnap(warm, mnID)[rtDrop] {
		t.Fatal("warm snapshot must contain route to delete")
	}

	beforeInv, beforeRef := pub.counts()
	rec := do(t, h, "DELETE", "/admin/api/routes/"+itoa(rtDrop), "", true)
	if rec.Code == http.StatusNoContent {
		t.Fatal("Refresh failure must not return 204 while routing may be stale")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 on Refresh failure, got %d: %s", rec.Code, rec.Body.String())
	}
	afterInv, afterRef := pub.counts()
	// Invalidate + failed Refresh + re-Invalidate to keep TTL forced open.
	if afterInv != beforeInv+2 || afterRef != beforeRef+1 {
		t.Fatalf("want Invalidate x2 and Refresh x1: inv=%d ref=%d", afterInv-beforeInv, afterRef-beforeRef)
	}

	snap, err := src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	got := routeIDsInSnap(snap, mnID)
	if got[rtDrop] {
		t.Fatalf("deleted route %d still selectable after Refresh failure", rtDrop)
	}
	if !got[rtKeep] {
		t.Fatal("sibling route must remain selectable")
	}
	if id := selectRouteID(t, snap, "refresh-fail-m"); id != rtKeep {
		t.Fatalf("Select got route %d want %d", id, rtKeep)
	}
}

var errRefreshBoom = errors.New("refresh boom")
