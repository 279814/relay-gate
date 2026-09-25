package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/store"
)

func routeEnabledInSnap(snap *router.Snapshot, mnID, rtID int64) (found, enabled bool) {
	for _, rt := range snap.RoutesByModelName[mnID] {
		if rt != nil && rt.ID == rtID {
			return true, rt.Enabled
		}
	}
	return false, false
}

func forceTableUpdateFail(t *testing.T, s *Server, table string) {
	t.Helper()
	_, err := s.st.DB().Exec(`CREATE TEMP TRIGGER block_upd_` + table + ` BEFORE UPDATE ON ` + table + `
		BEGIN SELECT RAISE(ABORT, 'forced update failure'); END`)
	if err != nil {
		t.Fatal(err)
	}
}

// After a successful create/update that changes selection (enabled / route),
// the next select/preamble snapshot must see the new values without waiting
// out livecfg's TTL (docs/01 §6.4).
func TestWrite_PublishesEnabledAndRouteBeforeHandlerReturns(t *testing.T) {
	_, h, src, pub := newLivecfgServer(t)

	mnID := mkModelNameViaAPI(t, h, "write-pub-m")
	upKeep := mkUpstreamViaAPI(t, h,
		`{"name":"write-keep-u","base_url":"https://write-keep.example.com","api_key":"sk-aaaaaaaaaaaa"}`)
	upAlt := mkUpstreamViaAPI(t, h,
		`{"name":"write-alt-u","base_url":"https://write-alt.example.com","api_key":"sk-bbbbbbbbbbbb"}`)
	rtKeep := mkRouteViaAPI(t, h, mnID, upKeep)
	rtFlip := mkRouteViaAPI(t, h, mnID, upAlt)

	warm, err := src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if found, en := routeEnabledInSnap(warm, mnID, rtFlip); !found || !en {
		t.Fatal("warm snapshot must contain enabled rtFlip")
	}

	// ── disable route: Select must stop choosing it within TTL ──
	beforeInv, beforeRef := pub.counts()
	rec := do(t, h, "PUT", "/admin/api/routes/"+itoa(rtFlip), `{"enabled":false}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable route: %d %s", rec.Code, rec.Body.String())
	}
	assertPublished(t, pub, beforeInv, beforeRef)

	snap, err := src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if found, en := routeEnabledInSnap(snap, mnID, rtFlip); !found {
		t.Fatal("disabled route must remain in snapshot (not deleted)")
	} else if en {
		t.Fatal("disabled route still Enabled=true in snapshot within TTL")
	}
	if id := selectRouteID(t, snap, "write-pub-m"); id != rtKeep {
		t.Fatalf("Select after disable got route %d want %d", id, rtKeep)
	}

	// ── re-enable + create a higher-priority route on a new upstream ──
	beforeInv, beforeRef = pub.counts()
	rec = do(t, h, "PUT", "/admin/api/routes/"+itoa(rtFlip), `{"enabled":true}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-enable route: %d %s", rec.Code, rec.Body.String())
	}
	assertPublished(t, pub, beforeInv, beforeRef)

	upNew := mkUpstreamViaAPI(t, h,
		`{"name":"write-new-u","base_url":"https://write-new.example.com","api_key":"sk-cccccccccccc"}`)
	beforeInv, beforeRef = pub.counts()
	rec = do(t, h, "POST", "/admin/api/routes",
		`{"model_name_id":`+itoa(mnID)+`,"upstream_id":`+itoa(upNew)+
			`,"priority":1,"weight":100,"enabled":true}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create priority-1 route: %d %s", rec.Code, rec.Body.String())
	}
	assertPublished(t, pub, beforeInv, beforeRef)
	rtNew := int64(decodeBody[map[string]any](t, rec)["id"].(float64))

	// Demote older routes so Select is deterministic without waiting on TTL.
	beforeInv, beforeRef = pub.counts()
	rec = do(t, h, "PUT", "/admin/api/routes/"+itoa(rtKeep), `{"priority":9}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("demote rtKeep: %d %s", rec.Code, rec.Body.String())
	}
	assertPublished(t, pub, beforeInv, beforeRef)
	beforeInv, beforeRef = pub.counts()
	rec = do(t, h, "PUT", "/admin/api/routes/"+itoa(rtFlip), `{"priority":9}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("demote rtFlip: %d %s", rec.Code, rec.Body.String())
	}
	assertPublished(t, pub, beforeInv, beforeRef)

	snap, err = src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if found, en := routeEnabledInSnap(snap, mnID, rtNew); !found || !en {
		t.Fatalf("created route %d must be enabled in snapshot within TTL", rtNew)
	}
	if id := selectRouteID(t, snap, "write-pub-m"); id != rtNew {
		t.Fatalf("Select after create got route %d want new %d", id, rtNew)
	}

	// ── disable upstream: its routes must drop out of Select immediately ──
	beforeInv, beforeRef = pub.counts()
	rec = do(t, h, "PUT", "/admin/api/upstreams/"+itoa(upAlt), `{"enabled":false}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable upstream: %d %s", rec.Code, rec.Body.String())
	}
	assertPublished(t, pub, beforeInv, beforeRef)

	snap, err = src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if up := snap.Upstreams[upAlt]; up == nil || up.Enabled {
		t.Fatalf("upstream %d must be Enabled=false in snapshot: %+v", upAlt, up)
	}
	if id := selectRouteID(t, snap, "write-pub-m"); id == rtFlip {
		t.Fatal("Select must not pick route on disabled upstream")
	}

	// ── disable model_name: Select must fail closed for that name ──
	beforeInv, beforeRef = pub.counts()
	rec = do(t, h, "PUT", "/admin/api/model-names/"+itoa(mnID), `{"enabled":false}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable model_name: %d %s", rec.Code, rec.Body.String())
	}
	assertPublished(t, pub, beforeInv, beforeRef)

	snap, err = src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var mnEnabled bool
	var mnFound bool
	for _, mn := range snap.ModelNames {
		if mn != nil && mn.ID == mnID {
			mnFound = true
			mnEnabled = mn.Enabled
			break
		}
	}
	if !mnFound {
		t.Fatal("disabled model_name must remain in snapshot")
	}
	if mnEnabled {
		t.Fatal("model_name still Enabled=true in snapshot within TTL")
	}
	if _, err := router.Select(snap, alwaysHealthy{}, "write-pub-m", model.ProtoAnthropic); err == nil {
		t.Fatal("expected Select to fail for disabled model_name")
	}
}

func TestWrite_RefreshFailureDoesNotReturnSuccessWithStaleSnapshot(t *testing.T) {
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
	h := s.Routes(testAdminPW)

	mnID := mkModelNameViaAPI(t, h, "write-rf-m")
	upKeep := mkUpstreamViaAPI(t, h,
		`{"name":"write-rf-keep","base_url":"https://write-rf-keep.example.com","api_key":"sk-aaaaaaaaaaaa"}`)
	upFlip := mkUpstreamViaAPI(t, h,
		`{"name":"write-rf-flip","base_url":"https://write-rf-flip.example.com","api_key":"sk-bbbbbbbbbbbb"}`)
	rtKeep := mkRouteViaAPI(t, h, mnID, upKeep)
	rtFlip := mkRouteViaAPI(t, h, mnID, upFlip)

	warm, err := src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if found, en := routeEnabledInSnap(warm, mnID, rtFlip); !found || !en {
		t.Fatal("warm snapshot must contain enabled rtFlip")
	}

	pub.mu.Lock()
	pub.refreshErr = errRefreshBoom
	pub.skipInnerRefresh = true
	pub.mu.Unlock()

	beforeInv, beforeRef := pub.counts()
	rec := do(t, h, "PUT", "/admin/api/routes/"+itoa(rtFlip), `{"enabled":false}`, true)
	if rec.Code == http.StatusOK {
		t.Fatal("Refresh failure must not return 200 while routing may be stale")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 on Refresh failure, got %d: %s", rec.Code, rec.Body.String())
	}
	afterInv, afterRef := pub.counts()
	if afterInv != beforeInv+2 || afterRef != beforeRef+1 {
		t.Fatalf("want Invalidate x2 and Refresh x1: inv=%d ref=%d", afterInv-beforeInv, afterRef-beforeRef)
	}

	// Re-Invalidate forces get() to reload: disabled flag from SQL must appear.
	snap, err := src.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if found, en := routeEnabledInSnap(snap, mnID, rtFlip); !found {
		t.Fatal("route must still exist after failed Refresh")
	} else if en {
		t.Fatal("SQL-disabled route still Enabled=true after Refresh failure + re-Invalidate")
	}
	if !routeIDsInSnap(snap, mnID)[rtKeep] {
		t.Fatal("sibling route must remain")
	}
}

func TestWrite_FailedStoreDoesNotPublish(t *testing.T) {
	s, h, _, pub := newLivecfgServer(t)

	upID := mkUpstreamViaAPI(t, h,
		`{"name":"fail-upd-u","base_url":"https://fail-upd.example.com","api_key":"sk-aaaaaaaaaaaa"}`)
	mnID := mkModelNameViaAPI(t, h, "fail-upd-m")
	rtID := mkRouteViaAPI(t, h, mnID, upID)

	beforeInv, beforeRef := pub.counts()
	forceTableUpdateFail(t, s, "route")
	rec := do(t, h, "PUT", "/admin/api/routes/"+itoa(rtID), `{"enabled":false}`, true)
	if rec.Code == http.StatusOK {
		t.Fatal("expected update failure, got 200")
	}
	afterInv, afterRef := pub.counts()
	if afterInv != beforeInv || afterRef != beforeRef {
		t.Fatalf("failed update must not publish: inv=%d→%d ref=%d→%d",
			beforeInv, afterInv, beforeRef, afterRef)
	}
}

// Endpoint url_override lives in the same livecfg Probe snapshot outbound uses.
// A successful update must Invalidate+Refresh so the next Endpoint() read sees
// the new URL within TTL; siblings stay put.
func TestWrite_EndpointURLOverrideVisibleBeforeHandlerReturns(t *testing.T) {
	s, _, src, pub := newLivecfgServer(t)
	h := s.WithProbeAdmin(probe.NewService(s.st, nil, nil, nil, nil, nil)).Routes(testAdminPW)

	upID := mkUpstreamViaAPI(t, h,
		`{"name":"ep-pub-u","base_url":"https://ep-pub.example.com","api_key":"sk-aaaaaaaaaaaa"}`)

	warm, err := src.Endpoint(context.Background(), upID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	siblingWarm, err := src.Endpoint(context.Background(), upID, model.EndpointModels)
	if err != nil {
		t.Fatal(err)
	}
	if warm.URLOverride != "" {
		t.Fatalf("warm messages override should be empty, got %q", warm.URLOverride)
	}

	override := "https://ep-pub.example.com/v1/custom-messages"
	beforeInv, beforeRef := pub.counts()
	rec := do(t, h, "PUT", "/admin/api/upstream-endpoints/"+itoa(warm.ID),
		`{"url_override":`+mustJSON(t, override)+`,"expected_revision":`+itoa(warm.Revision)+`}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("update endpoint: %d %s", rec.Code, rec.Body.String())
	}
	assertPublished(t, pub, beforeInv, beforeRef)

	got, err := src.Endpoint(context.Background(), upID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	if got.URLOverride != override {
		t.Fatalf("messages url_override still %q within TTL, want %q", got.URLOverride, override)
	}
	sibling, err := src.Endpoint(context.Background(), upID, model.EndpointModels)
	if err != nil {
		t.Fatal(err)
	}
	if sibling.URLOverride != siblingWarm.URLOverride || sibling.Revision != siblingWarm.Revision {
		t.Fatalf("sibling models endpoint changed: before=%+v after=%+v", siblingWarm, sibling)
	}

	// Validation failure must leave the published snapshot unchanged.
	beforeInv, beforeRef = pub.counts()
	rec = do(t, h, "PUT", "/admin/api/upstream-endpoints/"+itoa(got.ID),
		`{"url_override":"https://other.example.com/x","expected_revision":`+itoa(got.Revision)+`}`, true)
	if rec.Code == http.StatusOK {
		t.Fatal("cross-origin url_override must be rejected")
	}
	afterInv, afterRef := pub.counts()
	if afterInv != beforeInv || afterRef != beforeRef {
		t.Fatalf("validation failure must not publish: inv=%d→%d ref=%d→%d",
			beforeInv, afterInv, beforeRef, afterRef)
	}
	still, err := src.Endpoint(context.Background(), upID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	if still.URLOverride != override {
		t.Fatalf("rejected write changed snapshot override to %q", still.URLOverride)
	}
}

func TestWrite_EndpointRefreshFailureDoesNotReturnSuccessWithStaleSnapshot(t *testing.T) {
	s, _, src, pub := newLivecfgServer(t)
	h := s.WithProbeAdmin(probe.NewService(s.st, nil, nil, nil, nil, nil)).Routes(testAdminPW)

	upID := mkUpstreamViaAPI(t, h,
		`{"name":"ep-rf-u","base_url":"https://ep-rf.example.com","api_key":"sk-bbbbbbbbbbbb"}`)
	warm, err := src.Endpoint(context.Background(), upID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}

	pub.mu.Lock()
	pub.refreshErr = errRefreshBoom
	pub.skipInnerRefresh = true
	pub.mu.Unlock()

	override := "https://ep-rf.example.com/v1/after-fail"
	beforeInv, beforeRef := pub.counts()
	rec := do(t, h, "PUT", "/admin/api/upstream-endpoints/"+itoa(warm.ID),
		`{"url_override":`+mustJSON(t, override)+`,"expected_revision":`+itoa(warm.Revision)+`}`, true)
	if rec.Code == http.StatusOK {
		t.Fatal("Refresh failure must not return 200 while Probe may be stale")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 on Refresh failure, got %d: %s", rec.Code, rec.Body.String())
	}
	afterInv, afterRef := pub.counts()
	if afterInv != beforeInv+2 || afterRef != beforeRef+1 {
		t.Fatalf("want Invalidate x2 and Refresh x1: inv=%d ref=%d", afterInv-beforeInv, afterRef-beforeRef)
	}

	// Re-Invalidate forces get() to reload SQL: override must appear.
	got, err := src.Endpoint(context.Background(), upID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	if got.URLOverride != override {
		t.Fatalf("after Refresh failure + re-Invalidate want override %q, got %q", override, got.URLOverride)
	}
}

func TestWrite_EndpointFailedStoreDoesNotPublish(t *testing.T) {
	s, _, _, pub := newLivecfgServer(t)
	h := s.WithProbeAdmin(probe.NewService(s.st, nil, nil, nil, nil, nil)).Routes(testAdminPW)

	upID := mkUpstreamViaAPI(t, h,
		`{"name":"ep-fail-u","base_url":"https://ep-fail.example.com","api_key":"sk-cccccccccccc"}`)
	rec := do(t, h, "GET", "/admin/api/upstream-endpoints?upstream_id="+itoa(upID), "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("list endpoints: %d %s", rec.Code, rec.Body.String())
	}
	page := decodeBody[model.Page[model.UpstreamEndpoint]](t, rec)
	if len(page.Items) == 0 {
		t.Fatal("expected auto-created endpoints")
	}
	ep := page.Items[0]

	beforeInv, beforeRef := pub.counts()
	forceTableUpdateFail(t, s, "upstream_endpoint")
	rec = do(t, h, "PUT", "/admin/api/upstream-endpoints/"+itoa(ep.ID),
		`{"url_override":`+mustJSON(t, "https://ep-fail.example.com/x")+
			`,"expected_revision":`+itoa(ep.Revision)+`}`, true)
	if rec.Code == http.StatusOK {
		t.Fatal("expected update failure, got 200")
	}
	afterInv, afterRef := pub.counts()
	if afterInv != beforeInv || afterRef != beforeRef {
		t.Fatalf("failed endpoint update must not publish: inv=%d→%d ref=%d→%d",
			beforeInv, afterInv, beforeRef, afterRef)
	}
}

// Endpoint delete must Invalidate+Refresh so the next Probe/outbound Endpoint()
// read omits the row within TTL; a sibling kind on the same upstream stays.
func TestWrite_EndpointDeleteGoneBeforeHandlerReturns(t *testing.T) {
	s, _, src, pub := newLivecfgServer(t)
	h := s.WithProbeAdmin(probe.NewService(s.st, nil, nil, nil, nil, nil)).Routes(testAdminPW)

	upID := mkUpstreamViaAPI(t, h,
		`{"name":"ep-del-u","base_url":"https://ep-del.example.com","api_key":"sk-dddddddddddd"}`)
	drop, err := src.Endpoint(context.Background(), upID, model.EndpointCountTokens)
	if err != nil {
		t.Fatal(err)
	}
	siblingWarm, err := src.Endpoint(context.Background(), upID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}

	// DeleteEndpoint requires a disabled upstream with no Route dependents.
	rec := do(t, h, "PUT", "/admin/api/upstreams/"+itoa(upID), `{"enabled":false}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable upstream: %d %s", rec.Code, rec.Body.String())
	}

	beforeInv, beforeRef := pub.counts()
	rec = do(t, h, "DELETE",
		"/admin/api/upstream-endpoints/"+itoa(drop.ID)+"?expected_revision="+itoa(drop.Revision),
		"", true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete endpoint: %d %s", rec.Code, rec.Body.String())
	}
	assertPublished(t, pub, beforeInv, beforeRef)

	_, err = src.Endpoint(context.Background(), upID, model.EndpointCountTokens)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted endpoint still in Probe snapshot within TTL: %v", err)
	}
	sibling, err := src.Endpoint(context.Background(), upID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	if sibling.ID != siblingWarm.ID || sibling.Revision != siblingWarm.Revision {
		t.Fatalf("sibling messages endpoint changed: before=%+v after=%+v", siblingWarm, sibling)
	}
}

func TestWrite_EndpointDeleteRefreshFailureDoesNotReturnSuccessWithStaleSnapshot(t *testing.T) {
	s, _, src, pub := newLivecfgServer(t)
	h := s.WithProbeAdmin(probe.NewService(s.st, nil, nil, nil, nil, nil)).Routes(testAdminPW)

	upID := mkUpstreamViaAPI(t, h,
		`{"name":"ep-del-rf-u","base_url":"https://ep-del-rf.example.com","api_key":"sk-eeeeeeeeeeee"}`)
	drop, err := src.Endpoint(context.Background(), upID, model.EndpointCountTokens)
	if err != nil {
		t.Fatal(err)
	}
	rec := do(t, h, "PUT", "/admin/api/upstreams/"+itoa(upID), `{"enabled":false}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable upstream: %d %s", rec.Code, rec.Body.String())
	}

	pub.mu.Lock()
	pub.refreshErr = errRefreshBoom
	pub.skipInnerRefresh = true
	pub.mu.Unlock()

	beforeInv, beforeRef := pub.counts()
	rec = do(t, h, "DELETE",
		"/admin/api/upstream-endpoints/"+itoa(drop.ID)+"?expected_revision="+itoa(drop.Revision),
		"", true)
	if rec.Code == http.StatusNoContent {
		t.Fatal("Refresh failure must not return 204 while Probe may be stale")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 on Refresh failure, got %d: %s", rec.Code, rec.Body.String())
	}
	afterInv, afterRef := pub.counts()
	if afterInv != beforeInv+2 || afterRef != beforeRef+1 {
		t.Fatalf("want Invalidate x2 and Refresh x1: inv=%d ref=%d", afterInv-beforeInv, afterRef-beforeRef)
	}

	// Re-Invalidate forces get() to reload SQL: deleted row must be gone.
	_, err = src.Endpoint(context.Background(), upID, model.EndpointCountTokens)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after Refresh failure + re-Invalidate want ErrNotFound, got %v", err)
	}
}

func TestWrite_EndpointDeleteFailedStoreDoesNotPublish(t *testing.T) {
	s, _, src, pub := newLivecfgServer(t)
	h := s.WithProbeAdmin(probe.NewService(s.st, nil, nil, nil, nil, nil)).Routes(testAdminPW)

	upID := mkUpstreamViaAPI(t, h,
		`{"name":"ep-del-fail-u","base_url":"https://ep-del-fail.example.com","api_key":"sk-ffffffffffff"}`)
	drop, err := src.Endpoint(context.Background(), upID, model.EndpointCountTokens)
	if err != nil {
		t.Fatal(err)
	}
	rec := do(t, h, "PUT", "/admin/api/upstreams/"+itoa(upID), `{"enabled":false}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable upstream: %d %s", rec.Code, rec.Body.String())
	}

	beforeInv, beforeRef := pub.counts()
	forceTableDeleteFail(t, s, "upstream_endpoint")
	rec = do(t, h, "DELETE",
		"/admin/api/upstream-endpoints/"+itoa(drop.ID)+"?expected_revision="+itoa(drop.Revision),
		"", true)
	if rec.Code == http.StatusNoContent {
		t.Fatal("expected delete failure, got 204")
	}
	afterInv, afterRef := pub.counts()
	if afterInv != beforeInv || afterRef != beforeRef {
		t.Fatalf("failed endpoint delete must not publish: inv=%d→%d ref=%d→%d",
			beforeInv, afterInv, beforeRef, afterRef)
	}
}
