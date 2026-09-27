package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
	"github.com/279814/relay-gate/internal/revisioncodec"
	"github.com/279814/relay-gate/internal/store"
)

type supportedCapabilityReducer struct{}

func (supportedCapabilityReducer) ReduceReachability(*model.UpstreamReachability, model.ProbeExecution, model.ReachabilityReductionPolicy) (*model.UpstreamReachability, error) {
	return nil, nil
}

func (supportedCapabilityReducer) ReduceCapability(*model.EndpointCapability, model.ProbeExecution, model.CapabilityReductionPolicy) (*model.EndpointCapability, error) {
	return &model.EndpointCapability{State: model.CapabilitySupported}, nil
}

type secretProbeTarget struct {
	target   model.SemanticTarget
	identity model.RecipeIdentity
	facts    model.RecipeBindingFacts
	selector model.EvidencePolicySelector
}

func (p secretProbeTarget) expectation(t *testing.T, snap *livecfg.ProbeSnapshot) *model.SemanticExpectation {
	t.Helper()
	exp, err := snap.SemanticExpectation(p.target, p.identity, p.facts, p.selector)
	if err != nil {
		t.Fatal(err)
	}
	return &exp
}

func (p secretProbeTarget) commit(t *testing.T, st *store.Store, exp *model.SemanticExpectation, id string, order int64) model.ApplyDisposition {
	t.Helper()
	policy, err := revisioncodec.BuildCapabilityEvidencePolicy(model.DefaultSettings(), p.selector)
	if err != nil {
		t.Fatal(err)
	}
	rev := exp.Revision
	execution := model.ProbeExecution{
		ID: id, Trigger: model.TriggerScheduled, UpstreamID: p.target.UpstreamID, RouteID: p.target.RouteID,
		UpstreamNetworkRevision: rev.UpstreamNetwork, UpstreamCredentialRevision: rev.UpstreamCredential,
		CapabilityPolicySelector: p.selector, ProbeSettingsFingerprint: rev.ProbeSettingsFingerprint,
		EndpointID: rev.EndpointID, EndpointRevision: rev.EndpointRevision,
		ModelCapabilityRevision: rev.ModelCapability, RouteCapabilityRevision: rev.RouteCapability,
		AuthProfileRevision: rev.AuthProfile, Endpoint: p.target.Endpoint,
		RecipeBindingUse: p.facts.Use, RecipeStorage: p.identity.Storage, RecipeOrigin: p.identity.Origin,
		TemplateID: p.identity.TemplateID, RecipeIdentityRevision: p.identity.Revision,
		RecipeBindingRevision: rev.RecipeBindingRevision, RecipeBindingFacts: p.facts,
		CapabilityToken: exp.ObservationToken, EvidenceHash: id + "-evidence", ErrorClass: model.ErrorNone,
		Capability: model.CapabilitySupported, Scope: model.ScopeRouteEndpoint,
		Reachable: true, Final: true, Success: true, SemanticSeen: true, NormalEndSeen: true,
		ObservationOrder: order, SentAtMS: order, DoneAtMS: order + 1,
	}
	result, err := st.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: execution, CapabilityExpectation: exp, CapabilityPolicy: &policy.State,
	}, supportedCapabilityReducer{})
	if err != nil {
		t.Fatal(err)
	}
	return result.Capability
}

func probeSecretRevision(t *testing.T, src *livecfg.Source, name string) (model.SecretRevision, bool) {
	t.Helper()
	snap, err := src.ProbeSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	rev, ok := snap.SecretRevisions[name]
	return rev, ok
}

func assertNoPlaintextInProbeSnapshot(t *testing.T, src *livecfg.Source, plains ...string) {
	t.Helper()
	snap, err := src.ProbeSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range plains {
		if strings.Contains(string(raw), plain) {
			t.Fatalf("Probe snapshot contains Secret plaintext %q", plain)
		}
	}
}

// A secret write must reach the Probe snapshot before the handler returns, so
// the very next probe's capability expectation carries the store's current
// secret revision and its result is applied instead of config_stale.
func TestWrite_ProbeSecretRevisionVisibleBeforeHandlerReturns(t *testing.T) {
	s, _, src, pub := newLivecfgServer(t)
	h := s.WithProbeAdmin(probe.NewService(s.st, nil, nil, nil, nil, nil)).Routes(testAdminPW)

	const plainOne = "probe-secret-plain-one"
	const plainTwo = "probe-secret-plain-two"
	upID := mkUpstreamViaAPI(t, h,
		`{"name":"secret-pub-u","base_url":"https://secret-pub.example.com","api_key":"sk-aaaaaaaaaaaa"}`)
	mnID := mkModelNameViaAPI(t, h, "secret-pub-m")
	rtID := mkRouteViaAPI(t, h, mnID, upID)
	if _, err := src.ProbeSnapshot(); err != nil {
		t.Fatal(err)
	}

	beforeInv, beforeRef := pub.counts()
	rec := do(t, h, "POST", "/admin/api/probe-secrets", `{"name":"tok","value":"`+plainOne+`"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create secret: %d %s", rec.Code, rec.Body.String())
	}
	assertPublished(t, pub, beforeInv, beforeRef)
	created := decodeBody[secretOut](t, rec)
	if rev, ok := probeSecretRevision(t, src, "tok"); !ok || rev.ID != created.ID || rev.Revision != created.Revision {
		t.Fatalf("created secret not in Probe snapshot within TTL: %+v ok=%v want id=%d rev=%d",
			rev, ok, created.ID, created.Revision)
	}

	endpoint, err := src.Endpoint(context.Background(), upID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	rec = do(t, h, "PUT", "/admin/api/upstream-endpoints/"+itoa(endpoint.ID),
		`{"fixed_query_template":"k={{SECRET:tok}}","expected_revision":`+itoa(endpoint.Revision)+`}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("bind secret on endpoint: %d %s", rec.Code, rec.Body.String())
	}

	target := secretProbeTarget{
		target: model.SemanticTarget{Scope: model.RecipeScopeRoute, UpstreamID: upID, RouteID: rtID, Endpoint: model.EndpointMessages},
		identity: model.RecipeIdentity{
			Storage: model.RecipeStorageEmbedded, Origin: model.RecipeBasic, TemplateID: "builtin:messages", Revision: 1,
		},
		facts: model.RecipeBindingFacts{Use: model.BindingResolved, ResolvedLayer: model.ResolvedEmbedded},
		selector: model.EvidencePolicySelector{
			Kind: model.EvidenceL2, Endpoint: model.EndpointMessages, TimeoutProfile: model.TimeoutL2Standard,
		},
	}
	snapBefore, err := src.ProbeSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	inFlight := target.expectation(t, snapBefore)

	// Failed write (stale expected_revision) must not publish.
	beforeInv, beforeRef = pub.counts()
	rec = do(t, h, "PUT", "/admin/api/probe-secrets/"+itoa(created.ID),
		`{"value":"`+plainTwo+`","expected_revision":`+itoa(created.Revision+5)+`}`, true)
	if rec.Code == http.StatusOK {
		t.Fatal("stale expected_revision must be rejected")
	}
	if afterInv, afterRef := pub.counts(); afterInv != beforeInv || afterRef != beforeRef {
		t.Fatalf("failed secret update must not publish: inv=%d→%d ref=%d→%d", beforeInv, afterInv, beforeRef, afterRef)
	}

	beforeInv, beforeRef = pub.counts()
	rec = do(t, h, "PUT", "/admin/api/probe-secrets/"+itoa(created.ID),
		`{"value":"`+plainTwo+`","expected_revision":`+itoa(created.Revision)+`}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("update secret: %d %s", rec.Code, rec.Body.String())
	}
	assertPublished(t, pub, beforeInv, beforeRef)
	updated := decodeBody[secretOut](t, rec)
	if rev, ok := probeSecretRevision(t, src, "tok"); !ok || rev.ID != created.ID || rev.Revision != updated.Revision {
		t.Fatalf("updated secret revision not in Probe snapshot within TTL: %+v want rev=%d", rev, updated.Revision)
	}
	assertNoPlaintextInProbeSnapshot(t, src, plainOne, plainTwo)

	snapAfter, err := src.ProbeSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	fresh := target.expectation(t, snapAfter)
	if got := target.commit(t, s.st, fresh, "after-update", 10); got != model.ApplyCurrent {
		t.Fatalf("probe built right after secret update: capability=%s want applied", got)
	}
	// Built from the pre-update snapshot: ran against the old revision.
	if got := target.commit(t, s.st, inFlight, "in-flight-old-revision", 11); got != model.ApplyConfigStale {
		t.Fatalf("probe sent with pre-update secret revision: capability=%s want config_stale", got)
	}

	// Referenced secret stays undeletable, and the refusal does not publish.
	beforeInv, beforeRef = pub.counts()
	rec = do(t, h, "DELETE", "/admin/api/probe-secrets/"+itoa(created.ID)+"?expected_revision="+itoa(updated.Revision), "", true)
	if rec.Code == http.StatusNoContent {
		t.Fatal("deleting a referenced secret must be refused")
	}
	if afterInv, afterRef := pub.counts(); afterInv != beforeInv || afterRef != beforeRef {
		t.Fatalf("refused secret delete must not publish: inv=%d→%d ref=%d→%d", beforeInv, afterInv, beforeRef, afterRef)
	}

	endpoint, err = src.Endpoint(context.Background(), upID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	rec = do(t, h, "PUT", "/admin/api/upstream-endpoints/"+itoa(endpoint.ID),
		`{"fixed_query_template":"","expected_revision":`+itoa(endpoint.Revision)+`}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("unbind secret: %d %s", rec.Code, rec.Body.String())
	}
	beforeInv, beforeRef = pub.counts()
	rec = do(t, h, "DELETE", "/admin/api/probe-secrets/"+itoa(created.ID)+"?expected_revision="+itoa(updated.Revision), "", true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete unreferenced secret: %d %s", rec.Code, rec.Body.String())
	}
	assertPublished(t, pub, beforeInv, beforeRef)
	if rev, ok := probeSecretRevision(t, src, "tok"); ok {
		t.Fatalf("deleted secret still in Probe snapshot within TTL: %+v", rev)
	}

	// Same-name recreate gets a new id and must not satisfy the old binding.
	rec = do(t, h, "POST", "/admin/api/probe-secrets", `{"name":"tok","value":"`+plainOne+`"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("recreate secret: %d %s", rec.Code, rec.Body.String())
	}
	recreated := decodeBody[secretOut](t, rec)
	if recreated.ID == created.ID {
		t.Fatalf("same-name recreate reused id %d", created.ID)
	}
	if rev, ok := probeSecretRevision(t, src, "tok"); !ok || rev.ID != recreated.ID {
		t.Fatalf("recreated secret not in Probe snapshot within TTL: %+v", rev)
	}
	if got := target.commit(t, s.st, fresh, "old-binding-after-recreate", 12); got != model.ApplyConfigStale {
		t.Fatalf("old binding after same-name recreate: capability=%s want config_stale", got)
	}
	assertNoPlaintextInProbeSnapshot(t, src, plainOne, plainTwo)
}

func TestWrite_ProbeSecretRefreshFailureDoesNotReturnSuccess(t *testing.T) {
	s, _, src, pub := newLivecfgServer(t)
	h := s.WithProbeAdmin(probe.NewService(s.st, nil, nil, nil, nil, nil)).Routes(testAdminPW)

	rec := do(t, h, "POST", "/admin/api/probe-secrets", `{"name":"rf_tok","value":"refresh-fail-plain-one"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create secret: %d %s", rec.Code, rec.Body.String())
	}
	created := decodeBody[secretOut](t, rec)

	pub.mu.Lock()
	pub.refreshErr = errRefreshBoom
	pub.skipInnerRefresh = true
	pub.mu.Unlock()

	beforeInv, beforeRef := pub.counts()
	rec = do(t, h, "PUT", "/admin/api/probe-secrets/"+itoa(created.ID),
		`{"value":"refresh-fail-plain-two","expected_revision":`+itoa(created.Revision)+`}`, true)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 on Refresh failure, got %d: %s", rec.Code, rec.Body.String())
	}
	afterInv, afterRef := pub.counts()
	if afterInv != beforeInv+2 || afterRef != beforeRef+1 {
		t.Fatalf("want Invalidate x2 and Refresh x1: inv=%d ref=%d", afterInv-beforeInv, afterRef-beforeRef)
	}
	// Probe must fail closed rather than build expectations from the stale revision.
	if snap, err := src.ProbeSnapshot(); !errors.Is(err, livecfg.ErrProbeSnapshotUnavailable) {
		t.Fatalf("after Refresh failure want ErrProbeSnapshotUnavailable, got snap=%v err=%v", snap != nil, err)
	}
}
