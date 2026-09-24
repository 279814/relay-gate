package probe

import (
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

type capSettings struct{ s model.Settings }

func (s capSettings) Settings() (model.Settings, error) { return s.s, nil }

func TestCapabilityRegistry_Models404DoesNotAffectMessages(t *testing.T) {
	settings := model.DefaultSettings()
	reg := NewCapabilityRegistry(capSettings{settings})
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildCapabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	fp := revisioncodec.ProbeSettingsFingerprint(policy)

	reg.ApplyCommitted(&model.EndpointCapability{
		ScopeType: model.RecipeScopeUpstream, ScopeID: 1, Endpoint: model.EndpointModels,
		PolicySelector: selector, State: model.CapabilityUnsupported,
		ObservationToken: "tok-models", ProbeSettingsFingerprint: fp,
		LastObservationOrder: 1, ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	})
	reg.ApplyCommitted(&model.EndpointCapability{
		ScopeType: model.RecipeScopeRoute, ScopeID: 9, Endpoint: model.EndpointMessages,
		PolicySelector: model.EvidencePolicySelector{
			Kind: model.EvidenceL2, Endpoint: model.EndpointMessages, TimeoutProfile: model.TimeoutL2Standard,
		},
		State: model.CapabilitySupported, ObservationToken: "tok-msg",
		ProbeSettingsFingerprint: mustCapFP(t, settings, model.EvidencePolicySelector{
			Kind: model.EvidenceL2, Endpoint: model.EndpointMessages, TimeoutProfile: model.TimeoutL2Standard,
		}),
		LastObservationOrder: 1, ExpiresAt: time.Now().Add(7 * 24 * time.Hour).UnixMilli(),
	})

	if got := reg.Effective(model.RecipeScopeUpstream, 1, model.EndpointModels, "tok-models"); got != model.CapabilityUnsupported {
		t.Fatalf("models=%s", got)
	}
	if got := reg.Effective(model.RecipeScopeRoute, 9, model.EndpointMessages, "tok-msg"); got != model.CapabilitySupported {
		t.Fatalf("messages must stay supported, got %s", got)
	}
}

func TestCapabilityRegistry_CountTokensDoesNotChangeMessages(t *testing.T) {
	settings := model.DefaultSettings()
	reg := NewCapabilityRegistry(capSettings{settings})
	msgSel := model.EvidencePolicySelector{
		Kind: model.EvidenceL2, Endpoint: model.EndpointMessages, TimeoutProfile: model.TimeoutL2Standard,
	}
	reg.ApplyCommitted(&model.EndpointCapability{
		ScopeType: model.RecipeScopeRoute, ScopeID: 2, Endpoint: model.EndpointMessages,
		PolicySelector: msgSel, State: model.CapabilitySupported,
		ObservationToken: "m", ProbeSettingsFingerprint: mustCapFP(t, settings, msgSel),
		LastObservationOrder: 3, ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	})
	ctSel := model.EvidencePolicySelector{Kind: model.EvidenceCountTokens, Endpoint: model.EndpointCountTokens}
	reg.ApplyCommitted(&model.EndpointCapability{
		ScopeType: model.RecipeScopeRoute, ScopeID: 2, Endpoint: model.EndpointCountTokens,
		PolicySelector: ctSel, State: model.CapabilityUnsupported,
		ObservationToken: "c", ProbeSettingsFingerprint: mustCapFP(t, settings, ctSel),
		LastObservationOrder: 4, ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	})
	if got := reg.Effective(model.RecipeScopeRoute, 2, model.EndpointMessages, "m"); got != model.CapabilitySupported {
		t.Fatalf("messages changed to %s", got)
	}
}

func TestCapabilityRegistry_MarkCountTokensUnsupported(t *testing.T) {
	settings := model.DefaultSettings()
	reg := NewCapabilityRegistry(capSettings{settings})
	now := time.UnixMilli(1_700_000_000_000)
	reg.now = func() time.Time { return now }

	reg.MarkCountTokensUnsupported(7, 0, 500)
	if got := reg.Effective(model.RecipeScopeRoute, 7, model.EndpointCountTokens, ""); got != model.CapabilityUnknown {
		t.Fatalf("500 marked unsupported: %s", got)
	}

	reg.MarkCountTokensUnsupported(7, 0, 404)
	if got := reg.Effective(model.RecipeScopeRoute, 7, model.EndpointCountTokens, ""); got != model.CapabilityUnsupported {
		t.Fatalf("404 effective=%s, want unsupported", got)
	}
	row := reg.Snapshot(model.RecipeScopeRoute, 7, model.EndpointCountTokens)
	if row == nil || row.StatusCode != 404 {
		t.Fatalf("snapshot=%+v", row)
	}
	if row.Endpoint != model.EndpointCountTokens {
		t.Fatalf("endpoint=%s", row.Endpoint)
	}
	policy, err := revisioncodec.BuildCapabilityEvidencePolicy(settings, model.EvidencePolicySelector{
		Kind: model.EvidenceCountTokens, Endpoint: model.EndpointCountTokens,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantExp := now.UnixMilli() + policy.State.UnsupportedTTL.Milliseconds()
	if row.ExpiresAt != wantExp {
		t.Fatalf("ExpiresAt=%d want=%d (existing UnsupportedTTL)", row.ExpiresAt, wantExp)
	}
	if got := reg.Effective(model.RecipeScopeRoute, 7, model.EndpointMessages, ""); got != model.CapabilityUnknown {
		t.Fatalf("messages capability leaked: %s", got)
	}
}

func TestCapabilityRegistry_MarkCountTokensConfigError(t *testing.T) {
	settings := model.DefaultSettings()
	reg := NewCapabilityRegistry(capSettings{settings})
	now := time.UnixMilli(1_700_000_000_000)
	reg.now = func() time.Time { return now }

	reg.MarkCountTokensConfigError(7, 0, 500)
	if got := reg.Effective(model.RecipeScopeRoute, 7, model.EndpointCountTokens, ""); got != model.CapabilityUnknown {
		t.Fatalf("500 marked config_error: %s", got)
	}
	reg.MarkCountTokensConfigError(7, 0, 404)
	if got := reg.Effective(model.RecipeScopeRoute, 7, model.EndpointCountTokens, ""); got != model.CapabilityUnknown {
		t.Fatalf("404 marked config_error: %s", got)
	}

	reg.MarkCountTokensConfigError(7, 0, 401)
	if got := reg.Effective(model.RecipeScopeRoute, 7, model.EndpointCountTokens, ""); got != model.CapabilityConfigError {
		t.Fatalf("401 effective=%s, want config_error", got)
	}
	row := reg.Snapshot(model.RecipeScopeRoute, 7, model.EndpointCountTokens)
	if row == nil || row.StatusCode != 401 {
		t.Fatalf("snapshot=%+v", row)
	}
	if row.State != model.CapabilityConfigError || row.ErrorClass != model.ErrorAuthRejected {
		t.Fatalf("state=%s class=%s", row.State, row.ErrorClass)
	}
	if row.ExpiresAt != 0 {
		t.Fatalf("ExpiresAt=%d want 0 (config_error does not TTL)", row.ExpiresAt)
	}
	if got := reg.Effective(model.RecipeScopeRoute, 7, model.EndpointMessages, ""); got != model.CapabilityUnknown {
		t.Fatalf("messages capability leaked: %s", got)
	}

	// 404 remains unsupported, not overwritten by a later mis-mark as config_error path.
	reg2 := NewCapabilityRegistry(capSettings{settings})
	reg2.now = func() time.Time { return now }
	reg2.MarkCountTokensUnsupported(8, 0, 404)
	if got := reg2.Effective(model.RecipeScopeRoute, 8, model.EndpointCountTokens, ""); got != model.CapabilityUnsupported {
		t.Fatalf("404 effective=%s, want unsupported", got)
	}
	reg2.MarkCountTokensConfigError(8, 0, 500)
	if got := reg2.Effective(model.RecipeScopeRoute, 8, model.EndpointCountTokens, ""); got != model.CapabilityUnsupported {
		t.Fatalf("500 must not change unsupported to %s", got)
	}
}

// Delete + recreate can reuse a SQLite route rowid. InvalidateRoute clears
// Capability, but a late count_tokens Mark* that skips the RouteHealth
// generation check would re-poison the new incarnation — same hole as
// TestReportResult_ModelNotFound_LateAfterReuseDoesNotPoison.
func TestCapabilityRegistry_MarkCountTokens_LateAfterReuseDoesNotPoison(t *testing.T) {
	const routeID int64 = 42
	settings := model.DefaultSettings()
	caps := NewCapabilityRegistry(capSettings{settings})
	tr := health.NewTracker(nil)
	caps.WithRouteGeneration(tr)
	sem := health.NewSemanticInvalidator(tr, nil, caps, nil, nil)

	oldGen := tr.EnsureGeneration(routeID)

	caps.MarkCountTokensUnsupported(routeID, oldGen, 404)
	if got := caps.Effective(model.RecipeScopeRoute, routeID, model.EndpointCountTokens, ""); got != model.CapabilityUnsupported {
		t.Fatalf("live 404 capability=%s want unsupported", got)
	}
	if got := caps.Effective(model.RecipeScopeRoute, routeID, model.EndpointMessages, ""); got != model.CapabilityUnknown {
		t.Fatalf("messages leaked: %s", got)
	}

	sem.InvalidateRoute(routeID)
	if got := caps.Effective(model.RecipeScopeRoute, routeID, model.EndpointCountTokens, ""); got == model.CapabilityUnsupported {
		t.Fatal("InvalidateRoute must clear count_tokens unsupported")
	}

	newGen := tr.EnsureGeneration(routeID)
	if newGen == 0 || newGen == oldGen {
		t.Fatalf("reused id must get a new generation: old=%d new=%d", oldGen, newGen)
	}

	// Late 404 from the deleted incarnation must not mark the new route.
	caps.MarkCountTokensUnsupported(routeID, oldGen, 404)
	if got := caps.Effective(model.RecipeScopeRoute, routeID, model.EndpointCountTokens, ""); got != model.CapabilityUnknown {
		t.Fatalf("stale 404 must not leave reused id unsupported, got %s", got)
	}

	// Late 401 must not mark config_error either.
	caps.MarkCountTokensConfigError(routeID, oldGen, 401)
	if got := caps.Effective(model.RecipeScopeRoute, routeID, model.EndpointCountTokens, ""); got != model.CapabilityUnknown {
		t.Fatalf("stale 401 must not leave reused id config_error, got %s", got)
	}
	if got := caps.Effective(model.RecipeScopeRoute, routeID, model.EndpointMessages, ""); got != model.CapabilityUnknown {
		t.Fatalf("messages must stay untouched, got %s", got)
	}

	// Matching generation on the live reuse still marks.
	caps.MarkCountTokensUnsupported(routeID, newGen, 404)
	if got := caps.Effective(model.RecipeScopeRoute, routeID, model.EndpointCountTokens, ""); got != model.CapabilityUnsupported {
		t.Fatalf("live reused 404 capability=%s want unsupported", got)
	}

	sem.InvalidateRoute(routeID)
	newGen2 := tr.EnsureGeneration(routeID)
	caps.MarkCountTokensConfigError(routeID, newGen2, 401)
	if got := caps.Effective(model.RecipeScopeRoute, routeID, model.EndpointCountTokens, ""); got != model.CapabilityConfigError {
		t.Fatalf("live reused 401 capability=%s want config_error", got)
	}
	if got := caps.Effective(model.RecipeScopeRoute, routeID, model.EndpointMessages, ""); got != model.CapabilityUnknown {
		t.Fatalf("messages must stay untouched after config_error mark, got %s", got)
	}
}

func TestCapabilityRegistry_CASKeepsHigherOrder(t *testing.T) {
	settings := model.DefaultSettings()
	reg := NewCapabilityRegistry(capSettings{settings})
	sel := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	fp := mustCapFP(t, settings, sel)
	newer := &model.EndpointCapability{
		ScopeType: model.RecipeScopeUpstream, ScopeID: 1, Endpoint: model.EndpointModels,
		PolicySelector: sel, State: model.CapabilitySupported,
		ObservationToken: "t", ProbeSettingsFingerprint: fp,
		LastObservationOrder: 20, ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	}
	older := &model.EndpointCapability{
		ScopeType: model.RecipeScopeUpstream, ScopeID: 1, Endpoint: model.EndpointModels,
		PolicySelector: sel, State: model.CapabilityUnsupported,
		ObservationToken: "t", ProbeSettingsFingerprint: fp,
		LastObservationOrder: 10, ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	}
	reg.ApplyCommitted(newer)
	reg.ApplyCommitted(older)
	if got := reg.Snapshot(model.RecipeScopeUpstream, 1, model.EndpointModels); got.State != model.CapabilitySupported {
		t.Fatalf("CAS failed: %+v", got)
	}
}

func TestCapabilityRegistry_ExpiredDerivedUnknown(t *testing.T) {
	settings := model.DefaultSettings()
	now := time.UnixMilli(1_700_000_000_000)
	reg := NewCapabilityRegistry(capSettings{settings})
	reg.now = func() time.Time { return now }
	sel := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	reg.ApplyCommitted(&model.EndpointCapability{
		ScopeType: model.RecipeScopeUpstream, ScopeID: 1, Endpoint: model.EndpointModels,
		PolicySelector: sel, State: model.CapabilitySupported,
		ObservationToken: "t", ProbeSettingsFingerprint: mustCapFP(t, settings, sel),
		LastObservationOrder: 1, ExpiresAt: now.UnixMilli(), // exactly now → expired
	})
	if got := reg.Effective(model.RecipeScopeUpstream, 1, model.EndpointModels, "t"); got != model.CapabilityUnknown {
		t.Fatalf("expired effective=%s", got)
	}
	if snap := reg.Snapshot(model.RecipeScopeUpstream, 1, model.EndpointModels); snap.State != model.CapabilitySupported {
		t.Fatalf("persisted state must remain five-state, got %s", snap.State)
	}
}

func mustCapFP(t *testing.T, settings model.Settings, selector model.EvidencePolicySelector) string {
	t.Helper()
	policy, err := revisioncodec.BuildCapabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	return revisioncodec.ProbeSettingsFingerprint(policy)
}
