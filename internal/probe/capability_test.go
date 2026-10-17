package probe

import (
	"fmt"
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

func TestCountTokensCommittedStatusAndUnsupportedTTL(t *testing.T) {
	h := newCountTrafficHarness(t)
	h.finish(t, h.begin(), 500, `{"error":{"type":"server_error"}}`)
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens, ""); got != model.CapabilityTransientError {
		t.Fatalf("500 state=%s", got)
	}
	h.finish(t, h.begin(), 404, `{"error":{"type":"not_found_error"}}`)
	row := h.caps.Snapshot(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens)
	policy, err := revisioncodec.BuildCapabilityEvidencePolicy(model.DefaultSettings(), model.EvidencePolicySelector{Kind: model.EvidenceCountTokens, Endpoint: model.EndpointCountTokens})
	if err != nil {
		t.Fatal(err)
	}
	if row == nil || row.State != model.CapabilityUnsupported || row.StatusCode != 404 || row.ObservationToken == "" || row.ExpiresAt != h.now.Add(policy.State.UnsupportedTTL).UnixMilli() {
		t.Fatalf("404 committed row=%+v", row)
	}
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages, ""); got != model.CapabilityUnknown {
		t.Fatalf("messages leaked: %s", got)
	}
}

func TestCapabilityRegistry_CountTokensUnsupportedLasts24Hours(t *testing.T) {
	h := newCountTrafficHarness(t)
	start := h.now
	h.finish(t, h.begin(), 405, "")
	h.now = start.Add(24*time.Hour - time.Millisecond)
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens, ""); got != model.CapabilityUnsupported {
		t.Fatalf("before TTL=%s", got)
	}
	h.now = start.Add(24 * time.Hour)
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens, ""); got != model.CapabilityUnknown {
		t.Fatalf("at TTL=%s", got)
	}
}

func TestCapabilityRegistry_SupportedLasts7Days(t *testing.T) {
	settings := model.DefaultSettings()
	reg := NewCapabilityRegistry(capSettings{settings})
	start := time.UnixMilli(1_700_000_000_000)
	now := start
	reg.now = func() time.Time { return now }

	selector := model.EvidencePolicySelector{
		Kind: model.EvidenceL2, Endpoint: model.EndpointMessages, TimeoutProfile: model.TimeoutL2Standard,
	}
	policy, err := revisioncodec.BuildCapabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	reducer := health.NewObservationReducer(func() time.Time { return start })
	row, err := reducer.ReduceCapability(nil, model.ProbeExecution{
		Capability: model.CapabilitySupported, Success: true, CapabilityToken: "tok",
	}, policy.State)
	if err != nil {
		t.Fatal(err)
	}
	row.ScopeType, row.ScopeID, row.Endpoint = model.RecipeScopeRoute, 5, model.EndpointMessages
	row.PolicySelector = selector
	row.ObservationToken = "tok"
	row.ProbeSettingsFingerprint = revisioncodec.ProbeSettingsFingerprint(policy)
	row.LastObservationOrder = 1
	reg.ApplyCommitted(row)

	now = start.Add(7*24*time.Hour - time.Millisecond)
	if got := reg.Effective(model.RecipeScopeRoute, 5, model.EndpointMessages, "tok"); got != model.CapabilitySupported {
		t.Fatalf("just before 7d effective=%s, want supported", got)
	}
	now = start.Add(7 * 24 * time.Hour)
	if got := reg.Effective(model.RecipeScopeRoute, 5, model.EndpointMessages, "tok"); got != model.CapabilityUnknown {
		t.Fatalf("at 7d effective=%s, want unknown", got)
	}
}

// §8.13 / §10.3: a successful real count_tokens observation is supported,
// expires on the existing SupportedTTL, and stays count_tokens-only.
func TestCountTokensCommittedSuccessTTLAndScope(t *testing.T) {
	h := newCountTrafficHarness(t)
	h.finish(t, h.begin(), 200, `{"input_tokens":12}`)
	row := h.caps.Snapshot(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens)
	policy, err := revisioncodec.BuildCapabilityEvidencePolicy(model.DefaultSettings(), model.EvidencePolicySelector{Kind: model.EvidenceCountTokens, Endpoint: model.EndpointCountTokens})
	if err != nil {
		t.Fatal(err)
	}
	if row == nil || row.State != model.CapabilitySupported || row.StatusCode != 200 || row.ErrorClass != model.ErrorNone || row.ExpiresAt != h.now.Add(policy.State.SupportedTTL).UnixMilli() {
		t.Fatalf("committed success=%+v", row)
	}
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages, ""); got != model.CapabilityUnknown {
		t.Fatalf("messages leaked: %s", got)
	}
	h.now = h.now.Add(policy.State.SupportedTTL)
	if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens, ""); got != model.CapabilityUnknown {
		t.Fatalf("expired success=%s", got)
	}
}

func TestCountTokensCommittedAuthErrorIsStickyAndEndpointLocal(t *testing.T) {
	for _, status := range []int{401, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			h := newCountTrafficHarness(t)
			h.finish(t, h.begin(), 500, `{"error":{"type":"server_error"}}`)
			if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens, ""); got == model.CapabilityConfigError {
				t.Fatal("500 became config_error")
			}
			h.finish(t, h.begin(), 404, "")
			if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens, ""); got != model.CapabilityUnsupported {
				t.Fatalf("404=%s", got)
			}
			h.finish(t, h.begin(), status, `{"error":{"type":"authentication_error"}}`)
			row := h.caps.Snapshot(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens)
			if row == nil || row.State != model.CapabilityConfigError || row.ErrorClass != model.ErrorAuthRejected || row.ExpiresAt != 0 {
				t.Fatalf("auth committed row=%+v", row)
			}
			h.now = h.now.AddDate(1, 0, 0)
			if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointCountTokens, ""); got != model.CapabilityConfigError {
				t.Fatalf("config_error expired=%s", got)
			}
			if got := h.caps.Effective(model.RecipeScopeRoute, h.route.ID, model.EndpointMessages, ""); got != model.CapabilityUnknown {
				t.Fatalf("messages leaked: %s", got)
			}
		})
	}
}

func TestInvalidateUpstream_ClearsUpstreamScopedCapability(t *testing.T) {
	const (
		deletedUp  int64 = 10
		otherUp    int64 = 20
		childRoute int64 = 100
		otherRoute int64 = 200
	)
	settings := model.DefaultSettings()
	caps := NewCapabilityRegistry(capSettings{settings})
	sem := health.NewSemanticInvalidator(nil, nil, caps, nil, nil)

	l1 := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	l2 := model.EvidencePolicySelector{
		Kind: model.EvidenceL2, Endpoint: model.EndpointMessages, TimeoutProfile: model.TimeoutL2Standard,
	}
	l1FP := mustCapFP(t, settings, l1)
	l2FP := mustCapFP(t, settings, l2)

	caps.ApplyCommitted(&model.EndpointCapability{
		ScopeType: model.RecipeScopeUpstream, ScopeID: deletedUp, Endpoint: model.EndpointModels,
		PolicySelector: l1, State: model.CapabilityUnsupported,
		ObservationToken: "tok-del", ProbeSettingsFingerprint: l1FP,
		LastObservationOrder: 1, ErrorClass: model.ErrorUnsupported,
	})
	caps.ApplyCommitted(&model.EndpointCapability{
		ScopeType: model.RecipeScopeUpstream, ScopeID: otherUp, Endpoint: model.EndpointModels,
		PolicySelector: l1, State: model.CapabilityConfigError,
		ObservationToken: "tok-other", ProbeSettingsFingerprint: l1FP,
		LastObservationOrder: 1, ErrorClass: model.ErrorAuthRejected, ExpiresAt: 0,
	})
	caps.ApplyCommitted(&model.EndpointCapability{
		ScopeType: model.RecipeScopeRoute, ScopeID: childRoute, Endpoint: model.EndpointMessages,
		PolicySelector: l2, State: model.CapabilityUnsupported,
		ObservationToken: "tok-child", ProbeSettingsFingerprint: l2FP,
		LastObservationOrder: 1, ErrorClass: model.ErrorUnsupported,
	})
	caps.ApplyCommitted(&model.EndpointCapability{
		ScopeType: model.RecipeScopeRoute, ScopeID: otherRoute, Endpoint: model.EndpointMessages,
		PolicySelector: l2, State: model.CapabilityUnsupported,
		ObservationToken: "tok-keep", ProbeSettingsFingerprint: l2FP,
		LastObservationOrder: 1, ErrorClass: model.ErrorUnsupported,
	})

	if got := caps.Effective(model.RecipeScopeUpstream, deletedUp, model.EndpointModels, ""); got != model.CapabilityUnsupported {
		t.Fatalf("setup deleted upstream capability=%s want unsupported", got)
	}

	sem.InvalidateUpstream(deletedUp, []int64{childRoute})

	if got := caps.Effective(model.RecipeScopeUpstream, deletedUp, model.EndpointModels, ""); got != model.CapabilityUnknown {
		t.Fatalf("deleted upstream capability=%s want unknown (reused id must not inherit)", got)
	}
	if got := caps.Effective(model.RecipeScopeUpstream, otherUp, model.EndpointModels, ""); got != model.CapabilityConfigError {
		t.Fatalf("other upstream capability=%s want config_error retained", got)
	}
	if got := caps.Effective(model.RecipeScopeRoute, childRoute, model.EndpointMessages, ""); got != model.CapabilityUnknown {
		t.Fatalf("child route capability=%s want unknown", got)
	}
	if got := caps.Effective(model.RecipeScopeRoute, otherRoute, model.EndpointMessages, ""); got != model.CapabilityUnsupported {
		t.Fatalf("unrelated route capability=%s want unsupported retained", got)
	}
}

// Delete + recreate can reuse a SQLite route rowid. InvalidateRoute clears
// Capability, but a late count_tokens Mark* that skips the RouteHealth
// generation check would re-poison the new incarnation — same hole as
// TestReportResult_ModelNotFound_LateAfterReuseDoesNotPoison.
func TestCapabilityRegistry_GuardedCommittedApplyRejectsForgottenGeneration(t *testing.T) {
	caps := NewCapabilityRegistry(capSettings{model.DefaultSettings()})
	track := health.NewTracker(nil)
	caps.WithRouteGeneration(track)
	semantic := health.NewSemanticInvalidator(track, nil, caps, nil, nil)
	const routeID int64 = 42
	old := track.EnsureGeneration(routeID)
	selector := model.EvidencePolicySelector{Kind: model.EvidenceCountTokens, Endpoint: model.EndpointCountTokens}
	row := &model.EndpointCapability{ScopeType: model.RecipeScopeRoute, ScopeID: routeID, Endpoint: model.EndpointCountTokens, PolicySelector: selector, State: model.CapabilityUnsupported, ObservationToken: "captured-token", ProbeSettingsFingerprint: mustCapFP(t, model.DefaultSettings(), selector), LastObservationOrder: 1}
	caps.applyCommitted(row, &old)
	if got := caps.Effective(model.RecipeScopeRoute, routeID, model.EndpointCountTokens, ""); got != model.CapabilityUnsupported {
		t.Fatalf("current generation=%s", got)
	}
	semantic.InvalidateRoute(routeID)
	current := track.EnsureGeneration(routeID)
	if current == old {
		t.Fatal("forgotten identity reused generation")
	}
	for _, state := range []model.CapabilityState{model.CapabilityUnsupported, model.CapabilityConfigError} {
		row.State = state
		row.LastObservationOrder++
		caps.applyCommitted(row, &old)
		if got := caps.Effective(model.RecipeScopeRoute, routeID, model.EndpointCountTokens, ""); got != model.CapabilityUnknown {
			t.Fatalf("late generation revived %s", got)
		}
	}
	caps.applyCommitted(row, &current)
	if got := caps.Effective(model.RecipeScopeRoute, routeID, model.EndpointCountTokens, ""); got != model.CapabilityConfigError {
		t.Fatalf("new committed generation=%s", got)
	}
	if got := caps.Effective(model.RecipeScopeRoute, routeID, model.EndpointMessages, ""); got != model.CapabilityUnknown {
		t.Fatalf("messages leaked=%s", got)
	}
}

func TestCapabilityRegistry_GuardedApplyRejectsUnboundGenerationAgainstLiveRoute(t *testing.T) {
	caps := NewCapabilityRegistry(capSettings{model.DefaultSettings()})
	track := health.NewTracker(nil)
	caps.WithRouteGeneration(track)
	const routeID int64 = 55
	track.EnsureGeneration(routeID)
	track.Forget(routeID)
	current := track.EnsureGeneration(routeID)
	zero := uint64(0)
	selector := model.EvidencePolicySelector{Kind: model.EvidenceCountTokens, Endpoint: model.EndpointCountTokens}
	row := &model.EndpointCapability{ScopeType: model.RecipeScopeRoute, ScopeID: routeID, Endpoint: model.EndpointCountTokens, PolicySelector: selector, State: model.CapabilityUnsupported, ObservationToken: "token", ProbeSettingsFingerprint: mustCapFP(t, model.DefaultSettings(), selector), LastObservationOrder: 1}
	for _, state := range []model.CapabilityState{model.CapabilityUnsupported, model.CapabilityConfigError} {
		row.State = state
		caps.applyCommitted(row, &zero)
		if got := caps.Snapshot(model.RecipeScopeRoute, routeID, model.EndpointCountTokens); got != nil {
			t.Fatalf("unbound generation polluted route: %+v", got)
		}
	}
	caps.applyCommitted(row, &current)
	if got := caps.Snapshot(model.RecipeScopeRoute, routeID, model.EndpointCountTokens); got == nil {
		t.Fatal("current generation was dropped")
	}
	row.ScopeID = 56
	caps.applyCommitted(row, &zero)
	if got := caps.Snapshot(model.RecipeScopeRoute, 56, model.EndpointCountTokens); got == nil {
		t.Fatal("initial zero generation must be usable")
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

// A prior incarnation (or Mark* UnixMilli placeholder) can leave a higher
// LastObservationOrder under a different ObservationToken. The new token must
// still replace it — same-token order CAS must not gate cross-token applies.
func TestCapabilityRegistry_DifferentTokenLowerOrderReplaces(t *testing.T) {
	settings := model.DefaultSettings()
	reg := NewCapabilityRegistry(capSettings{settings})
	sel := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	fp := mustCapFP(t, settings, sel)
	reg.ApplyCommitted(&model.EndpointCapability{
		ScopeType: model.RecipeScopeUpstream, ScopeID: 1, Endpoint: model.EndpointModels,
		PolicySelector: sel, State: model.CapabilityUnsupported,
		ObservationToken: "old-incarnation", ProbeSettingsFingerprint: fp,
		LastObservationOrder: 1_700_000_000_000, ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	})
	reg.ApplyCommitted(&model.EndpointCapability{
		ScopeType: model.RecipeScopeUpstream, ScopeID: 1, Endpoint: model.EndpointModels,
		PolicySelector: sel, State: model.CapabilitySupported,
		ObservationToken: "new-incarnation", ProbeSettingsFingerprint: fp,
		LastObservationOrder: 42, ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	})
	got := reg.Snapshot(model.RecipeScopeUpstream, 1, model.EndpointModels)
	if got == nil || got.ObservationToken != "new-incarnation" || got.LastObservationOrder != 42 ||
		got.State != model.CapabilitySupported {
		t.Fatalf("new token with lower order must replace: %+v", got)
	}
}

// Empty ObservationToken (MarkCountTokens* / real_model_not_found) must not
// clobber a non-empty revision token, even with a higher UnixMilli order.
// Non-empty still replaces an empty placeholder (#281).
func TestCapabilityRegistry_EmptyTokenDoesNotClobberNonEmpty(t *testing.T) {
	settings := model.DefaultSettings()
	reg := NewCapabilityRegistry(capSettings{settings})
	sel := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	fp := mustCapFP(t, settings, sel)
	reg.ApplyCommitted(&model.EndpointCapability{
		ScopeType: model.RecipeScopeUpstream, ScopeID: 1, Endpoint: model.EndpointModels,
		PolicySelector: sel, State: model.CapabilitySupported,
		ObservationToken: "revision-token", ProbeSettingsFingerprint: fp,
		LastObservationOrder: 42, ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	})
	reg.ApplyCommitted(&model.EndpointCapability{
		ScopeType: model.RecipeScopeUpstream, ScopeID: 1, Endpoint: model.EndpointModels,
		PolicySelector: sel, State: model.CapabilityUnsupported,
		ObservationToken: "", ProbeSettingsFingerprint: fp,
		LastObservationOrder: 1_700_000_000_000, ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	})
	got := reg.Snapshot(model.RecipeScopeUpstream, 1, model.EndpointModels)
	if got == nil || got.ObservationToken != "revision-token" || got.LastObservationOrder != 42 ||
		got.State != model.CapabilitySupported {
		t.Fatalf("empty token must not clobber non-empty: %+v", got)
	}

	reg.ApplyCommitted(&model.EndpointCapability{
		ScopeType: model.RecipeScopeUpstream, ScopeID: 2, Endpoint: model.EndpointModels,
		PolicySelector: sel, State: model.CapabilityUnsupported,
		ObservationToken: "", ProbeSettingsFingerprint: fp,
		LastObservationOrder: 1_700_000_000_000, ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	})
	reg.ApplyCommitted(&model.EndpointCapability{
		ScopeType: model.RecipeScopeUpstream, ScopeID: 2, Endpoint: model.EndpointModels,
		PolicySelector: sel, State: model.CapabilitySupported,
		ObservationToken: "revision-token", ProbeSettingsFingerprint: fp,
		LastObservationOrder: 42, ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	})
	got = reg.Snapshot(model.RecipeScopeUpstream, 2, model.EndpointModels)
	if got == nil || got.ObservationToken != "revision-token" || got.LastObservationOrder != 42 ||
		got.State != model.CapabilitySupported {
		t.Fatalf("non-empty must still replace empty placeholder: %+v", got)
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
