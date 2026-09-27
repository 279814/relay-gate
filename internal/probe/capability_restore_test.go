package probe

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

type fixedCapabilityRows []*model.EndpointCapability

func (rows fixedCapabilityRows) ListEndpointCapabilitiesByState(context.Context, model.CapabilityState) ([]*model.EndpointCapability, error) {
	return rows, nil
}

func restoreTestDeps(st *store.Store) (*livecfg.Source, *RecipeResolver) {
	cfg := livecfg.New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	recipes := NewRecipeResolver(st).WithNotFound(func(err error) bool {
		return errors.Is(err, store.ErrNotFound)
	})
	return cfg, recipes
}

// commitRouteConfigError 走 Scheduler 同一路径构造 expectation，并经真实
// CommitProbeObservation 落一行 config_error，模拟重启前的探活结论。
func commitRouteConfigError(t *testing.T, st *store.Store, up *model.Upstream, rt *model.Route,
	endpoint model.EndpointKind) *model.SemanticExpectation {

	t.Helper()
	ctx := context.Background()
	cfg, recipes := restoreTestDeps(st)
	pub, err := cfg.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	snap := pub.Probe
	recipe, err := recipes.Resolve(ctx, RecipeQuery{UpstreamID: up.ID, RouteID: rt.ID, Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	_, _, capExp, capPolicy, err := buildL2Expectations(snap, up, rt, endpoint, recipe)
	if err != nil {
		t.Fatal(err)
	}
	identity := recipe.Identity
	revision := capExp.Revision
	execution := model.ProbeExecution{
		ID: "restore-config-error", Trigger: model.TriggerScheduled,
		UpstreamID: up.ID, RouteID: rt.ID, Endpoint: endpoint,
		UpstreamNetworkRevision: revision.UpstreamNetwork, UpstreamCredentialRevision: revision.UpstreamCredential,
		CapabilityPolicySelector: capExp.PolicySelector, ProbeSettingsFingerprint: revision.ProbeSettingsFingerprint,
		EndpointID: revision.EndpointID, EndpointRevision: revision.EndpointRevision,
		ModelCapabilityRevision: revision.ModelCapability, RouteCapabilityRevision: revision.RouteCapability,
		AuthProfileRevision: revision.AuthProfile,
		RecipeBindingUse:    capExp.BindingFacts.Use, RecipeBindingFacts: capExp.BindingFacts,
		RecipeStorage: identity.Storage, RecipeOrigin: identity.Origin, RecipeVersionID: identity.DBVersionID,
		ClientProfileID: identity.ClientProfileID, TemplateID: identity.TemplateID,
		RecipeIdentityRevision: identity.Revision, RecipeBindingRevision: revision.RecipeBindingRevision,
		CapabilityToken: capExp.ObservationToken, EvidenceHash: "restore-config-error-evidence",
		StatusCode: 404, ErrorClass: model.ErrorModelNotFound, Capability: model.CapabilityConfigError,
		Scope: model.ScopeRouteEndpoint, Final: true, ObservationOrder: 7, SentAtMS: 1, DoneAtMS: 2,
	}
	result, err := st.CommitProbeObservation(ctx, &model.ProbeObservation{
		Execution: execution, CapabilityExpectation: capExp, CapabilityPolicy: capPolicy,
	}, health.NewObservationReducer(nil))
	if err != nil {
		t.Fatal(err)
	}
	if result.Capability != model.ApplyCurrent || result.CommittedCapability == nil ||
		result.CommittedCapability.State != model.CapabilityConfigError {
		t.Fatalf("seed commit = %+v", result)
	}
	return capExp
}

// docs/01 §5.2：重启后匹配当前 Observation Token 的 config_error 继续生效，
// token 失配的不恢复；supported / unsupported 不跨重启。
func TestRestoreConfigErrors_MatchingTokenSurvivesRestart(t *testing.T) {
	st := calibrationTestStore(t)
	up, _, rt := seedCalibrationRoute(t, st)
	settings := capSettings{model.DefaultSettings()}
	endpoint := model.EndpointMessages
	commitRouteConfigError(t, st, up, rt, endpoint)

	caps := NewCapabilityRegistry(settings)
	if got := caps.Effective(model.RecipeScopeRoute, rt.ID, endpoint, ""); got != model.CapabilityUnknown {
		t.Fatalf("fresh registry state=%s, want unknown before restore", got)
	}
	cfg, recipes := restoreTestDeps(st)
	n, err := caps.RestoreConfigErrors(context.Background(), st, cfg, recipes)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("restored=%d want 1", n)
	}
	if got := caps.Effective(model.RecipeScopeRoute, rt.ID, endpoint, ""); got != model.CapabilityConfigError {
		t.Fatalf("after restart state=%s, want config_error", got)
	}

	stored, err := st.ListEndpointCapabilitiesByState(context.Background(), model.CapabilityConfigError)
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored rows=%d err=%v", len(stored), err)
	}
	for _, state := range []model.CapabilityState{model.CapabilitySupported, model.CapabilityUnsupported} {
		row := *stored[0]
		row.State = state
		other := NewCapabilityRegistry(settings)
		n, err := other.RestoreConfigErrors(context.Background(), fixedCapabilityRows{&row}, cfg, recipes)
		if err != nil || n != 0 {
			t.Fatalf("%s restored=%d err=%v, want 0", state, n, err)
		}
		if got := other.Effective(model.RecipeScopeRoute, rt.ID, endpoint, ""); got != model.CapabilityUnknown {
			t.Fatalf("%s after restart state=%s, want unknown", state, got)
		}
	}

	updated := *rt
	updated.UpstreamModel = "claude-cal-renamed"
	if err := st.UpdateRouteWithRevision(context.Background(), &updated, rt.Revision); err != nil {
		t.Fatal(err)
	}
	staleCaps := NewCapabilityRegistry(settings)
	staleCfg, staleRecipes := restoreTestDeps(st)
	n, err = staleCaps.RestoreConfigErrors(context.Background(), st, staleCfg, staleRecipes)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("stale token restored=%d want 0", n)
	}
	if got := staleCaps.Effective(model.RecipeScopeRoute, rt.ID, endpoint, ""); got != model.CapabilityUnknown {
		t.Fatalf("stale token state=%s, want unknown", got)
	}
}
