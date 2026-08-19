package store

import (
	"context"
	"errors"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

type fakeStateReducer struct {
	reachCalls int
	capCalls   int
	panicReach bool
	allowCap   bool
}

func (reducer *fakeStateReducer) ReduceReachability(_ *model.UpstreamReachability, execution model.ProbeExecution, policy model.ReachabilityReductionPolicy) (*model.UpstreamReachability, error) {
	reducer.reachCalls++
	if reducer.panicReach {
		panic("fake reducer panic")
	}
	return &model.UpstreamReachability{
		UpstreamID:              execution.UpstreamID,
		PolicySelector:          execution.ReachabilityPolicySelector,
		State:                   model.ReachabilityReachable,
		ConsecutiveOK:           policy.ReachableThreshold,
		ObservedNetworkRevision: execution.UpstreamNetworkRevision,
		SettingsFingerprint:     execution.ReachabilitySettingsFingerprint,
		ObservationToken:        execution.ReachabilityToken,
		LastObservationOrder:    execution.ObservationOrder,
	}, nil
}

func (reducer *fakeStateReducer) ReduceCapability(_ *model.EndpointCapability, _ model.ProbeExecution, _ model.CapabilityReductionPolicy) (*model.EndpointCapability, error) {
	reducer.capCalls++
	if reducer.allowCap {
		return &model.EndpointCapability{State: model.CapabilitySupported}, nil
	}
	return nil, errors.New("capability should not be called")
}

func TestCommitProbeObservationIsAtomicIdempotentAndPanicSafe(t *testing.T) {
	store := testStore(t)
	upstream := mkUpstream(t, store, "observation")
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(model.DefaultSettings(), selector)
	if err != nil {
		t.Fatal(err)
	}
	revision := model.ReachabilityRevision{
		NetworkRevision:     upstream.NetworkRevision,
		SettingsFingerprint: revisioncodec.ReachabilitySettingsFingerprint(policy),
	}
	expectation := &model.ReachabilityExpectation{
		UpstreamID: upstream.ID, PolicySelector: selector, Revision: revision,
		ObservationToken: revisioncodec.NewReachabilityToken(revision),
	}
	execution := minimalReachabilityExecution(t, store, upstream, expectation, "exec-1", "evidence-1", 1)
	reducer := &fakeStateReducer{}
	result, err := store.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: execution, ReachabilityExpectation: expectation, ReachabilityPolicy: &policy.State,
	}, reducer)
	if err != nil {
		t.Fatal(err)
	}
	if result.Reachability != model.ApplyCurrent || result.Capability != model.ApplyNotApplicable || reducer.reachCalls != 1 {
		t.Fatalf("result=%+v calls=%d", result, reducer.reachCalls)
	}
	if result.CommittedReachability == nil || result.CommittedReachability.LastObservationOrder != 1 {
		t.Fatalf("committed reachability = %+v", result.CommittedReachability)
	}

	replayed, err := store.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: execution, ReachabilityExpectation: expectation, ReachabilityPolicy: &policy.State,
	}, reducer)
	if err != nil || reducer.reachCalls != 1 || replayed.Reachability != model.ApplyCurrent {
		t.Fatalf("idempotent replay=%+v err=%v calls=%d", replayed, err, reducer.reachCalls)
	}
	execution.EvidenceHash = "different-evidence"
	if _, err := store.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: execution, ReachabilityExpectation: expectation, ReachabilityPolicy: &policy.State,
	}, reducer); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different evidence error = %v", err)
	}

	panicExecution := minimalReachabilityExecution(t, store, upstream, expectation, "exec-panic", "evidence-panic", 2)
	panicReducer := &fakeStateReducer{panicReach: true}
	if _, err := store.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: panicExecution, ReachabilityExpectation: expectation, ReachabilityPolicy: &policy.State,
	}, panicReducer); err == nil {
		t.Fatal("reducer panic must become an error")
	}
	var stored int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM probe_execution WHERE id='exec-panic'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Fatal("reducer panic committed execution")
	}
}

func TestCommitProbeObservationAppliesReachabilityWhenCapabilityIsConfigStale(t *testing.T) {
	store := testStore(t)
	upstream := mkUpstream(t, store, "observation-partial")
	modelName := mkModelName(t, store, "observation-partial-model", model.ProtoAnthropic)
	route := &model.Route{ModelNameID: modelName.ID, UpstreamID: upstream.ID, Enabled: true}
	if err := store.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	endpointPage, err := store.ListEndpointsPage(context.Background(), model.EndpointFilter{
		UpstreamID: upstream.ID, Endpoint: model.EndpointMessages,
	})
	if err != nil || len(endpointPage.Items) != 1 {
		t.Fatalf("messages endpoint=%+v err=%v", endpointPage, err)
	}
	endpoint := endpointPage.Items[0]
	selector := model.EvidencePolicySelector{
		Kind: model.EvidenceL2, Endpoint: model.EndpointMessages, TimeoutProfile: model.TimeoutL2Standard,
	}
	settings := model.DefaultSettings()
	reachPolicy, err := revisioncodec.BuildReachabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	capPolicy, err := revisioncodec.BuildCapabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	reachRevision := model.ReachabilityRevision{
		NetworkRevision:     upstream.NetworkRevision,
		SettingsFingerprint: revisioncodec.ReachabilitySettingsFingerprint(reachPolicy),
	}
	reachExpectation := &model.ReachabilityExpectation{
		UpstreamID: upstream.ID, PolicySelector: selector, Revision: reachRevision,
		ObservationToken: revisioncodec.NewReachabilityToken(reachRevision),
	}
	identity := model.RecipeIdentity{
		Storage: model.RecipeStorageEmbedded, Origin: model.RecipeBasic,
		TemplateID: "builtin:messages", Revision: 1,
	}
	semanticRevision := model.SemanticRevision{
		UpstreamNetwork: upstream.NetworkRevision, UpstreamCredential: upstream.CredentialRevision,
		EndpointID: endpoint.ID, EndpointRevision: endpoint.Revision,
		ModelCapability: modelName.CapabilityRevision, RouteCapability: route.CapabilityRevision,
		AuthProfile: endpoint.AuthProfile.Revision, RecipeIdentity: identity,
		RecipeBindingRevision:    1,
		ProbeSettingsFingerprint: revisioncodec.ProbeSettingsFingerprint(capPolicy),
	}
	facts := model.RecipeBindingFacts{Use: model.BindingResolved, ResolvedLayer: model.ResolvedEmbedded}
	capExpectation := &model.SemanticExpectation{
		Target:         model.SemanticTarget{Scope: model.RecipeScopeRoute, UpstreamID: upstream.ID, RouteID: route.ID, Endpoint: model.EndpointMessages},
		PolicySelector: selector, Revision: semanticRevision, BindingFacts: facts,
		ObservationToken: revisioncodec.NewObservationToken(semanticRevision),
	}
	execution := model.ProbeExecution{
		ID: "partial", Trigger: model.TriggerScheduled, UpstreamID: upstream.ID, RouteID: route.ID,
		UpstreamNetworkRevision: upstream.NetworkRevision, UpstreamCredentialRevision: upstream.CredentialRevision,
		ReachabilityPolicySelector: selector, CapabilityPolicySelector: selector,
		ReachabilitySettingsFingerprint: reachRevision.SettingsFingerprint,
		ProbeSettingsFingerprint:        semanticRevision.ProbeSettingsFingerprint,
		EndpointID:                      endpoint.ID, EndpointRevision: endpoint.Revision,
		ModelCapabilityRevision: modelName.CapabilityRevision, RouteCapabilityRevision: route.CapabilityRevision,
		AuthProfileRevision: endpoint.AuthProfile.Revision, Endpoint: model.EndpointMessages,
		RecipeBindingUse: model.BindingResolved, RecipeStorage: identity.Storage, RecipeOrigin: identity.Origin,
		TemplateID: identity.TemplateID, RecipeIdentityRevision: identity.Revision,
		RecipeBindingRevision: semanticRevision.RecipeBindingRevision, RecipeBindingFacts: facts,
		ReachabilityToken: reachExpectation.ObservationToken, CapabilityToken: capExpectation.ObservationToken,
		EvidenceHash: "partial-evidence", ErrorClass: model.ErrorNone,
		Capability: model.CapabilitySupported, Scope: model.ScopeRouteEndpoint,
		Reachable: true, Final: true, Success: true, SemanticSeen: true, NormalEndSeen: true,
		ObservationOrder: 20, SentAtMS: 1, DoneAtMS: 2,
	}

	// The actual network evidence remains current, but the endpoint revision in
	// the capability expectation is deliberately stale.
	capExpectation.Revision.EndpointRevision++
	capExpectation.ObservationToken = revisioncodec.NewObservationToken(capExpectation.Revision)
	execution.EndpointRevision = capExpectation.Revision.EndpointRevision
	execution.CapabilityToken = capExpectation.ObservationToken
	reducer := &fakeStateReducer{allowCap: true}
	result, err := store.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: execution, ReachabilityExpectation: reachExpectation, CapabilityExpectation: capExpectation,
		ReachabilityPolicy: &reachPolicy.State, CapabilityPolicy: &capPolicy.State,
	}, reducer)
	if err != nil {
		t.Fatal(err)
	}
	if result.Reachability != model.ApplyCurrent || result.Capability != model.ApplyConfigStale {
		t.Fatalf("partial result = %+v", result)
	}
	if reducer.reachCalls != 1 || reducer.capCalls != 0 {
		t.Fatalf("reducer calls reach=%d cap=%d", reducer.reachCalls, reducer.capCalls)
	}

	currentExpectation := &model.SemanticExpectation{
		Target: capExpectation.Target, PolicySelector: selector, Revision: semanticRevision,
		BindingFacts: facts, ObservationToken: revisioncodec.NewObservationToken(semanticRevision),
	}
	currentExecution := execution
	currentExecution.ID = "current-capability"
	currentExecution.EvidenceHash = "current-capability-evidence"
	currentExecution.ObservationOrder = 21
	currentExecution.EndpointRevision = endpoint.Revision
	currentExecution.CapabilityToken = currentExpectation.ObservationToken
	currentExecution.DoneAtMS = 3
	result, err = store.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: currentExecution, ReachabilityExpectation: reachExpectation, CapabilityExpectation: currentExpectation,
		ReachabilityPolicy: &reachPolicy.State, CapabilityPolicy: &capPolicy.State,
	}, reducer)
	if err != nil {
		t.Fatal(err)
	}
	if result.Reachability != model.ApplyCurrent || result.Capability != model.ApplyCurrent ||
		result.CommittedCapability == nil || result.CommittedCapability.State != model.CapabilitySupported {
		t.Fatalf("current result = %+v", result)
	}
	if reducer.reachCalls != 2 || reducer.capCalls != 1 {
		t.Fatalf("current reducer calls reach=%d cap=%d", reducer.reachCalls, reducer.capCalls)
	}

	recipeID, err := store.CreateRecipe(model.RecipeScopeRoute, route.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	version := &model.ProbeRecipeVersion{
		RecipeID: recipeID, Origin: model.RecipeManual, Method: "POST",
		Body:       []byte(`{"model":"{{UPSTREAM_MODEL}}","max_tokens":1,"messages":[{"role":"user","content":"1"}]}`),
		BodyIsText: true, TimeoutProfile: model.TimeoutL2Standard,
	}
	if err := store.AddRecipeVersion(version, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE probe_recipe SET status='published',published_version_id=?,
		active_binding_revision=active_binding_revision+1 WHERE id=?`, version.ID, recipeID); err != nil {
		t.Fatal(err)
	}
	bindingStale := currentExecution
	bindingStale.ID = "binding-stale"
	bindingStale.EvidenceHash = "binding-stale-evidence"
	bindingStale.ObservationOrder = 22
	bindingStale.DoneAtMS = 4
	result, err = store.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: bindingStale, ReachabilityExpectation: reachExpectation, CapabilityExpectation: currentExpectation,
		ReachabilityPolicy: &reachPolicy.State, CapabilityPolicy: &capPolicy.State,
	}, reducer)
	if err != nil {
		t.Fatal(err)
	}
	if result.Reachability != model.ApplyCurrent || result.Capability != model.ApplyConfigStale || reducer.capCalls != 1 {
		t.Fatalf("new higher-priority binding result=%+v capCalls=%d", result, reducer.capCalls)
	}
}

func TestCommitProbeObservationSeparatesConfigStaleFromSuperseded(t *testing.T) {
	store := testStore(t)
	upstream := mkUpstream(t, store, "observation-order")
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(model.DefaultSettings(), selector)
	if err != nil {
		t.Fatal(err)
	}
	revision := model.ReachabilityRevision{
		NetworkRevision:     upstream.NetworkRevision,
		SettingsFingerprint: revisioncodec.ReachabilitySettingsFingerprint(policy),
	}
	expectation := &model.ReachabilityExpectation{UpstreamID: upstream.ID, PolicySelector: selector, Revision: revision}
	expectation.ObservationToken = revisioncodec.NewReachabilityToken(revision)
	reducer := &fakeStateReducer{}
	newer := minimalReachabilityExecution(t, store, upstream, expectation, "newer", "newer-evidence", 10)
	if _, err := store.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: newer, ReachabilityExpectation: expectation, ReachabilityPolicy: &policy.State,
	}, reducer); err != nil {
		t.Fatal(err)
	}
	older := minimalReachabilityExecution(t, store, upstream, expectation, "older", "older-evidence", 9)
	result, err := store.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: older, ReachabilityExpectation: expectation, ReachabilityPolicy: &policy.State,
	}, reducer)
	if err != nil || result.Reachability != model.ApplySuperseded || reducer.reachCalls != 1 {
		t.Fatalf("older result=%+v err=%v calls=%d", result, err, reducer.reachCalls)
	}

	staleRevision := revision
	staleRevision.NetworkRevision++
	stale := &model.ReachabilityExpectation{UpstreamID: upstream.ID, PolicySelector: selector, Revision: staleRevision}
	stale.ObservationToken = revisioncodec.NewReachabilityToken(staleRevision)
	staleExecution := minimalReachabilityExecution(t, store, upstream, stale, "stale", "stale-evidence", 11)
	result, err = store.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: staleExecution, ReachabilityExpectation: stale, ReachabilityPolicy: &policy.State,
	}, reducer)
	if err != nil || result.Reachability != model.ApplyConfigStale || reducer.reachCalls != 1 {
		t.Fatalf("stale result=%+v err=%v calls=%d", result, err, reducer.reachCalls)
	}
}

func minimalReachabilityExecution(t *testing.T, store *Store, upstream *model.Upstream, expectation *model.ReachabilityExpectation, id, evidence string, order int64) model.ProbeExecution {
	t.Helper()
	page, err := store.ListEndpointsPage(context.Background(), model.EndpointFilter{
		UpstreamID: upstream.ID, Endpoint: model.EndpointModels,
	})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("models endpoint = %+v err=%v", page, err)
	}
	endpoint := page.Items[0]
	return model.ProbeExecution{
		ID: id, Trigger: model.TriggerScheduled, UpstreamID: upstream.ID,
		UpstreamNetworkRevision: upstream.NetworkRevision, UpstreamCredentialRevision: upstream.CredentialRevision,
		ReachabilityPolicySelector:      expectation.PolicySelector,
		ReachabilitySettingsFingerprint: expectation.Revision.SettingsFingerprint,
		EndpointID:                      endpoint.ID, EndpointRevision: endpoint.Revision, AuthProfileRevision: endpoint.AuthProfile.Revision,
		Endpoint: model.EndpointModels, RecipeBindingUse: model.BindingResolved,
		RecipeStorage: model.RecipeStorageEmbedded, RecipeOrigin: model.RecipeBasic,
		TemplateID: "builtin:models", RecipeIdentityRevision: 1,
		ReachabilityToken: expectation.ObservationToken, EvidenceHash: evidence,
		ErrorClass: model.ErrorNone, Capability: model.CapabilityUnknown,
		Scope: model.ScopeUpstreamReachability, Reachable: true, Final: true, Success: true,
		ObservationOrder: order, SentAtMS: order, DoneAtMS: order + 1,
	}
}
