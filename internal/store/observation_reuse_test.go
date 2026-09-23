package store

import (
	"context"
	"testing"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

// Delete + recreate can reuse a SQLite rowid (especially if the sequence is
// reset). NetworkRevision alone restarts at 1, so a late L1 that started on
// the old row must not ApplyCurrent on the new incarnation.
func TestCommitProbeObservation_ReusedIDSameNetworkRevisionIsConfigStale(t *testing.T) {
	st := testStore(t)
	upstream := mkUpstream(t, st, "reuse-a")
	oldID := upstream.ID
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(model.DefaultSettings(), selector)
	if err != nil {
		t.Fatal(err)
	}
	revision := model.ReachabilityRevision{
		NetworkRevision:     upstream.NetworkRevision,
		CreatedAt:           upstream.CreatedAt,
		SettingsFingerprint: revisioncodec.ReachabilitySettingsFingerprint(policy),
	}
	expectation := &model.ReachabilityExpectation{UpstreamID: oldID, PolicySelector: selector, Revision: revision}
	expectation.ObservationToken = revisioncodec.NewReachabilityToken(revision)
	late := minimalReachabilityExecution(t, st, upstream, expectation, "late-reuse", "ev-reuse", 5)
	late.Reachable = false
	late.Success = false
	late.ErrorClass = model.ErrorUnreachable
	late.StatusCode = 0

	if err := st.DeleteUpstream(oldID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.db.Exec(`DELETE FROM sqlite_sequence WHERE name='upstream'`); err != nil {
		t.Fatalf("reset sequence: %v", err)
	}
	if _, err := st.db.Exec(`DELETE FROM sqlite_sequence WHERE name='upstream_endpoint'`); err != nil {
		t.Fatalf("reset endpoint sequence: %v", err)
	}
	// Distinct created_at from the deleted row (same ms would still be a bug
	// if CreatedAt were omitted from the revision check).
	time.Sleep(2 * time.Millisecond)
	neu := &model.Upstream{Name: "reuse-b", BaseURL: "https://b.example", APIKey: "sk-bbbbbbbbbbbb", Enabled: true}
	if err := st.CreateUpstream(neu); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if neu.ID != oldID {
		t.Fatalf("forced reuse failed: new id=%d old=%d", neu.ID, oldID)
	}
	if neu.NetworkRevision != revision.NetworkRevision {
		t.Fatalf("NetworkRevision=%d want %d (incarnation must not rely on a bump)", neu.NetworkRevision, revision.NetworkRevision)
	}
	if neu.CreatedAt == revision.CreatedAt {
		t.Fatal("recreated upstream must have a distinct created_at")
	}
	page, err := st.ListEndpointsPage(context.Background(), model.EndpointFilter{
		UpstreamID: neu.ID, Endpoint: model.EndpointModels,
	})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("new models endpoint=%+v err=%v", page, err)
	}
	late.EndpointID = page.Items[0].ID
	late.EndpointRevision = page.Items[0].Revision

	reducer := &fakeStateReducer{}
	result, err := st.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: late, ReachabilityExpectation: expectation, ReachabilityPolicy: &policy.State,
	}, reducer)
	if err != nil {
		t.Fatal(err)
	}
	if result.Reachability != model.ApplyConfigStale {
		t.Fatalf("disposition=%s want config_stale (CreatedAt incarnation mismatch)", result.Reachability)
	}
	if reducer.reachCalls != 0 {
		t.Fatalf("reducer must not run for stale incarnation, calls=%d", reducer.reachCalls)
	}
}

// Delete + recreate can reuse a SQLite route rowid. CapabilityRevision alone
// restarts at 1, so a late capability observation that started on the old row
// must not ApplyCurrent on the new incarnation (same class of hole as L1
// ReachabilityRevision.CreatedAt).
func TestCommitProbeObservation_ReusedRouteIDSameCapabilityRevisionIsConfigStale(t *testing.T) {
	st := testStore(t)
	upstream := mkUpstream(t, st, "cap-reuse-up")
	modelName := mkModelName(t, st, "cap-reuse-model", model.ProtoAnthropic)
	route := &model.Route{ModelNameID: modelName.ID, UpstreamID: upstream.ID, Enabled: true}
	if err := st.CreateRoute(route); err != nil {
		t.Fatal(err)
	}
	oldID := route.ID
	endpointPage, err := st.ListEndpointsPage(context.Background(), model.EndpointFilter{
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
	capPolicy, err := revisioncodec.BuildCapabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	identity := model.RecipeIdentity{
		Storage: model.RecipeStorageEmbedded, Origin: model.RecipeBasic,
		TemplateID: "builtin:messages", Revision: 1,
	}
	semanticRevision := model.SemanticRevision{
		UpstreamNetwork: upstream.NetworkRevision, UpstreamCredential: upstream.CredentialRevision,
		UpstreamCreatedAt: upstream.CreatedAt,
		EndpointID:        endpoint.ID, EndpointRevision: endpoint.Revision,
		EndpointCreatedAt: endpoint.CreatedAt,
		ModelCapability:   modelName.CapabilityRevision, RouteCapability: route.CapabilityRevision,
		RouteCreatedAt: route.CreatedAt,
		AuthProfile:    endpoint.AuthProfile.Revision, RecipeIdentity: identity,
		RecipeBindingRevision:    1,
		ProbeSettingsFingerprint: revisioncodec.ProbeSettingsFingerprint(capPolicy),
	}
	facts := model.RecipeBindingFacts{Use: model.BindingResolved, ResolvedLayer: model.ResolvedEmbedded}
	capExpectation := &model.SemanticExpectation{
		Target: model.SemanticTarget{
			Scope: model.RecipeScopeRoute, UpstreamID: upstream.ID, RouteID: oldID, Endpoint: model.EndpointMessages,
		},
		PolicySelector: selector, Revision: semanticRevision, BindingFacts: facts,
		ObservationToken: revisioncodec.NewObservationToken(semanticRevision),
	}
	late := model.ProbeExecution{
		ID: "late-cap-reuse", Trigger: model.TriggerScheduled, UpstreamID: upstream.ID, RouteID: oldID,
		UpstreamNetworkRevision: upstream.NetworkRevision, UpstreamCredentialRevision: upstream.CredentialRevision,
		CapabilityPolicySelector: selector, ProbeSettingsFingerprint: semanticRevision.ProbeSettingsFingerprint,
		EndpointID: endpoint.ID, EndpointRevision: endpoint.Revision,
		ModelCapabilityRevision: modelName.CapabilityRevision, RouteCapabilityRevision: route.CapabilityRevision,
		AuthProfileRevision: endpoint.AuthProfile.Revision, Endpoint: model.EndpointMessages,
		RecipeBindingUse: model.BindingResolved, RecipeStorage: identity.Storage, RecipeOrigin: identity.Origin,
		TemplateID: identity.TemplateID, RecipeIdentityRevision: identity.Revision,
		RecipeBindingRevision: semanticRevision.RecipeBindingRevision, RecipeBindingFacts: facts,
		CapabilityToken: capExpectation.ObservationToken, EvidenceHash: "ev-cap-reuse",
		ErrorClass: model.ErrorNone, Capability: model.CapabilitySupported, Scope: model.ScopeRouteEndpoint,
		Reachable: true, Final: true, Success: true, SemanticSeen: true, NormalEndSeen: true,
		ObservationOrder: 30, SentAtMS: 1, DoneAtMS: 2,
	}

	if err := st.DeleteRoute(oldID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.db.Exec(`DELETE FROM sqlite_sequence WHERE name='route'`); err != nil {
		t.Fatalf("reset sequence: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	neu := &model.Route{ModelNameID: modelName.ID, UpstreamID: upstream.ID, Enabled: true}
	if err := st.CreateRoute(neu); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if neu.ID != oldID {
		t.Fatalf("forced reuse failed: new id=%d old=%d", neu.ID, oldID)
	}
	if neu.CapabilityRevision != semanticRevision.RouteCapability {
		t.Fatalf("CapabilityRevision=%d want %d (incarnation must not rely on a bump)",
			neu.CapabilityRevision, semanticRevision.RouteCapability)
	}
	if neu.CreatedAt == semanticRevision.RouteCreatedAt {
		t.Fatal("recreated route must have a distinct created_at")
	}

	reducer := &fakeStateReducer{allowCap: true}
	result, err := st.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: late, CapabilityExpectation: capExpectation, CapabilityPolicy: &capPolicy.State,
	}, reducer)
	if err != nil {
		t.Fatal(err)
	}
	if result.Capability != model.ApplyConfigStale {
		t.Fatalf("disposition=%s want config_stale (RouteCreatedAt incarnation mismatch)", result.Capability)
	}
	if reducer.capCalls != 0 {
		t.Fatalf("capability reducer must not run for stale incarnation, calls=%d", reducer.capCalls)
	}
}

// Delete + recreate can reuse a SQLite upstream rowid (and, with a reset
// sequence, the same EndpointID). Network/Credential revisions alone restart
// at 1, so a late upstream-scope capability observation that started on the
// old row must not ApplyCurrent on the new incarnation.
func TestCommitProbeObservation_ReusedUpstreamIDSameNetworkRevisionCapabilityIsConfigStale(t *testing.T) {
	st := testStore(t)
	upstream := mkUpstream(t, st, "up-cap-reuse-a")
	oldID := upstream.ID
	endpointPage, err := st.ListEndpointsPage(context.Background(), model.EndpointFilter{
		UpstreamID: oldID, Endpoint: model.EndpointModels,
	})
	if err != nil || len(endpointPage.Items) != 1 {
		t.Fatalf("models endpoint=%+v err=%v", endpointPage, err)
	}
	endpoint := endpointPage.Items[0]
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	settings := model.DefaultSettings()
	capPolicy, err := revisioncodec.BuildCapabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	identity := model.RecipeIdentity{
		Storage: model.RecipeStorageEmbedded, Origin: model.RecipeBasic,
		TemplateID: "builtin:models", Revision: 1,
	}
	semanticRevision := model.SemanticRevision{
		UpstreamNetwork: upstream.NetworkRevision, UpstreamCredential: upstream.CredentialRevision,
		UpstreamCreatedAt: upstream.CreatedAt,
		EndpointID:        endpoint.ID, EndpointRevision: endpoint.Revision,
		EndpointCreatedAt: endpoint.CreatedAt,
		AuthProfile:       endpoint.AuthProfile.Revision, RecipeIdentity: identity,
		RecipeBindingRevision:    1,
		ProbeSettingsFingerprint: revisioncodec.ProbeSettingsFingerprint(capPolicy),
	}
	facts := model.RecipeBindingFacts{Use: model.BindingResolved, ResolvedLayer: model.ResolvedEmbedded}
	capExpectation := &model.SemanticExpectation{
		Target: model.SemanticTarget{
			Scope: model.RecipeScopeUpstream, UpstreamID: oldID, Endpoint: model.EndpointModels,
		},
		PolicySelector: selector, Revision: semanticRevision, BindingFacts: facts,
		ObservationToken: revisioncodec.NewObservationToken(semanticRevision),
	}
	late := model.ProbeExecution{
		ID: "late-up-cap-reuse", Trigger: model.TriggerScheduled, UpstreamID: oldID,
		UpstreamNetworkRevision: upstream.NetworkRevision, UpstreamCredentialRevision: upstream.CredentialRevision,
		CapabilityPolicySelector: selector, ProbeSettingsFingerprint: semanticRevision.ProbeSettingsFingerprint,
		EndpointID: endpoint.ID, EndpointRevision: endpoint.Revision,
		AuthProfileRevision: endpoint.AuthProfile.Revision, Endpoint: model.EndpointModels,
		RecipeBindingUse: model.BindingResolved, RecipeStorage: identity.Storage, RecipeOrigin: identity.Origin,
		TemplateID: identity.TemplateID, RecipeIdentityRevision: identity.Revision,
		RecipeBindingRevision: semanticRevision.RecipeBindingRevision, RecipeBindingFacts: facts,
		CapabilityToken: capExpectation.ObservationToken, EvidenceHash: "ev-up-cap-reuse",
		ErrorClass: model.ErrorNone, Capability: model.CapabilitySupported, Scope: model.ScopeUpstreamEndpoint,
		Reachable: true, Final: true, Success: true, SemanticSeen: true, NormalEndSeen: true,
		ObservationOrder: 40, SentAtMS: 1, DoneAtMS: 2,
	}

	if err := st.DeleteUpstream(oldID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.db.Exec(`DELETE FROM sqlite_sequence WHERE name='upstream'`); err != nil {
		t.Fatalf("reset upstream sequence: %v", err)
	}
	if _, err := st.db.Exec(`DELETE FROM sqlite_sequence WHERE name='upstream_endpoint'`); err != nil {
		t.Fatalf("reset endpoint sequence: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	neu := &model.Upstream{Name: "up-cap-reuse-b", BaseURL: "https://b.example", APIKey: "sk-bbbbbbbbbbbb", Enabled: true}
	if err := st.CreateUpstream(neu); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if neu.ID != oldID {
		t.Fatalf("forced reuse failed: new id=%d old=%d", neu.ID, oldID)
	}
	if neu.NetworkRevision != semanticRevision.UpstreamNetwork || neu.CredentialRevision != semanticRevision.UpstreamCredential {
		t.Fatalf("revisions network=%d credential=%d want %d/%d (incarnation must not rely on a bump)",
			neu.NetworkRevision, neu.CredentialRevision, semanticRevision.UpstreamNetwork, semanticRevision.UpstreamCredential)
	}
	if neu.CreatedAt == semanticRevision.UpstreamCreatedAt {
		t.Fatal("recreated upstream must have a distinct created_at")
	}
	page, err := st.ListEndpointsPage(context.Background(), model.EndpointFilter{
		UpstreamID: neu.ID, Endpoint: model.EndpointModels,
	})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("new models endpoint=%+v err=%v", page, err)
	}
	if page.Items[0].ID != semanticRevision.EndpointID {
		t.Fatalf("EndpointID=%d want %d (sequence reset must also reuse endpoint id)",
			page.Items[0].ID, semanticRevision.EndpointID)
	}
	late.EndpointID = page.Items[0].ID
	late.EndpointRevision = page.Items[0].Revision

	reducer := &fakeStateReducer{allowCap: true}
	result, err := st.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: late, CapabilityExpectation: capExpectation, CapabilityPolicy: &capPolicy.State,
	}, reducer)
	if err != nil {
		t.Fatal(err)
	}
	if result.Capability != model.ApplyConfigStale {
		t.Fatalf("disposition=%s want config_stale (UpstreamCreatedAt incarnation mismatch)", result.Capability)
	}
	if reducer.capCalls != 0 {
		t.Fatalf("capability reducer must not run for stale incarnation, calls=%d", reducer.capCalls)
	}
}

// Delete + recreate can reuse a SQLite endpoint rowid under the same still-
// living upstream (especially if the sequence is reset). EndpointRevision alone
// restarts at 1 and UpstreamCreatedAt is unchanged, so a late capability
// observation that started on the old endpoint row must not ApplyCurrent on
// the new incarnation.
func TestCommitProbeObservation_ReusedEndpointIDSameRevisionIsConfigStale(t *testing.T) {
	st := testStore(t)
	upstream := disabledUpstreamWithEndpoints(t, st, "ep-cap-reuse")
	endpoint := endpointOf(t, st, upstream.ID, model.EndpointModels)
	oldEndpointID := endpoint.ID
	selector := model.EvidencePolicySelector{Kind: model.EvidenceL1, Endpoint: model.EndpointModels}
	settings := model.DefaultSettings()
	capPolicy, err := revisioncodec.BuildCapabilityEvidencePolicy(settings, selector)
	if err != nil {
		t.Fatal(err)
	}
	identity := model.RecipeIdentity{
		Storage: model.RecipeStorageEmbedded, Origin: model.RecipeBasic,
		TemplateID: "builtin:models", Revision: 1,
	}
	semanticRevision := model.SemanticRevision{
		UpstreamNetwork: upstream.NetworkRevision, UpstreamCredential: upstream.CredentialRevision,
		UpstreamCreatedAt: upstream.CreatedAt,
		EndpointID:        endpoint.ID, EndpointRevision: endpoint.Revision,
		EndpointCreatedAt: endpoint.CreatedAt,
		AuthProfile:       endpoint.AuthProfile.Revision, RecipeIdentity: identity,
		RecipeBindingRevision:    1,
		ProbeSettingsFingerprint: revisioncodec.ProbeSettingsFingerprint(capPolicy),
	}
	facts := model.RecipeBindingFacts{Use: model.BindingResolved, ResolvedLayer: model.ResolvedEmbedded}
	capExpectation := &model.SemanticExpectation{
		Target: model.SemanticTarget{
			Scope: model.RecipeScopeUpstream, UpstreamID: upstream.ID, Endpoint: model.EndpointModels,
		},
		PolicySelector: selector, Revision: semanticRevision, BindingFacts: facts,
		ObservationToken: revisioncodec.NewObservationToken(semanticRevision),
	}
	late := model.ProbeExecution{
		ID: "late-ep-cap-reuse", Trigger: model.TriggerScheduled, UpstreamID: upstream.ID,
		UpstreamNetworkRevision: upstream.NetworkRevision, UpstreamCredentialRevision: upstream.CredentialRevision,
		CapabilityPolicySelector: selector, ProbeSettingsFingerprint: semanticRevision.ProbeSettingsFingerprint,
		EndpointID: endpoint.ID, EndpointRevision: endpoint.Revision,
		AuthProfileRevision: endpoint.AuthProfile.Revision, Endpoint: model.EndpointModels,
		RecipeBindingUse: model.BindingResolved, RecipeStorage: identity.Storage, RecipeOrigin: identity.Origin,
		TemplateID: identity.TemplateID, RecipeIdentityRevision: identity.Revision,
		RecipeBindingRevision: semanticRevision.RecipeBindingRevision, RecipeBindingFacts: facts,
		CapabilityToken: capExpectation.ObservationToken, EvidenceHash: "ev-ep-cap-reuse",
		ErrorClass: model.ErrorNone, Capability: model.CapabilitySupported, Scope: model.ScopeUpstreamEndpoint,
		Reachable: true, Final: true, Success: true, SemanticSeen: true, NormalEndSeen: true,
		ObservationOrder: 50, SentAtMS: 1, DoneAtMS: 2,
	}

	// Clear every endpoint so a sequence reset can reuse the original models id
	// while the parent upstream row (and UpstreamCreatedAt) stays put.
	for _, kind := range []model.EndpointKind{
		model.EndpointModels, model.EndpointMessages, model.EndpointResponses,
		model.EndpointChatCompletions, model.EndpointCountTokens,
	} {
		row := endpointOf(t, st, upstream.ID, kind)
		if err := st.DeleteEndpoint(row.ID, row.Revision); err != nil {
			t.Fatalf("delete %s: %v", kind, err)
		}
	}
	if _, err := st.db.Exec(`DELETE FROM sqlite_sequence WHERE name='upstream_endpoint'`); err != nil {
		t.Fatalf("reset endpoint sequence: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	neu := &model.UpstreamEndpoint{
		UpstreamID: upstream.ID, Kind: model.EndpointModels,
		URLMode: model.EndpointURLCanonical,
		AuthProfile: model.EndpointAuthProfile{
			Mode: model.AuthModeXAPIKey, SecretRef: "upstream_api_key", Revision: 1,
		},
	}
	if err := st.CreateEndpoint(neu); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if neu.ID != oldEndpointID {
		t.Fatalf("forced reuse failed: new id=%d old=%d", neu.ID, oldEndpointID)
	}
	if neu.Revision != semanticRevision.EndpointRevision {
		t.Fatalf("EndpointRevision=%d want %d (incarnation must not rely on a bump)",
			neu.Revision, semanticRevision.EndpointRevision)
	}
	if neu.CreatedAt == semanticRevision.EndpointCreatedAt {
		t.Fatal("recreated endpoint must have a distinct created_at")
	}
	reread, err := st.GetUpstream(upstream.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reread.CreatedAt != semanticRevision.UpstreamCreatedAt {
		t.Fatalf("parent UpstreamCreatedAt changed: %d want %d", reread.CreatedAt, semanticRevision.UpstreamCreatedAt)
	}

	reducer := &fakeStateReducer{allowCap: true}
	result, err := st.CommitProbeObservation(context.Background(), &model.ProbeObservation{
		Execution: late, CapabilityExpectation: capExpectation, CapabilityPolicy: &capPolicy.State,
	}, reducer)
	if err != nil {
		t.Fatal(err)
	}
	if result.Capability != model.ApplyConfigStale {
		t.Fatalf("disposition=%s want config_stale (EndpointCreatedAt incarnation mismatch)", result.Capability)
	}
	if reducer.capCalls != 0 {
		t.Fatalf("capability reducer must not run for stale incarnation, calls=%d", reducer.capCalls)
	}
}
