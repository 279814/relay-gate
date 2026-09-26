package livecfg

// ProbeSnapshot 是探活专用的不可变配置快照（§4.9）。
//
// 与真实流量的 routing snapshot 同代发布；不含 Secret/API Key/legacy URL 明文。
// 开始 expectation 必须从同一份快照计算。

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/store"
)

// ErrProbeSnapshotUnavailable 表示配置已持久化但 Probe 快照尚未激活。
//
// Invalidate 后 Refresh 失败时真实转发仍可读旧 routing snapshot，但 Probe
// 不得发送公网请求。
var ErrProbeSnapshotUnavailable = errors.New("config_snapshot_unavailable")

// ProbeSnapshot 见 §4.9。发布后只读。
type ProbeSnapshot struct {
	Generation              uint64
	LoadedAt                time.Time
	Upstreams               map[int64]*model.ProbeUpstreamConfig
	ModelNames              map[int64]*model.ModelName
	Routes                  map[int64]*model.Route
	Settings                model.Settings
	SettingsRowRevision     int64
	Endpoints               map[int64]map[model.EndpointKind]*model.UpstreamEndpoint
	LegacyFullURLs          map[int64]*model.LegacyFullURL
	Recipes                 map[int64]*model.ProbeRecipe
	RecipeVersions          map[int64]*model.ProbeRecipeVersion
	ClientProfilesByID      map[int64]*model.ClientProbeProfile
	TestedClientProfiles    map[int64]map[model.EndpointKind]*model.ClientProbeProfile
	SecretRevisions         map[string]model.SecretRevision
	EndpointSecretRefs      map[int64][]model.RequiredSecretRef
	RecipeVersionSecretRefs map[int64][]model.RequiredSecretRef
	ClientProfileSecretRefs map[int64][]model.RequiredSecretRef
}

// PublishedConfig 是同代 routing + Probe 快照。
type PublishedConfig struct {
	Generation uint64
	Routing    *router.Snapshot
	Probe      *ProbeSnapshot
	Settings   model.Settings
	RunState   store.RunState
}

// Endpoint 取快照内的 Endpoint 配置，满足 outbound.EndpointConfigSource。
func (s *ProbeSnapshot) Endpoint(_ context.Context, upstreamID int64, endpoint model.EndpointKind) (*model.UpstreamEndpoint, error) {
	if s == nil {
		return nil, ErrProbeSnapshotUnavailable
	}
	byKind := s.Endpoints[upstreamID]
	if byKind == nil {
		return nil, store.ErrNotFound
	}
	ep := byKind[endpoint]
	if ep == nil {
		return nil, store.ErrNotFound
	}
	copyValue := *ep
	return &copyValue, nil
}

// ReachabilityExpectation 从本快照构造站级可达性期望。
func (s *ProbeSnapshot) ReachabilityExpectation(upstreamID int64, selector model.EvidencePolicySelector) (model.ReachabilityExpectation, error) {
	if s == nil {
		return model.ReachabilityExpectation{}, ErrProbeSnapshotUnavailable
	}
	up := s.Upstreams[upstreamID]
	if up == nil {
		return model.ReachabilityExpectation{}, fmt.Errorf("%w: upstream %d", store.ErrNotFound, upstreamID)
	}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(s.Settings, selector)
	if err != nil {
		return model.ReachabilityExpectation{}, err
	}
	revision := model.ReachabilityRevision{
		NetworkRevision:     up.NetworkRevision,
		CreatedAt:           up.CreatedAt,
		SettingsFingerprint: revisioncodec.ReachabilitySettingsFingerprint(policy),
	}
	return model.ReachabilityExpectation{
		UpstreamID:       upstreamID,
		PolicySelector:   selector,
		Revision:         revision,
		ObservationToken: revisioncodec.NewReachabilityToken(revision),
	}, nil
}

// SemanticExpectation 从本快照构造端点能力期望。
func (s *ProbeSnapshot) SemanticExpectation(target model.SemanticTarget, identity model.RecipeIdentity,
	facts model.RecipeBindingFacts, selector model.EvidencePolicySelector) (model.SemanticExpectation, error) {

	if s == nil {
		return model.SemanticExpectation{}, ErrProbeSnapshotUnavailable
	}
	if err := target.Validate(); err != nil {
		return model.SemanticExpectation{}, err
	}
	up := s.Upstreams[target.UpstreamID]
	if up == nil {
		return model.SemanticExpectation{}, fmt.Errorf("%w: upstream %d", store.ErrNotFound, target.UpstreamID)
	}
	byKind := s.Endpoints[target.UpstreamID]
	if byKind == nil || byKind[target.Endpoint] == nil {
		return model.SemanticExpectation{}, fmt.Errorf("%w: endpoint %s", store.ErrNotFound, target.Endpoint)
	}
	endpoint := byKind[target.Endpoint]
	policy, err := revisioncodec.BuildCapabilityEvidencePolicy(s.Settings, selector)
	if err != nil {
		return model.SemanticExpectation{}, err
	}

	revision := model.SemanticRevision{
		UpstreamNetwork:          up.NetworkRevision,
		UpstreamCredential:       up.CredentialRevision,
		UpstreamCreatedAt:        up.CreatedAt,
		EndpointID:               endpoint.ID,
		EndpointRevision:         endpoint.Revision,
		EndpointCreatedAt:        endpoint.CreatedAt,
		AuthProfile:              endpoint.AuthProfile.Revision,
		RecipeIdentity:           identity,
		RecipeBindingRevision:    factsBindingRevision(facts, identity),
		ProbeSettingsFingerprint: revisioncodec.ProbeSettingsFingerprint(policy),
		ProbeSecrets:             s.secretRevisionsFor(target, identity, facts),
		RequestTransform:         0,
	}
	if target.Scope == model.RecipeScopeRoute {
		route := s.Routes[target.RouteID]
		if route == nil {
			return model.SemanticExpectation{}, fmt.Errorf("%w: route %d", store.ErrNotFound, target.RouteID)
		}
		revision.RouteCapability = route.CapabilityRevision
		revision.RouteCreatedAt = route.CreatedAt
		if mn := s.ModelNames[route.ModelNameID]; mn != nil {
			revision.ModelCapability = mn.CapabilityRevision
		}
	}
	return model.SemanticExpectation{
		Target:           target,
		PolicySelector:   selector,
		Revision:         revision,
		BindingFacts:     facts,
		ObservationToken: revisioncodec.NewObservationToken(revision),
	}, nil
}

func factsBindingRevision(facts model.RecipeBindingFacts, identity model.RecipeIdentity) int64 {
	switch facts.ResolvedLayer {
	case model.ResolvedRoute:
		return facts.RouteBindingRevision
	case model.ResolvedUpstream:
		return facts.UpstreamBindingRevision
	case model.ResolvedProfile:
		return facts.TestedProfileRevision
	case model.ResolvedEmbedded:
		return identity.Revision
	default:
		return identity.Revision
	}
}

func (s *ProbeSnapshot) secretRevisionsFor(target model.SemanticTarget, identity model.RecipeIdentity,
	facts model.RecipeBindingFacts) []model.SecretRevision {

	var refs []model.RequiredSecretRef
	switch {
	case identity.Storage == model.RecipeStorageDB && identity.DBVersionID > 0:
		refs = append(refs, s.RecipeVersionSecretRefs[identity.DBVersionID]...)
	case identity.Storage == model.RecipeStorageProfile && identity.ClientProfileID > 0:
		refs = append(refs, s.ClientProfileSecretRefs[identity.ClientProfileID]...)
	}
	if ep := s.Endpoints[target.UpstreamID][target.Endpoint]; ep != nil {
		refs = append(refs, s.EndpointSecretRefs[ep.ID]...)
	}
	_ = facts // 选择层已体现在 identity；refs 来自实际绑定。

	seen := map[string]model.SecretRevision{}
	for _, ref := range refs {
		if rev, ok := s.SecretRevisions[ref.Name]; ok {
			seen[ref.Name] = rev
			continue
		}
		seen[ref.Name] = model.SecretRevision{Name: ref.Name, ID: ref.BoundSecretID}
	}
	out := make([]model.SecretRevision, 0, len(seen))
	for _, rev := range seen {
		out = append(out, rev)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// buildPublishedConfig 从一份 ConfigBundle 构建同代 PublishedConfig。
func buildPublishedConfig(bundle *store.ConfigBundle, generation uint64, loadedAt time.Time) (*PublishedConfig, error) {
	if bundle == nil {
		return nil, model.WrapValidation("config bundle 不能为空")
	}
	settings := bundle.Settings
	if err := settings.Validate(); err != nil {
		// 与 store.usableSettings 同一口径：手改库或降级写出的超时不能进转发，
		// 也不能只在快照里换成默认值、提交时仍用原值。那样指纹对不上，
		// 每次探活都是 config_stale。
		settings = model.DefaultSettings()
	}

	probe := &ProbeSnapshot{
		Generation:              generation,
		LoadedAt:                loadedAt,
		Upstreams:               map[int64]*model.ProbeUpstreamConfig{},
		ModelNames:              map[int64]*model.ModelName{},
		Routes:                  map[int64]*model.Route{},
		Settings:                settings,
		SettingsRowRevision:     bundle.SettingsRowRevision,
		Endpoints:               map[int64]map[model.EndpointKind]*model.UpstreamEndpoint{},
		LegacyFullURLs:          map[int64]*model.LegacyFullURL{},
		Recipes:                 map[int64]*model.ProbeRecipe{},
		RecipeVersions:          map[int64]*model.ProbeRecipeVersion{},
		ClientProfilesByID:      map[int64]*model.ClientProbeProfile{},
		TestedClientProfiles:    map[int64]map[model.EndpointKind]*model.ClientProbeProfile{},
		SecretRevisions:         map[string]model.SecretRevision{},
		EndpointSecretRefs:      map[int64][]model.RequiredSecretRef{},
		RecipeVersionSecretRefs: map[int64][]model.RequiredSecretRef{},
		ClientProfileSecretRefs: map[int64][]model.RequiredSecretRef{},
	}

	routingUpstreams := make([]*model.Upstream, 0, len(bundle.Upstreams))
	for _, up := range bundle.Upstreams {
		copyUp := *up
		// ProbeHeaders 是 map：浅拷贝会与 bundle 共享 backing，发布后写一边会脏另一边。
		if up.ProbeHeaders != nil {
			copyUp.ProbeHeaders = make(map[string]string, len(up.ProbeHeaders))
			for k, v := range up.ProbeHeaders {
				copyUp.ProbeHeaders[k] = v
			}
		}
		// routing 快照保留解密后的 APIKey 供真实出站鉴权；Probe 只用 ProbeConfig（无明文）。
		routingUpstreams = append(routingUpstreams, &copyUp)
		probe.Upstreams[up.ID] = up.ProbeConfig()
	}
	modelNames := make([]*model.ModelName, 0, len(bundle.ModelNames))
	for _, mn := range bundle.ModelNames {
		copyMN := *mn
		modelNames = append(modelNames, &copyMN)
		probe.ModelNames[mn.ID] = &copyMN
	}
	routes := make([]*model.Route, 0, len(bundle.Routes))
	for _, rt := range bundle.Routes {
		copyRT := *rt
		routes = append(routes, &copyRT)
		probe.Routes[rt.ID] = &copyRT
	}
	for _, ep := range bundle.Endpoints {
		copyEP := *ep
		// AuthProfile.ManualHeaders 是 slice：浅拷贝会与 bundle 共享 backing。
		if ep.AuthProfile.ManualHeaders != nil {
			copyEP.AuthProfile.ManualHeaders = append([]model.HeaderTemplate(nil), ep.AuthProfile.ManualHeaders...)
		}
		if probe.Endpoints[ep.UpstreamID] == nil {
			probe.Endpoints[ep.UpstreamID] = map[model.EndpointKind]*model.UpstreamEndpoint{}
		}
		probe.Endpoints[ep.UpstreamID][ep.Kind] = &copyEP
	}
	for _, legacy := range bundle.LegacyFullURLs {
		copyLegacy := *legacy
		probe.LegacyFullURLs[legacy.ID] = &copyLegacy
	}
	for _, recipe := range bundle.Recipes {
		copyRecipe := *recipe
		probe.Recipes[recipe.ID] = &copyRecipe
	}
	for _, version := range bundle.RecipeVersions {
		copyVersion := *version
		if version.Headers != nil {
			copyVersion.Headers = append([]model.HeaderTemplate(nil), version.Headers...)
		}
		if version.Body != nil {
			copyVersion.Body = append([]byte(nil), version.Body...)
		}
		probe.RecipeVersions[version.ID] = &copyVersion
	}
	for _, profile := range bundle.ClientProfiles {
		copyProfile := *profile
		if profile.SafeHeaders != nil {
			copyProfile.SafeHeaders = append([]model.HeaderTemplate(nil), profile.SafeHeaders...)
		}
		if profile.BodyTemplate != nil {
			copyProfile.BodyTemplate = append([]byte(nil), profile.BodyTemplate...)
		}
		if profile.BodyShapeJSON != nil {
			copyProfile.BodyShapeJSON = append([]byte(nil), profile.BodyShapeJSON...)
		}
		if profile.QueryShapeJSON != nil {
			copyProfile.QueryShapeJSON = append([]byte(nil), profile.QueryShapeJSON...)
		}
		probe.ClientProfilesByID[profile.ID] = &copyProfile
		if profile.Status == model.ProfileTested {
			if probe.TestedClientProfiles[profile.UpstreamID] == nil {
				probe.TestedClientProfiles[profile.UpstreamID] = map[model.EndpointKind]*model.ClientProbeProfile{}
			}
			probe.TestedClientProfiles[profile.UpstreamID][profile.Endpoint] = &copyProfile
		}
	}
	for _, rev := range bundle.SecretRevisions {
		probe.SecretRevisions[rev.Name] = rev
	}
	for id, refs := range bundle.EndpointSecretRefs {
		probe.EndpointSecretRefs[id] = append([]model.RequiredSecretRef(nil), refs...)
	}
	for id, refs := range bundle.RecipeVersionSecretRefs {
		probe.RecipeVersionSecretRefs[id] = append([]model.RequiredSecretRef(nil), refs...)
	}
	for id, refs := range bundle.ClientProfileSecretRefs {
		probe.ClientProfileSecretRefs[id] = append([]model.RequiredSecretRef(nil), refs...)
	}

	return &PublishedConfig{
		Generation: generation,
		Routing:    router.BuildSnapshot(modelNames, routingUpstreams, routes),
		Probe:      probe,
		Settings:   settings,
		RunState:   bundle.RunState,
	}, nil
}
