package api

import (
	"context"
	"net/http"
	"strconv"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
)

// ManualProbeRunner 执行恰好一次 manual ProbeExecution（P0-14）。
type ManualProbeRunner interface {
	RunManual(ctx context.Context, routeID int64) (model.ProbeExecution, error)
}

// ProbeAdmin 是探活资源管理面。
type ProbeAdmin interface {
	ManualProbeRunner
	ListEndpoints(ctx context.Context, f model.EndpointFilter) (model.Page[model.UpstreamEndpoint], error)
	GetEndpoint(ctx context.Context, id int64) (model.UpstreamEndpoint, error)
	CreateEndpoint(ctx context.Context, in model.UpstreamEndpoint) (model.UpstreamEndpoint, error)
	UpdateEndpoint(ctx context.Context, id, expectedRevision int64, in model.UpstreamEndpoint) (model.UpstreamEndpoint, error)
	DeleteEndpoint(ctx context.Context, id, expectedRevision int64) error

	ListSecrets(ctx context.Context, f model.ProbeSecretFilter) (model.Page[model.ProbeSecret], error)
	CreateSecret(ctx context.Context, name string, plain []byte) (model.ProbeSecret, error)
	UpdateSecret(ctx context.Context, id, expectedRevision int64, plain []byte) (model.ProbeSecret, error)
	DeleteSecret(ctx context.Context, id, expectedRevision int64) error

	ListRecipes(ctx context.Context, f model.RecipeFilter) (model.Page[model.ProbeRecipe], error)
	GetRecipe(ctx context.Context, id int64) (model.ProbeRecipe, error)
	CreateRecipe(ctx context.Context, scope model.RecipeScope, scopeID int64, endpoint model.EndpointKind) (model.ProbeRecipe, error)
	ListVersions(ctx context.Context, f model.RecipeVersionFilter) (model.Page[model.ProbeRecipeVersion], error)
	GetVersion(ctx context.Context, versionID int64) (model.ProbeRecipeVersion, error)
	DisableRecipe(ctx context.Context, recipeID, expectedRevision int64) (model.ProbeRecipe, error)
	ArchiveRecipe(ctx context.Context, recipeID, expectedRevision int64) (model.ProbeRecipe, error)

	ListExecutions(ctx context.Context, f model.ProbeExecutionFilter) (model.Page[model.ProbeExecution], error)
	GetExecution(ctx context.Context, id string) (model.ProbeExecution, error)
	ListCapabilities(ctx context.Context, f model.CapabilityFilter) (model.Page[model.EndpointCapability], error)
	ListReachability(ctx context.Context, f model.ReachabilityFilter) (model.Page[model.UpstreamReachability], error)
	ListCosts(ctx context.Context, f model.ProbeCostFilter) (model.Page[model.ProbeCostDaily], error)
	RuntimeStats(ctx context.Context) model.ProbeRuntimeStats

	ListCalibrations(ctx context.Context, f model.CalibrationFilter) (model.Page[model.CalibrationRun], error)
	PlanCalibration(ctx context.Context, routeID int64, endpoint model.EndpointKind) (model.CalibrationRun, error)
	StartCalibration(ctx context.Context, runID string, expectedRevision int64) (model.CalibrationRun, error)
	GetCalibration(ctx context.Context, runID string) (model.CalibrationRun, error)
	CancelCalibration(ctx context.Context, runID string, expectedRevision int64) error
}

// WithProbeAdmin 注入 P0-14 探活管理服务。
func (s *Server) WithProbeAdmin(admin ProbeAdmin) *Server {
	s.probeAdmin = admin
	return s
}

type secretOut struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Masked      string `json:"masked"`
	Fingerprint string `json:"fingerprint"`
	Revision    int64  `json:"revision"`
	IsSet       bool   `json:"is_set"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at"`
}

func maskSecret(sec model.ProbeSecret) secretOut {
	return secretOut{
		ID: sec.ID, Name: sec.Name, Masked: sec.Masked, Fingerprint: sec.Fingerprint,
		Revision: sec.Revision, IsSet: sec.Masked != "", CreatedAt: sec.CreatedAt, UpdatedAt: sec.UpdatedAt,
	}
}

func (s *Server) listUpstreamEndpoints(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	filter := model.EndpointFilter{PageRequest: pageFromQuery(r)}
	if v := r.URL.Query().Get("upstream_id"); v != "" {
		id, _ := strconv.ParseInt(v, 10, 64)
		filter.UpstreamID = id
	}
	page, err := s.probeAdmin.ListEndpoints(r.Context(), filter)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) getUpstreamEndpoint(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	ep, err := s.probeAdmin.GetEndpoint(r.Context(), id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ep)
}

func (s *Server) createUpstreamEndpoint(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	var in model.UpstreamEndpoint
	if err := decodeJSON(r, &in); err != nil {
		s.writeErr(w, err)
		return
	}
	ep, err := s.probeAdmin.CreateEndpoint(r.Context(), in)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	// §9.2: Endpoint URL / Auth Profile changes clear child RouteHealth.
	// Create also invalidates: a new kind/URL is part of the request identity.
	s.invalidateUpstream(ep.UpstreamID)
	// livecfg Probe 快照含 Endpoint：url_override / path 影响下一次出站 URL
	// （outbound 读同代 Bundle），须 Invalidate+Refresh，不能等 2s TTL。
	if err := s.publishAfterSuccessfulWrite(); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, ep)
}

func (s *Server) updateUpstreamEndpoint(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	// 以库中现值为基底：PUT 未提供的字段保持原样（与 updateRoute / updateModelName 一致）。
	cur, err := s.probeAdmin.GetEndpoint(r.Context(), id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	body := struct {
		model.UpstreamEndpoint
		ExpectedRevision int64 `json:"expected_revision"`
	}{UpstreamEndpoint: cur}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	// URL 路径上的 id / 库中的 upstream_id 不可被 body 改写：否则会校验到别的站、
	// 或把 Invalidate 打到错误 Upstream（store UPDATE 本身不写 upstream_id 列）。
	body.ID = id
	body.UpstreamID = cur.UpstreamID
	ep, err := s.probeAdmin.UpdateEndpoint(r.Context(), id, body.ExpectedRevision, body.UpstreamEndpoint)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	// §9.2: Endpoint 来源/URL and Auth Profile must Forget RouteHealth immediately
	// (probe.Service alone only reaches Scheduler, not SemanticInvalidator).
	s.invalidateUpstream(ep.UpstreamID)
	// url_override / path 变更必须立刻进入 livecfg Probe 快照（同代 Bundle）。
	if err := s.publishAfterSuccessfulWrite(); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ep)
}

func (s *Server) deleteUpstreamEndpoint(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	expected, _ := strconv.ParseInt(r.URL.Query().Get("expected_revision"), 10, 64)
	// Read UpstreamID before DELETE so §9.2 Forget still targets the right station.
	cur, getErr := s.probeAdmin.GetEndpoint(r.Context(), id)
	if err := s.probeAdmin.DeleteEndpoint(r.Context(), id, expected); err != nil {
		s.writeErr(w, err)
		return
	}
	// §15: bindings are (route_id, endpoint_id); drop any for this endpoint so a
	// later row that reuses the numeric id cannot inherit a published transform.
	s.detachTransformBindingsForEndpoint(id)
	if getErr == nil && cur.UpstreamID > 0 {
		s.invalidateUpstream(cur.UpstreamID)
	}
	// Deleted Endpoint must leave the livecfg Probe snapshot immediately;
	// otherwise outbound/probe keep the pre-delete URL/path for the 2s TTL.
	if err := s.publishAfterSuccessfulWrite(); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) listProbeSecrets(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	page, err := s.probeAdmin.ListSecrets(r.Context(), model.ProbeSecretFilter{PageRequest: pageFromQuery(r)})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]secretOut, 0, len(page.Items))
	for _, sec := range page.Items {
		out = append(out, maskSecret(sec))
	}
	writeJSON(w, http.StatusOK, model.Page[secretOut]{Items: out, NextCursor: page.NextCursor})
}

func (s *Server) createProbeSecret(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	var body struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	sec, err := s.probeAdmin.CreateSecret(r.Context(), body.Name, []byte(body.Value))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, maskSecret(sec))
}

func (s *Server) updateProbeSecret(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	var body struct {
		Value            string `json:"value"`
		ExpectedRevision int64  `json:"expected_revision"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	sec, err := s.probeAdmin.UpdateSecret(r.Context(), id, body.ExpectedRevision, []byte(body.Value))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, maskSecret(sec))
}

func (s *Server) deleteProbeSecret(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	expected, _ := strconv.ParseInt(r.URL.Query().Get("expected_revision"), 10, 64)
	if err := s.probeAdmin.DeleteSecret(r.Context(), id, expected); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) listProbeRecipes(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	page, err := s.probeAdmin.ListRecipes(r.Context(), model.RecipeFilter{PageRequest: pageFromQuery(r)})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) getProbeRecipe(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	recipe, err := s.probeAdmin.GetRecipe(r.Context(), id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, recipe)
}

func (s *Server) createProbeRecipe(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	var body struct {
		Scope    model.RecipeScope  `json:"scope"`
		ScopeID  int64              `json:"scope_id"`
		Endpoint model.EndpointKind `json:"endpoint"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	recipe, err := s.probeAdmin.CreateRecipe(r.Context(), body.Scope, body.ScopeID, body.Endpoint)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, recipe)
}

func (s *Server) listProbeExecutions(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	page, err := s.probeAdmin.ListExecutions(r.Context(), model.ProbeExecutionFilter{PageRequest: pageFromQuery(r)})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) getProbeExecution(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	id := r.PathValue("id")
	exec, err := s.probeAdmin.GetExecution(r.Context(), id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, exec)
}

func (s *Server) listCapabilities(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	page, err := s.probeAdmin.ListCapabilities(r.Context(), model.CapabilityFilter{PageRequest: pageFromQuery(r)})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) listReachability(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	page, err := s.probeAdmin.ListReachability(r.Context(), model.ReachabilityFilter{PageRequest: pageFromQuery(r)})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) getProbeRuntime(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	writeJSON(w, http.StatusOK, s.probeAdmin.RuntimeStats(r.Context()))
}

func (s *Server) listCalibrations(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	page, err := s.probeAdmin.ListCalibrations(r.Context(), model.CalibrationFilter{PageRequest: pageFromQuery(r)})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) createCalibration(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	var body struct {
		RouteID  int64              `json:"route_id"`
		Endpoint model.EndpointKind `json:"endpoint"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	run, err := s.probeAdmin.PlanCalibration(r.Context(), body.RouteID, body.Endpoint)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, run)
}

func (s *Server) getCalibration(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	run, err := s.probeAdmin.GetCalibration(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) startCalibration(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	var body struct {
		ExpectedRevision int64 `json:"expected_revision"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	run, err := s.probeAdmin.StartCalibration(r.Context(), r.PathValue("id"), body.ExpectedRevision)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) cancelCalibration(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	var body struct {
		ExpectedRevision int64 `json:"expected_revision"`
	}
	_ = decodeJSON(r, &body)
	if err := s.probeAdmin.CancelCalibration(r.Context(), r.PathValue("id"), body.ExpectedRevision); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) listProbeCosts(w http.ResponseWriter, r *http.Request) {
	if s.probeAdmin == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
		return
	}
	filter := model.ProbeCostFilter{PageRequest: pageFromQuery(r)}
	if v := r.URL.Query().Get("route_id"); v != "" {
		id, _ := strconv.ParseInt(v, 10, 64)
		filter.RouteID = id
	}
	if v := r.URL.Query().Get("upstream_id"); v != "" {
		id, _ := strconv.ParseInt(v, 10, 64)
		filter.UpstreamID = id
	}
	page, err := s.probeAdmin.ListCosts(r.Context(), filter)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func pageFromQuery(r *http.Request) model.PageRequest {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	return model.PageRequest{Cursor: r.URL.Query().Get("cursor"), Limit: limit}
}

// 编译期确认 probe.Service 满足 ProbeAdmin。
var _ ProbeAdmin = (*probe.Service)(nil)
