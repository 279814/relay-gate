package api

import (
	"fmt"
	"net/http"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
	"github.com/279814/relay-gate/internal/transform"
)

// WithTransformRegistry injects the P4 declarative transform registry.
func (s *Server) WithTransformRegistry(r *transform.Registry) *Server {
	s.transforms = r
	return s
}

// detachTransformBindingsForRoute removes published/shadow bindings for a
// deleted Route. Persist errors are logged; the SQL row is already gone.
func (s *Server) detachTransformBindingsForRoute(routeID int64) {
	if s == nil || s.transforms == nil || routeID <= 0 {
		return
	}
	if err := s.transforms.RemoveBindingsForRoute(routeID); err != nil && s.log != nil {
		s.log.Error("detach transform bindings after route delete", "route_id", routeID, "err", err)
	}
}

// detachTransformBindingsForEndpoint removes bindings for a deleted Endpoint.
func (s *Server) detachTransformBindingsForEndpoint(endpointID int64) {
	if s == nil || s.transforms == nil || endpointID <= 0 {
		return
	}
	if err := s.transforms.RemoveBindingsForEndpoint(endpointID); err != nil && s.log != nil {
		s.log.Error("detach transform bindings after endpoint delete", "endpoint_id", endpointID, "err", err)
	}
}

func (s *Server) listTransformSets(w http.ResponseWriter, r *http.Request) {
	if s.transforms == nil {
		writeJSON(w, http.StatusOK, map[string]any{"sets": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sets": s.transforms.ListSets()})
}

func (s *Server) createTransformSet(w http.ResponseWriter, r *http.Request) {
	if s.transforms == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"transform registry unavailable"})
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	set, err := s.transforms.CreateSet(body.Name)
	if err != nil {
		s.writeErr(w, fmt.Errorf("%w: %s", model.ErrValidation, err.Error()))
		return
	}
	writeJSON(w, http.StatusCreated, set)
}

func (s *Server) getTransformSet(w http.ResponseWriter, r *http.Request) {
	if s.transforms == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"transform registry unavailable"})
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	set, err := s.transforms.GetSet(id)
	if err != nil {
		s.writeErr(w, storeNotFound(err))
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (s *Server) putTransformDraft(w http.ResponseWriter, r *http.Request) {
	if s.transforms == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"transform registry unavailable"})
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	var body struct {
		Rules         []transform.Rule `json:"rules"`
		ReqFailPolicy string           `json:"req_fail_policy"`
		ResFailPolicy string           `json:"res_fail_policy"`
		Note          string           `json:"note"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	set, err := s.transforms.UpdateDraft(id, body.Rules, body.ReqFailPolicy, body.ResFailPolicy, body.Note)
	if err != nil {
		s.writeErr(w, fmt.Errorf("%w: %s", model.ErrValidation, err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (s *Server) postTransformPreview(w http.ResponseWriter, r *http.Request) {
	if s.transforms == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"transform registry unavailable"})
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	var body struct {
		Phase      string            `json:"phase"`
		Body       string            `json:"body"`
		Headers    map[string]string `json:"headers"`
		Status     int               `json:"status"`
		RespBody   string            `json:"resp_body"`
		RespHeader map[string]string `json:"resp_headers"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if body.Phase == "" {
		body.Phase = "request"
	}
	reqIn := transform.RequestInput{Header: http.Header{}, Body: []byte(body.Body)}
	for k, v := range body.Headers {
		reqIn.Header.Set(k, v)
	}
	resIn := transform.ResponseInput{Status: body.Status, Header: http.Header{}, Body: []byte(body.RespBody)}
	if resIn.Status == 0 {
		resIn.Status = 200
	}
	for k, v := range body.RespHeader {
		resIn.Header.Set(k, v)
	}
	out, err := s.transforms.Preview(id, body.Phase, reqIn, resIn)
	if err != nil {
		s.writeErr(w, fmt.Errorf("%w: %s", model.ErrValidation, err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) postTransformPublish(w http.ResponseWriter, r *http.Request) {
	s.transformBindAction(w, r, "publish")
}

func (s *Server) postTransformShadow(w http.ResponseWriter, r *http.Request) {
	s.transformBindAction(w, r, "shadow")
}

func (s *Server) transformBindAction(w http.ResponseWriter, r *http.Request, action string) {
	if s.transforms == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"transform registry unavailable"})
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	var body struct {
		RouteID    int64 `json:"route_id"`
		EndpointID int64 `json:"endpoint_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if body.RouteID <= 0 || body.EndpointID <= 0 {
		s.writeErr(w, fmt.Errorf("%w: route_id and endpoint_id required", model.ErrValidation))
		return
	}
	var (
		b *transform.Binding
		v *transform.Version
	)
	switch action {
	case "publish":
		b, v, err = s.transforms.PublishSnapshot(id, body.RouteID, body.EndpointID)
	case "shadow":
		b, v, err = s.transforms.ShadowSnapshot(id, body.RouteID, body.EndpointID)
	default:
		err = fmt.Errorf("unknown action")
	}
	if err != nil {
		s.writeErr(w, fmt.Errorf("%w: %s", model.ErrValidation, err.Error()))
		return
	}
	// §9.2: publish changes the live request Transform binding; clear RouteHealth
	// immediately. Shadow only points a non-live pointer — do not Forget.
	if action == "publish" {
		s.invalidateRoute(body.RouteID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"binding": b, "version": v, "action": action})
}

func (s *Server) postTransformRollback(w http.ResponseWriter, r *http.Request) {
	if s.transforms == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"transform registry unavailable"})
		return
	}
	var body struct {
		RouteID    int64 `json:"route_id"`
		EndpointID int64 `json:"endpoint_id"`
		VersionID  int64 `json:"version_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	b, err := s.transforms.Rollback(body.RouteID, body.EndpointID, body.VersionID)
	if err != nil {
		s.writeErr(w, fmt.Errorf("%w: %s", model.ErrValidation, err.Error()))
		return
	}
	// §9.2: rollback retargets the published Transform — Forget old RouteHealth.
	s.invalidateRoute(body.RouteID)
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) listTransformBindings(w http.ResponseWriter, r *http.Request) {
	if s.transforms == nil {
		writeJSON(w, http.StatusOK, map[string]any{"bindings": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bindings": s.transforms.ListBindings()})
}

func (s *Server) listTransformExecutions(w http.ResponseWriter, r *http.Request) {
	if s.transforms == nil {
		writeJSON(w, http.StatusOK, map[string]any{"executions": []any{}})
		return
	}
	limit, err := queryInt64(r.URL.Query().Get("limit"))
	if err != nil {
		s.writeErr(w, fmt.Errorf("%w: limit", model.ErrValidation))
		return
	}
	if r.URL.Query().Get("limit") == "" {
		limit = 50
	}
	writeJSON(w, http.StatusOK, map[string]any{"executions": s.transforms.ListExecutions(int(limit))})
}

func (s *Server) getTransformBudgets(w http.ResponseWriter, r *http.Request) {
	if s.transforms == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"transform registry unavailable"})
		return
	}
	b := s.transforms.Budgets()
	writeJSON(w, http.StatusOK, map[string]any{
		"budgets": b,
		"audit":   s.transforms.BudgetAudits(20),
	})
}

func (s *Server) putTransformBudgets(w http.ResponseWriter, r *http.Request) {
	if s.transforms == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"transform registry unavailable"})
		return
	}
	var body struct {
		RequestMs    int  `json:"request_ms"`
		SSEEventMs   int  `json:"sse_event_ms"`
		ConfirmRaise bool `json:"confirm_raise"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	out, err := s.transforms.SetBudgets(body.RequestMs, body.SSEEventMs, body.ConfirmRaise)
	if err != nil {
		s.writeErr(w, fmt.Errorf("%w: %s", model.ErrValidation, err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"budgets": out,
		"audit":   s.transforms.BudgetAudits(20),
	})
}

func storeNotFound(err error) error {
	return fmt.Errorf("%w: %s", store.ErrNotFound, err.Error())
}
