package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/sample"
	"github.com/279814/relay-gate/internal/store"
	"github.com/279814/relay-gate/internal/transform"
)

// WithTransformRegistry injects the P4 declarative transform registry.
func (s *Server) WithTransformRegistry(r *transform.Registry) *Server {
	s.transforms = r
	return s
}

// transformClientErr maps registry errors to 400 with their message, except
// persistence failures: those carry SQLite text and go to writeErr's 500 path.
func transformClientErr(err error) error {
	if errors.Is(err, transform.ErrRevisionConflict) {
		return store.ErrRevisionConflict
	}
	if errors.Is(err, transform.ErrBindingInUse) {
		return store.ErrDependencyConflict
	}
	if errors.Is(err, transform.ErrNotFound) {
		return store.ErrNotFound
	}
	if errors.Is(err, transform.ErrPersist) {
		return err
	}
	return fmt.Errorf("%w: %s", model.ErrValidation, err.Error())
}

func (s *Server) listTransformSets(w http.ResponseWriter, r *http.Request) {
	if s.transforms == nil || s.st == nil {
		writeJSON(w, 503, errBody{"transform store unavailable"})
		return
	}
	query, err := parseTransformQuery(r, "state", "name", "limit", "cursor")
	if err != nil {
		s.writeErr(w, err)
		return
	}
	pageRequest, err := transformPageRequest(query)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	page, err := s.st.ListTransformSetsPage(r.Context(), model.TransformSetFilter{PageRequest: pageRequest, State: query.Get("state"), Name: query.Get("name")})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"sets": page.Items, "total": page.Total, "next_cursor": page.NextCursor, "limit": page.Limit})
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
		s.writeErr(w, transformClientErr(err))
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
	historyCount := len(set.History)
	set.History = nil
	writeJSON(w, http.StatusOK, struct {
		*transform.Set
		HistoryCount int `json:"history_count"`
	}{set, historyCount})
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
		ExpectedRevision *int64           `json:"expected_revision"`
		Rules            []transform.Rule `json:"rules"`
		ReqFailPolicy    string           `json:"req_fail_policy"`
		ResFailPolicy    string           `json:"res_fail_policy"`
		Note             string           `json:"note"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if body.ExpectedRevision == nil || *body.ExpectedRevision < 1 {
		s.writeErr(w, model.WrapValidation("expected_revision 必须为正整数"))
		return
	}
	set, err := s.transforms.UpdateDraftAtRevision(id, *body.ExpectedRevision, body.Rules, body.ReqFailPolicy, body.ResFailPolicy, body.Note)
	if err != nil {
		s.writeErr(w, transformClientErr(err))
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
		ExpectedRevision *int64            `json:"expected_revision"`
		Phase            string            `json:"phase"`
		Body             string            `json:"body"`
		Headers          map[string]string `json:"headers"`
		Status           int               `json:"status"`
		RespBody         string            `json:"resp_body"`
		RespHeader       map[string]string `json:"resp_headers"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if body.Phase == "" {
		body.Phase = "request"
	}
	if body.Phase != "request" && body.Phase != "response" && body.Phase != "sse" {
		s.writeErr(w, model.WrapValidation("preview phase 无效"))
		return
	}
	if body.ExpectedRevision != nil && *body.ExpectedRevision < 1 {
		s.writeErr(w, model.WrapValidation("expected_revision 必须为正整数"))
		return
	}
	keys, ok := s.diagnosticKeys(w, r)
	if !ok {
		return
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
	out, err := s.transforms.PreviewSensitive(id, body.Phase, reqIn, resIn, keys, body.ExpectedRevision)
	if err != nil {
		clientErr := transformClientErr(err)
		if errors.Is(clientErr, model.ErrValidation) {
			clientErr = model.WrapValidation("%s", sample.RedactDiagnosticText(err.Error(), keys))
		}
		s.writeErr(w, clientErr)
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
		ExpectedRevision        *int64 `json:"expected_revision"`
		ExpectedBindingRevision *int64 `json:"expected_binding_revision"`
		RouteID                 int64  `json:"route_id"`
		EndpointID              int64  `json:"endpoint_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if body.RouteID <= 0 || body.EndpointID <= 0 {
		s.writeErr(w, fmt.Errorf("%w: route_id and endpoint_id required", model.ErrValidation))
		return
	}
	if body.ExpectedRevision == nil || *body.ExpectedRevision < 1 || body.ExpectedBindingRevision == nil || *body.ExpectedBindingRevision < 0 {
		s.writeErr(w, model.WrapValidation("expected_revision 必须为正整数，expected_binding_revision 必须显式提供且非负"))
		return
	}
	if err := s.validateTransformTarget(body.RouteID, body.EndpointID); err != nil {
		s.writeErr(w, err)
		return
	}
	publication, err := s.transforms.PublishAtRevision(id, body.RouteID, body.EndpointID, action == "shadow", transform.PublishPreconditions{SetRevision: *body.ExpectedRevision, BindingRevision: *body.ExpectedBindingRevision})
	if err != nil {
		s.writeErr(w, transformClientErr(err))
		return
	}
	// §9.2: publish changes the live request Transform binding; clear RouteHealth
	// immediately. Shadow only points a non-live pointer — do not Forget.
	if action == "publish" {
		s.invalidateRoute(body.RouteID)
		if err := s.publishAfterSuccessfulWrite(); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"code": "config_activation_pending", "error": "转换已保存，配置激活待重试", "persisted": true, "binding": publication.Binding, "revision": publication.Binding.Revision, "set_revision": publication.SetRevision})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"binding": publication.Binding, "version": publication.Version, "set_revision": publication.SetRevision, "action": action})
}

func (s *Server) postTransformRollback(w http.ResponseWriter, r *http.Request) {
	if s.transforms == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"transform registry unavailable"})
		return
	}
	var body struct {
		ExpectedRevision *int64 `json:"expected_revision"`
		RouteID          int64  `json:"route_id"`
		EndpointID       int64  `json:"endpoint_id"`
		VersionID        int64  `json:"version_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if body.ExpectedRevision == nil || *body.ExpectedRevision < 1 {
		s.writeErr(w, model.WrapValidation("expected_revision 必须为正整数"))
		return
	}
	if err := s.validateTransformTarget(body.RouteID, body.EndpointID); err != nil {
		s.writeErr(w, err)
		return
	}
	b, err := s.transforms.RollbackAtRevision(body.RouteID, body.EndpointID, body.VersionID, *body.ExpectedRevision)
	if err != nil {
		s.writeErr(w, transformClientErr(err))
		return
	}
	// §9.2: rollback retargets the published Transform — Forget old RouteHealth.
	s.invalidateRoute(body.RouteID)
	if err := s.publishAfterSuccessfulWrite(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"code": "config_activation_pending", "error": "转换回滚已保存，配置激活待重试", "persisted": true, "binding": b, "revision": b.Revision})
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) listTransformBindings(w http.ResponseWriter, r *http.Request) {
	if s.transforms == nil || s.st == nil {
		writeJSON(w, 503, errBody{"transform store unavailable"})
		return
	}
	query, err := parseTransformQuery(r, "set_id", "route_id", "endpoint_id", "version_id", "state", "limit", "cursor")
	if err != nil {
		s.writeErr(w, err)
		return
	}
	pageRequest, err := transformPageRequest(query)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	filter := model.TransformBindingFilter{PageRequest: pageRequest, State: query.Get("state")}
	for _, field := range []struct {
		name   string
		target *int64
	}{{"set_id", &filter.SetID}, {"route_id", &filter.RouteID}, {"endpoint_id", &filter.EndpointID}, {"version_id", &filter.VersionID}} {
		id, err := optionalTransformID(query, field.name)
		if err != nil {
			s.writeErr(w, err)
			return
		}
		*field.target = id
	}
	page, err := s.st.ListTransformBindingsPage(r.Context(), filter)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"bindings": page.Items, "total": page.Total, "next_cursor": page.NextCursor, "limit": page.Limit})
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
	pageLimit, err := store.NormalizePageLimit(int(limit))
	if err != nil {
		s.writeErr(w, fmt.Errorf("%w: %v", model.ErrValidation, err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"executions": s.transforms.ListExecutions(pageLimit)})
}

func (s *Server) getTransformBudgets(w http.ResponseWriter, r *http.Request) {
	if s.transforms == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"transform registry unavailable"})
		return
	}
	b, revision := s.transforms.BudgetSnapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"budgets":  b,
		"revision": revision,
		"audit":    s.transforms.BudgetAudits(20),
	})
}

func (s *Server) putTransformBudgets(w http.ResponseWriter, r *http.Request) {
	if s.transforms == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"transform registry unavailable"})
		return
	}
	var body struct {
		ExpectedRevision *int64 `json:"expected_revision"`
		RequestMs        int    `json:"request_ms"`
		SSEEventMs       int    `json:"sse_event_ms"`
		ConfirmRaise     bool   `json:"confirm_raise"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if body.ExpectedRevision == nil || *body.ExpectedRevision < 1 {
		s.writeErr(w, model.WrapValidation("expected_revision 必须为正整数"))
		return
	}
	out, revision, err := s.transforms.SetBudgetsAtRevision(body.RequestMs, body.SSEEventMs, body.ConfirmRaise, *body.ExpectedRevision)
	if err != nil {
		s.writeErr(w, transformClientErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"budgets":  out,
		"revision": revision,
		"audit":    s.transforms.BudgetAudits(20),
	})
}

func storeNotFound(err error) error {
	return fmt.Errorf("%w: %s", store.ErrNotFound, err.Error())
}

func (s *Server) postTransformDisable(w http.ResponseWriter, r *http.Request) {
	s.transformLifecycleAction(w, r, transform.LifecycleDisabled)
}
func (s *Server) postTransformEnable(w http.ResponseWriter, r *http.Request) {
	s.transformLifecycleAction(w, r, transform.LifecycleActive)
}
func (s *Server) postTransformArchive(w http.ResponseWriter, r *http.Request) {
	s.transformLifecycleAction(w, r, transform.LifecycleArchived)
}
func (s *Server) transformLifecycleAction(w http.ResponseWriter, r *http.Request, state transform.LifecycleState) {
	if s.transforms == nil {
		s.writeErr(w, fmt.Errorf("transform registry unavailable"))
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	var input struct {
		ExpectedRevision *int64 `json:"expected_revision"`
	}
	if err := decodeJSON(r, &input); err != nil {
		s.writeErr(w, err)
		return
	}
	if input.ExpectedRevision == nil || *input.ExpectedRevision < 1 {
		s.writeErr(w, model.WrapValidation("expected_revision 必须为正整数"))
		return
	}
	before, err := s.transforms.GetSet(id)
	if err != nil {
		s.writeErr(w, storeNotFound(err))
		return
	}
	result, err := s.transforms.SetLifecycleAtRevision(id, *input.ExpectedRevision, state)
	if err != nil {
		s.writeErr(w, transformClientErr(err))
		return
	}
	if result.Revision == before.Revision {
		writeJSON(w, http.StatusOK, result)
		return
	}
	// The store already invalidated every affected live Route in the same TX.
	for _, binding := range s.transforms.ListBindings() {
		if binding.SetID == id && binding.PublishedID != 0 && ((before.State == transform.LifecycleActive) != (result.State == transform.LifecycleActive)) {
			s.invalidateRoute(binding.RouteID)
		}
	}
	if err := s.publishAfterSuccessfulWrite(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"persisted": true, "code": "config_activation_pending", "error": "转换状态已保存，激活待确认", "resource": "transform", "resource_id": id, "new_revision": result.Revision})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) validateTransformTarget(routeID, endpointID int64) error {
	if s.st == nil {
		return fmt.Errorf("transform store unavailable")
	}
	route, err := s.st.GetRoute(routeID)
	if err != nil {
		return err
	}
	endpoint, err := s.st.GetEndpoint(endpointID)
	if err != nil {
		return err
	}
	if endpoint.UpstreamID != route.UpstreamID {
		return model.WrapValidation("Transform Endpoint 必须属于 Route 的 Upstream")
	}
	return nil
}
