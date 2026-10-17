package api

import (
	"encoding/json"
	"net/http"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
)

type clientProfileOut struct {
	ID                int64                    `json:"id"`
	UpstreamID        int64                    `json:"upstream_id"`
	Endpoint          model.EndpointKind       `json:"endpoint"`
	Status            model.ProbeProfileStatus `json:"status"`
	SafeHeaders       []model.HeaderTemplate   `json:"safe_headers"`
	FixedRawQuery     string                   `json:"fixed_raw_query"`
	BodyTemplate      string                   `json:"body_template"`
	BodyShape         json.RawMessage          `json:"body_shape"`
	ClientFamily      string                   `json:"client_family"`
	ShapeHash         string                   `json:"shape_hash"`
	Revision          int64                    `json:"revision"`
	LastSeenAt        int64                    `json:"last_seen_at"`
	SeenCount         int64                    `json:"seen_count"`
	TestedExecutionID string                   `json:"tested_execution_id"`
	CreatedAt         int64                    `json:"created_at"`
	UpdatedAt         int64                    `json:"updated_at"`
}

func clientProfileOutput(p model.ClientProbeProfile) clientProfileOut {
	return clientProfileOut{ID: p.ID, UpstreamID: p.UpstreamID, Endpoint: p.Endpoint, Status: p.Status, SafeHeaders: p.SafeHeaders, FixedRawQuery: p.FixedRawQuery, BodyTemplate: string(p.BodyTemplate), BodyShape: p.BodyShapeJSON, ClientFamily: p.ClientFamily, ShapeHash: p.ShapeHash, Revision: p.Revision, LastSeenAt: p.LastSeenAt, SeenCount: p.SeenCount, TestedExecutionID: p.TestedExecutionID, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
}
func (s *Server) getClientProfile(w http.ResponseWriter, r *http.Request) {
	if !s.probeAdminReady(w) {
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	profile, err := s.probeAdmin.GetClientProfile(r.Context(), id)
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	writeJSON(w, 200, clientProfileOutput(profile))
}
func (s *Server) previewClientProfile(w http.ResponseWriter, r *http.Request) {
	if !s.probeAdminReady(w) {
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	var body struct {
		RouteID int64 `json:"route_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	preview, err := s.probeAdmin.PreviewClientProfile(r.Context(), id, probe.PreviewInput{RouteID: body.RouteID})
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	writeJSON(w, 200, preview)
}
func (s *Server) testClientProfile(w http.ResponseWriter, r *http.Request) {
	if !s.probeAdminReady(w) {
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	var body struct {
		RouteID          int64 `json:"route_id"`
		ExpectedRevision int64 `json:"expected_revision"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	execution, err := s.probeAdmin.TestClientProfile(r.Context(), id, body.RouteID, body.ExpectedRevision)
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	s.writeExecutionDetail(w, r, execution)
}
func (s *Server) disableClientProfile(w http.ResponseWriter, r *http.Request) {
	if !s.probeAdminReady(w) {
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	var body struct {
		ExpectedRevision int64 `json:"expected_revision"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	if err := s.probeAdmin.DisableClientProfile(r.Context(), id, body.ExpectedRevision); err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	profile, err := s.probeAdmin.GetClientProfile(r.Context(), id)
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	writeJSON(w, 200, clientProfileOutput(profile))
}
