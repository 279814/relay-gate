package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/probe"
	"github.com/279814/relay-gate/internal/store"
)

type recipeVersionOut struct {
	ID             int64                     `json:"id"`
	RecipeID       int64                     `json:"recipe_id"`
	Version        int                       `json:"version"`
	Origin         model.RecipeSource        `json:"origin"`
	Method         string                    `json:"method"`
	FixedRawQuery  string                    `json:"fixed_raw_query"`
	Headers        []model.HeaderTemplate    `json:"headers"`
	BodyText       *string                   `json:"body_text,omitempty"`
	BodyBase64     *string                   `json:"body_base64,omitempty"`
	StreamExpected bool                      `json:"stream_expected"`
	TimeoutProfile model.ProbeTimeoutProfile `json:"timeout_profile"`
	CreatedAt      int64                     `json:"created_at"`
}

func (s *Server) writeRecipeErr(w http.ResponseWriter, err error) {
	var pending *probe.ActivationPendingError
	switch {
	case errors.As(err, &pending):
		writeJSON(w, 503, map[string]any{"error": pending.Error(), "code": "config_activation_pending", "persisted": true, "resource": pending.Resource, "id": pending.ID, "new_revision": pending.Revision})
	case errors.Is(err, store.ErrInvalidCursor):
		writeJSON(w, 400, errBody{"分页 cursor 或 limit 无效；筛选改变后请重新加载第一页"})
	case errors.Is(err, probe.ErrSyntheticClosed), errors.Is(err, livecfg.ErrProbeSnapshotUnavailable):
		w.Header().Set("Retry-After", "1")
		writeJSON(w, 503, errBody{"探活已暂停或配置快照尚未激活"})
	case errors.Is(err, outbound.ErrAuthConfig), errors.Is(err, outbound.ErrURLConfig), errors.Is(err, outbound.ErrLegacyNeedsReview):
		writeJSON(w, 400, errBody{"Endpoint URL/Auth 配置不可用于探活，请先检查或校准"})
	default:
		s.writeErr(w, err)
	}
}

func recipePage(r *http.Request) (model.PageRequest, error) {
	page := model.PageRequest{Cursor: r.URL.Query().Get("cursor")}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 0 || limit > store.MaximumPageLimit {
			return page, store.ErrInvalidCursor
		}
		page.Limit = limit
	}
	return page, nil
}

func recipeFilterID(r *http.Request, name string) (int64, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return 0, nil
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id < 1 {
		return 0, model.WrapValidation("ID 筛选必须是正整数")
	}
	return id, nil
}

func versionOutput(v model.ProbeRecipeVersion) recipeVersionOut {
	out := recipeVersionOut{ID: v.ID, RecipeID: v.RecipeID, Version: v.Version, Origin: v.Origin, Method: v.Method, FixedRawQuery: v.FixedRawQuery, Headers: v.Headers, StreamExpected: v.StreamExpected, TimeoutProfile: v.TimeoutProfile, CreatedAt: v.CreatedAt}
	if v.BodyIsText {
		body := string(v.Body)
		out.BodyText = &body
	} else {
		body := base64.StdEncoding.EncodeToString(v.Body)
		out.BodyBase64 = &body
	}
	return out
}

func (s *Server) probeAdminReady(w http.ResponseWriter) bool {
	if s.probeAdmin != nil {
		return true
	}
	writeJSON(w, http.StatusServiceUnavailable, errBody{"probe admin 未装配"})
	return false
}

func (s *Server) addRecipeVersion(w http.ResponseWriter, r *http.Request) {
	if !s.probeAdminReady(w) {
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	var body struct {
		ExpectedRevision int64                     `json:"expected_revision"`
		Method           string                    `json:"method"`
		FixedRawQuery    string                    `json:"fixed_raw_query"`
		Headers          []model.HeaderTemplate    `json:"headers"`
		BodyText         *string                   `json:"body_text"`
		BodyBase64       *string                   `json:"body_base64"`
		StreamExpected   bool                      `json:"stream_expected"`
		TimeoutProfile   model.ProbeTimeoutProfile `json:"timeout_profile"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeErr(w, err)
		return
	}
	if body.BodyText != nil && body.BodyBase64 != nil {
		s.writeErr(w, model.WrapValidation("body_text 与 body_base64 只能提供一个"))
		return
	}
	in := probe.RecipeVersionMutation{Method: body.Method, FixedRawQuery: body.FixedRawQuery, Headers: body.Headers, StreamExpected: body.StreamExpected, TimeoutProfile: body.TimeoutProfile, BodyIsText: body.BodyBase64 == nil}
	if body.BodyText != nil {
		in.Body = []byte(*body.BodyText)
	}
	if body.BodyBase64 != nil {
		raw, err := base64.StdEncoding.Strict().DecodeString(*body.BodyBase64)
		if err != nil {
			s.writeErr(w, model.WrapValidation("body_base64 无效"))
			return
		}
		in.Body = raw
	}
	version, err := s.probeAdmin.AddVersion(r.Context(), id, body.ExpectedRevision, in)
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, versionOutput(version))
}

func (s *Server) listRecipeVersions(w http.ResponseWriter, r *http.Request) {
	if !s.probeAdminReady(w) {
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	request, err := recipePage(r)
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	page, err := s.probeAdmin.ListVersions(r.Context(), model.RecipeVersionFilter{PageRequest: request, RecipeID: id, Origin: model.RecipeSource(r.URL.Query().Get("origin"))})
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	out := model.Page[recipeVersionOut]{Items: make([]recipeVersionOut, 0, len(page.Items)), NextCursor: page.NextCursor}
	for _, version := range page.Items {
		out.Items = append(out.Items, versionOutput(version))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listClientProfiles(w http.ResponseWriter, r *http.Request) {
	if !s.probeAdminReady(w) {
		return
	}
	request, err := recipePage(r)
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	f := model.ClientProfileFilter{PageRequest: request, Endpoint: model.EndpointKind(r.URL.Query().Get("endpoint")), Status: model.ProbeProfileStatus(r.URL.Query().Get("status")), ClientFamily: r.URL.Query().Get("client_family")}
	if raw := r.URL.Query().Get("upstream_id"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id < 1 {
			s.writeErr(w, model.WrapValidation("upstream_id 必须是正整数"))
			return
		}
		f.UpstreamID = id
	}
	page, err := s.probeAdmin.ListClientProfiles(r.Context(), f)
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	out := model.Page[clientProfileOut]{Items: make([]clientProfileOut, 0, len(page.Items)), NextCursor: page.NextCursor}
	for _, profile := range page.Items {
		out.Items = append(out.Items, clientProfileOutput(profile))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) nestedRecipeVersion(r *http.Request) (model.ProbeRecipeVersion, error) {
	id, err := pathID(r)
	if err != nil {
		return model.ProbeRecipeVersion{}, err
	}
	versionID, err := strconv.ParseInt(r.PathValue("version_id"), 10, 64)
	if err != nil || versionID < 1 {
		return model.ProbeRecipeVersion{}, model.WrapValidation("version_id 必须是正整数")
	}
	version, err := s.probeAdmin.GetVersion(r.Context(), versionID)
	if err != nil {
		return version, err
	}
	if version.RecipeID != id {
		return version, model.WrapValidation("版本不属于该 Recipe")
	}
	return version, nil
}

func (s *Server) previewRecipeVersion(w http.ResponseWriter, r *http.Request) {
	if !s.probeAdminReady(w) {
		return
	}
	version, err := s.nestedRecipeVersion(r)
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
	out, err := s.probeAdmin.Preview(r.Context(), version.ID, probe.PreviewInput{RouteID: body.RouteID})
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) testRecipeVersion(w http.ResponseWriter, r *http.Request) {
	if !s.probeAdminReady(w) {
		return
	}
	version, err := s.nestedRecipeVersion(r)
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
	execution, err := s.probeAdmin.Test(r.Context(), version.ID, probe.ManualTestInput{RouteID: body.RouteID, ExpectedRevision: body.ExpectedRevision})
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	s.writeExecutionDetail(w, r, execution)
}

func (s *Server) publishRecipeVersion(w http.ResponseWriter, r *http.Request) {
	if !s.probeAdminReady(w) {
		return
	}
	version, err := s.nestedRecipeVersion(r)
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	var body struct {
		ExpectedRevision int64  `json:"expected_revision"`
		TestExecutionID  string `json:"test_execution_id"`
		Force            bool   `json:"force"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	recipe, err := s.probeAdmin.Publish(r.Context(), version.RecipeID, version.ID, body.TestExecutionID, body.ExpectedRevision, body.Force)
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	writeJSON(w, 200, recipe)
}

func (s *Server) getRecipeVersion(w http.ResponseWriter, r *http.Request) {
	if !s.probeAdminReady(w) {
		return
	}
	version, err := s.nestedRecipeVersion(r)
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	writeJSON(w, 200, versionOutput(version))
}

func (s *Server) retireRecipe(w http.ResponseWriter, r *http.Request) {
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
	var recipe model.ProbeRecipe
	if r.PathValue("action") == "archive" {
		recipe, err = s.probeAdmin.ArchiveRecipe(r.Context(), id, body.ExpectedRevision)
	} else if r.PathValue("action") == "disable" {
		recipe, err = s.probeAdmin.DisableRecipe(r.Context(), id, body.ExpectedRevision)
	} else {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.writeRecipeErr(w, err)
		return
	}
	writeJSON(w, 200, recipe)
}
