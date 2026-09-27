package api

import (
	"net/http"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
)

// §19.2 第 4 条：未审核状态禁止新增或改变 URL 绑定，每个 Endpoint 须经确认。
// 通用 PUT/POST 不能绕过 confirm-review；确认本身必须成功并清掉 needs_review。
func TestEndpointReview_UnreviewedBindingOnlyChangesViaConfirm(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.WithProbeAdmin(probe.NewService(s.st, nil, nil, nil, nil, nil)).Routes(testAdminPW)

	upID := mkUpstreamViaAPI(t, h, `{"name":"review-u","base_url":"https://review.example.com","api_key":"sk-rrrrrrrrrrrr"}`)
	rec := do(t, h, "GET", "/admin/api/upstream-endpoints?upstream_id="+itoa(upID), "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("list endpoints: %d %s", rec.Code, rec.Body.String())
	}
	var pending, other model.UpstreamEndpoint
	for _, ep := range decodeBody[model.Page[model.UpstreamEndpoint]](t, rec).Items {
		switch ep.Kind {
		case model.EndpointMessages:
			pending = ep
		case model.EndpointResponses:
			other = ep
		}
	}
	if pending.ID == 0 || other.ID == 0 {
		t.Fatal("expected auto-created messages and responses endpoints")
	}

	db := s.st.DB()
	res, err := db.Exec(`INSERT INTO legacy_full_url
		(upstream_id,url_enc,masked_url,fingerprint,inferred_endpoint,needs_review,revision,created_at,updated_at)
		VALUES (?,'enc','https://review.example.com/***','fp','messages',1,1,1,1)`, upID)
	if err != nil {
		t.Fatalf("seed legacy_full_url: %v", err)
	}
	legacyID, _ := res.LastInsertId()
	if _, err := db.Exec(`UPDATE upstream_endpoint SET url_mode='legacy_exact',legacy_full_url_id=?,
		legacy_full_url_revision=1,needs_review=1,revision=revision+1 WHERE id=?`, legacyID, pending.ID); err != nil {
		t.Fatalf("mark needs_review: %v", err)
	}
	rec = do(t, h, "GET", "/admin/api/upstream-endpoints/"+itoa(pending.ID), "", true)
	pending = decodeBody[model.UpstreamEndpoint](t, rec)
	if !pending.NeedsReview {
		t.Fatalf("seed did not mark needs_review: %+v", pending)
	}

	override := "https://review.example.com/v1/messages"
	refused := []struct{ name, body string }{
		{"change url_override", `{"url_override":` + mustJSON(t, override)},
		{"bypass confirm", `{"url_mode":"canonical","legacy_full_url_id":0,"legacy_full_url_revision":0,` +
			`"url_override":` + mustJSON(t, override) + `,"needs_review":false`},
		{"change kind", `{"endpoint":"chat_completions"`},
	}
	for _, tc := range refused {
		rec = do(t, h, "PUT", "/admin/api/upstream-endpoints/"+itoa(pending.ID),
			tc.body+`,"expected_revision":`+itoa(pending.Revision)+`}`, true)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s on needs_review endpoint: status=%d body=%s, want 400", tc.name, rec.Code, rec.Body.String())
		}
	}
	rec = do(t, h, "GET", "/admin/api/upstream-endpoints/"+itoa(pending.ID), "", true)
	if after := decodeBody[model.UpstreamEndpoint](t, rec); after.Revision != pending.Revision ||
		!after.NeedsReview || after.URLMode != model.EndpointURLLegacyExact || after.URLOverride != pending.URLOverride {
		t.Fatalf("refused PUT changed row: before=%+v after=%+v", pending, after)
	}

	rec = do(t, h, "POST", "/admin/api/upstream-endpoints",
		`{"upstream_id":`+itoa(upID)+`,"endpoint":"messages","url_mode":"canonical","needs_review":true,`+
			`"auth_profile":{"mode":"x_api_key"}}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create needs_review endpoint: status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}

	otherOverride := "https://review.example.com/v1/responses"
	rec = do(t, h, "PUT", "/admin/api/upstream-endpoints/"+itoa(other.ID),
		`{"url_override":`+mustJSON(t, otherOverride)+`,"expected_revision":`+itoa(other.Revision)+`}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("reviewed endpoint binding change: %d %s", rec.Code, rec.Body.String())
	}

	rec = do(t, h, "POST", "/admin/api/upstream-endpoints/"+itoa(pending.ID)+"/confirm-review",
		`{"url_override":`+mustJSON(t, override)+`,"expected_revision":`+itoa(pending.Revision)+`}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm-review: %d %s", rec.Code, rec.Body.String())
	}
	confirmed := decodeBody[model.UpstreamEndpoint](t, rec)
	if confirmed.NeedsReview || confirmed.URLMode != model.EndpointURLCanonical || confirmed.URLOverride != override {
		t.Fatalf("confirm-review did not clear review: %+v", confirmed)
	}

	changed := "https://review.example.com/v2/messages"
	rec = do(t, h, "PUT", "/admin/api/upstream-endpoints/"+itoa(confirmed.ID),
		`{"url_override":`+mustJSON(t, changed)+`,"expected_revision":`+itoa(confirmed.Revision)+`}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("binding change after confirm: %d %s", rec.Code, rec.Body.String())
	}
}
