package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/probe"
	"github.com/279814/relay-gate/internal/store"
)

func endpointMutationHTTP(t *testing.T, method, url, body string) (int, []byte) {
	t.Helper()
	r, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+testAdminPW)
	r.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, data
}

type endpointFailingPublisher struct{ invalidates, refreshes int }

func (publisher *endpointFailingPublisher) Invalidate() { publisher.invalidates++ }
func (publisher *endpointFailingPublisher) Refresh() error {
	publisher.refreshes++
	return errRefreshBoom
}

func TestEndpointHTTPNoOpDoesNotInvalidateOrPublish(t *testing.T) {
	s, _ := newTestServer(t)
	up := metadataUpstream(t, s, "endpoint-noop", "synthetic-noop-upstream-key")
	ep, err := s.st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	publisher := &endpointFailingPublisher{}
	invalidator := &recordingInvalidator{}
	h := s.WithProbeAdmin(probe.NewService(s.st, nil, nil, nil, nil, nil)).WithConfigPublisher(publisher).WithInvalidator(invalidator).Routes(testAdminPW)
	server := httptest.NewServer(h)
	defer server.Close()
	status, data := endpointMutationHTTP(t, "PUT", server.URL+"/admin/api/upstream-endpoints/"+itoa(ep.ID), fmt.Sprintf(`{"expected_revision":%d,"auth_profile":{"manual_headers":[]}}`, ep.Revision))
	if status != 200 {
		t.Fatalf("no-op=%d %s", status, data)
	}
	after, err := s.st.GetEndpoint(ep.ID)
	routes, upstreams, names := invalidator.counts()
	if err != nil || !reflect.DeepEqual(*after, *ep) || publisher.invalidates != 0 || publisher.refreshes != 0 || routes+upstreams+names != 0 {
		t.Fatalf("empty update changed/published config: row=%+v err=%v publisher=%+v invalidations=%d", after, err, publisher, routes+upstreams+names)
	}
}

func TestEndpointHTTPCreateReportsPersistedActivationPending(t *testing.T) {
	s, _ := newTestServer(t)
	up := metadataUpstream(t, s, "endpoint-create-pending", "synthetic-create-upstream-key")
	up.Enabled = false
	if err := s.st.UpdateUpstreamWithRevision(context.Background(), &up, up.Revision); err != nil {
		t.Fatal(err)
	}
	ep, err := s.st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.st.DeleteEndpoint(ep.ID, ep.Revision); err != nil {
		t.Fatal(err)
	}
	publisher := &endpointFailingPublisher{}
	h := s.WithProbeAdmin(probe.NewService(s.st, nil, nil, nil, nil, nil)).WithConfigPublisher(publisher).Routes(testAdminPW)
	server := httptest.NewServer(h)
	defer server.Close()
	status, data := endpointMutationHTTP(t, "POST", server.URL+"/admin/api/upstream-endpoints", fmt.Sprintf(`{"upstream_id":%d,"endpoint":"messages","auth_profile":{"mode":"x_api_key","secret_ref":"upstream_api_key"}}`, up.ID))
	if status != 503 {
		t.Fatalf("create pending=%d %s", status, data)
	}
	var pending map[string]any
	if err := json.Unmarshal(data, &pending); err != nil {
		t.Fatal(err)
	}
	saved, err := s.st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal("503 falsely implied rollback")
	}
	if pending["persisted"] != true || pending["code"] != "config_activation_pending" || pending["resource"] != "endpoint" || pending["id"] != float64(saved.ID) || pending["new_revision"] != float64(saved.Revision) || publisher.refreshes != 1 {
		t.Fatalf("wrong pending identity=%v publisher=%+v", pending, publisher)
	}
}

func TestEndpointHTTPMutationRejectsNonEditableFields(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		for _, field := range []string{
			`"url_mode":"canonical"`, `"legacy_full_url_id":0`, `"legacy_full_url_revision":0`,
			`"legacy_compat_real_only":false`, `"needs_review":false`, `"id":123`, `"revision":9`,
			`"created_at":1`, `"updated_at":1`, `"unknown_legacy_setting":"private-value"`,
			`"auth_profile":{"mode":"legacy_auto_real_only","secret_ref":"upstream_api_key"}`,
			`"auth_profile":{"revision":1}`, `"auth_profile":{"calibrated_mode":"header_bearer"}`,
		} {
			t.Run(method+"/"+field, func(t *testing.T) {
				s, _ := newTestServer(t)
				up := metadataUpstream(t, s, "endpoint-dto", "synthetic-upstream-secret")
				ep, err := s.st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
				if err != nil {
					t.Fatal(err)
				}
				h := s.WithProbeAdmin(probe.NewService(s.st, nil, nil, nil, nil, nil)).Routes(testAdminPW)
				server := httptest.NewServer(h)
				defer server.Close()
				url := server.URL + "/admin/api/upstream-endpoints/" + itoa(ep.ID)
				body := fmt.Sprintf(`{"expected_revision":%d,%s}`, ep.Revision, field)
				if method == http.MethodPost {
					up.Enabled = false
					if err := s.st.UpdateUpstreamWithRevision(context.Background(), &up, up.Revision); err != nil {
						t.Fatal(err)
					}
					if err := s.st.DeleteEndpoint(ep.ID, ep.Revision); err != nil {
						t.Fatal(err)
					}
					url = server.URL + "/admin/api/upstream-endpoints"
					body = fmt.Sprintf(`{"upstream_id":%d,"endpoint":"messages","auth_profile":{"mode":"x_api_key","secret_ref":"upstream_api_key"},%s}`, up.ID, field)
				}
				status, data := endpointMutationHTTP(t, method, url, body)
				if status != 400 {
					t.Fatalf("forbidden field admitted: status=%d body=%s", status, data)
				}
				if strings.Contains(string(data), "private-value") {
					t.Fatal("rejected JSON echoed input")
				}
				after, err := s.st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
				if method == http.MethodPut && (err != nil || !reflect.DeepEqual(*after, *ep)) {
					t.Fatalf("rejected mutation changed Endpoint: before=%+v after=%+v err=%v", ep, after, err)
				}
				if method == http.MethodPost && !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("expected missing Endpoint, got %v", err)
				}
			})
		}
	}
}

func TestEndpointHTTPCreateAndPartialUpdateKeepServerOwnedIdentity(t *testing.T) {
	s, _ := newTestServer(t)
	up := metadataUpstream(t, s, "endpoint-happy", "synthetic-upstream-key")
	up.Enabled = false
	if err := s.st.UpdateUpstreamWithRevision(context.Background(), &up, up.Revision); err != nil {
		t.Fatal(err)
	}
	ep, err := s.st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.st.DeleteEndpoint(ep.ID, ep.Revision); err != nil {
		t.Fatal(err)
	}
	h := s.WithProbeAdmin(probe.NewService(s.st, nil, nil, nil, nil, nil)).Routes(testAdminPW)
	server := httptest.NewServer(h)
	defer server.Close()
	base := server.URL + "/admin/api/upstream-endpoints"
	status, data := endpointMutationHTTP(t, "POST", base, fmt.Sprintf(`{"upstream_id":%d,"endpoint":"messages","auth_profile":{"mode":"x_api_key","secret_ref":"upstream_api_key"}}`, up.ID))
	if status != 201 {
		t.Fatalf("create=%d %s", status, data)
	}
	var created model.UpstreamEndpoint
	if err := json.Unmarshal(data, &created); err != nil {
		t.Fatal(err)
	}
	if created.URLMode != model.EndpointURLCanonical || created.NeedsReview || created.LegacyCompatRealOnly || created.Revision != 1 || created.AuthProfile.Revision != 1 {
		t.Fatalf("ordinary creation minted provenance: %+v", created)
	}
	url := base + "/" + itoa(created.ID)
	status, data = endpointMutationHTTP(t, "PUT", url, fmt.Sprintf(`{"expected_revision":%d,"url_override":"https://endpoint.test/does-not-match-origin"}`, created.Revision))
	if status != 400 {
		t.Fatalf("cross-origin update=%d %s", status, data)
	}
	status, data = endpointMutationHTTP(t, "PUT", url, fmt.Sprintf(`{"expected_revision":%d,"auth_profile":{"mode":"header_bearer"}}`, created.Revision))
	if status != 200 {
		t.Fatalf("partial auth=%d %s", status, data)
	}
	var updated model.UpstreamEndpoint
	if err := json.Unmarshal(data, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.ID != created.ID || updated.UpstreamID != created.UpstreamID || updated.AuthProfile.SecretRef != created.AuthProfile.SecretRef || updated.Revision != created.Revision+1 {
		t.Fatalf("partial update lost baseline/identity: %+v", updated)
	}
	for _, request := range []struct {
		body   string
		status int
	}{{`{"expected_revision":1,"fixed_query_template":"x=1"}`, 409}, {fmt.Sprintf(`{"expected_revision":%d,"upstream_id":999}`, updated.Revision), 400}} {
		status, data = endpointMutationHTTP(t, "PUT", url, request.body)
		if status != request.status {
			t.Fatalf("stale/rehome=%d %s", status, data)
		}
	}
	after, err := s.st.GetEndpoint(created.ID)
	if err != nil || !reflect.DeepEqual(*after, updated) {
		t.Fatalf("rejected write changed canonical Endpoint: %+v %v", after, err)
	}
}

func TestEndpointHTTPLegacyURLReviewPreservesAuthUntilCalibration(t *testing.T) {
	s, _ := newTestServer(t)
	up := metadataUpstream(t, s, "endpoint-review-auth", "synthetic-upstream-key")
	ep, err := s.st.Endpoint(context.Background(), up.ID, model.EndpointMessages)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := store.NewCipher("test-passphrase-at-least-16-chars")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt(up.BaseURL + "/v1/messages")
	if err != nil {
		t.Fatal(err)
	}
	row, err := s.st.DB().Exec(`INSERT INTO legacy_full_url(upstream_id,url_enc,masked_url,fingerprint,inferred_endpoint,needs_review,revision,created_at,updated_at) VALUES (?,?,?,'audit-fingerprint','messages',1,1,1,1)`, up.ID, encrypted, up.BaseURL+"/***")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := row.LastInsertId()
	if _, err := s.st.DB().Exec(`UPDATE upstream_endpoint SET url_mode='legacy_exact',legacy_full_url_id=?,legacy_full_url_revision=1,needs_review=1,auth_mode='legacy_auto_real_only',legacy_compat_real_only=1,revision=revision+1 WHERE id=?`, id, ep.ID); err != nil {
		t.Fatal(err)
	}
	h := s.WithProbeAdmin(probe.NewService(s.st, nil, nil, nil, nil, nil)).Routes(testAdminPW)
	server := httptest.NewServer(h)
	defer server.Close()
	url := server.URL + "/admin/api/upstream-endpoints/" + itoa(ep.ID)
	status, data := endpointMutationHTTP(t, "GET", url, "")
	if status != 200 {
		t.Fatalf("historical GET=%d %s", status, data)
	}
	var historical model.UpstreamEndpoint
	if err := json.Unmarshal(data, &historical); err != nil {
		t.Fatal(err)
	}
	publisher := &endpointFailingPublisher{}
	s.WithConfigPublisher(publisher)
	status, data = endpointMutationHTTP(t, "POST", url+"/confirm-review", fmt.Sprintf(`{"expected_revision":%d,"url_override":%q}`, historical.Revision, up.BaseURL+"/v1/messages"))
	if status != 503 {
		t.Fatalf("historical review pending=%d %s", status, data)
	}
	var pending map[string]any
	if err := json.Unmarshal(data, &pending); err != nil {
		t.Fatal(err)
	}
	if pending["resource"] != "endpoint" || pending["id"] != float64(ep.ID) || pending["new_revision"] != float64(historical.Revision+1) || pending["persisted"] != true || publisher.refreshes != 1 {
		t.Fatalf("review pending identity=%v publisher=%+v", pending, publisher)
	}
	status, data = endpointMutationHTTP(t, "GET", url, "")
	if status != 200 {
		t.Fatalf("pending reviewed SQL read=%d %s", status, data)
	}
	var reviewed model.UpstreamEndpoint
	if err := json.Unmarshal(data, &reviewed); err != nil {
		t.Fatal(err)
	}
	if reviewed.NeedsReview || reviewed.URLMode != model.EndpointURLCanonical || !reviewed.LegacyCompatRealOnly || reviewed.AuthProfile.Mode != model.AuthModeLegacyAutoRealOnly || reviewed.AuthProfile.CalibratedMode != "" {
		t.Fatalf("URL review forged auth decision: %+v", reviewed)
	}
	replayStatus, replayBody := endpointMutationHTTP(t, "POST", url+"/confirm-review", fmt.Sprintf(`{"expected_revision":%d,"url_override":%q}`, historical.Revision, up.BaseURL+"/v1/messages"))
	if replayStatus != 409 || publisher.refreshes != 1 {
		t.Fatalf("review replay=%d %s publisher=%+v", replayStatus, replayBody, publisher)
	}
	status, data = endpointMutationHTTP(t, "PUT", url, fmt.Sprintf(`{"expected_revision":%d,"auth_profile":{"mode":"header_bearer"}}`, reviewed.Revision))
	if status != 400 {
		t.Fatalf("ordinary editor bypassed historical calibration: %d %s", status, data)
	}
}
