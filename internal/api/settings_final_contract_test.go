package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

func TestSettingsFinalHTTPRequiresExplicitClientRevision(t *testing.T) {
	_, handler := newTestServer(t)
	response := do(t, handler, http.MethodGet, "/admin/api/settings", "", true)
	var payload struct {
		Settings map[string]json.RawMessage `json:"settings"`
		Revision int64                      `json:"revision"`
		Limits   map[string]int             `json:"limits"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || payload.Revision < 1 || payload.Limits["min_real_first_semantic_sec"] != 300 {
		t.Fatalf("GET needs current Settings revision and stage limits: %d %s", response.Code, response.Body.String())
	}
	for _, legacy := range []string{"real_first_token_sec", "l2_first_token_sec", "count_tokens_sec"} {
		if _, ok := payload.Settings[legacy]; ok {
			t.Errorf("GET exposed legacy key %s", legacy)
		}
	}
}

func TestSettingsFinalHTTPActivationPendingPreservesCommitAndRejectsReplay(t *testing.T) {
	server, handler, source, publisher := newLivecfgServer(t)
	if _, err := source.Settings(); err != nil {
		t.Fatal(err)
	}
	publisher.mu.Lock()
	publisher.refreshErr = errors.New("fixture publish failure")
	publisher.skipInnerRefresh = true
	publisher.mu.Unlock()
	response := do(t, handler, http.MethodPut, "/admin/api/settings", `{"expected_revision":1,"count_tokens_connect_sec":2,"count_tokens_total_sec":11}`, true)
	var pending struct {
		Code      string `json:"code"`
		Persisted bool   `json:"persisted"`
		Revision  int64  `json:"new_revision"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}
	if response.Code != 503 || pending.Code != "config_activation_pending" || !pending.Persisted || pending.Revision != 2 {
		t.Fatalf("missing persisted pending metadata: %d %s", response.Code, response.Body.String())
	}
	stored, revision, err := server.st.GetSettingsWithRevision()
	if err != nil || revision != 2 || stored.CountTokensConnectSec != 2 || stored.CountTokensTotalSec != 11 {
		t.Fatal("pending response lost the actual committed settings")
	}
	beforeInv, beforeRef := publisher.counts()
	replayed := do(t, handler, http.MethodPut, "/admin/api/settings", `{"expected_revision":1,"count_tokens_connect_sec":2,"count_tokens_total_sec":11}`, true)
	afterInv, afterRef := publisher.counts()
	if replayed.Code != 409 || beforeInv != afterInv || beforeRef != afterRef {
		t.Fatal("stale pending replay did not conflict before publishing")
	}
}

func TestSettingsFinalHTTPPublishesExactStageFingerprintWithoutChangingOtherSide(t *testing.T) {
	_, handler, source, _ := newLivecfgServer(t)
	before, err := source.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	real := model.EvidencePolicySelector{Kind: model.EvidenceRealTraffic, Endpoint: model.EndpointMessages}
	l2 := model.EvidencePolicySelector{Kind: model.EvidenceL2, Endpoint: model.EndpointMessages, TimeoutProfile: model.TimeoutL2Standard}
	realBefore, err := revisioncodec.BuildCapabilityEvidencePolicy(before.Settings, real)
	if err != nil {
		t.Fatal(err)
	}
	l2Before, err := revisioncodec.BuildCapabilityEvidencePolicy(before.Settings, l2)
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, handler, http.MethodPut, "/admin/api/settings", `{"expected_revision":1,"l2_first_semantic_sec":337}`, true)
	if response.Code != 200 {
		t.Fatalf("update: %d %s", response.Code, response.Body.String())
	}
	after, err := source.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	realAfter, err := revisioncodec.BuildCapabilityEvidencePolicy(after.Settings, real)
	if err != nil {
		t.Fatal(err)
	}
	l2After, err := revisioncodec.BuildCapabilityEvidencePolicy(after.Settings, l2)
	if err != nil {
		t.Fatal(err)
	}
	if after.Probe.SettingsRowRevision != 2 || after.Probe.Settings.L2FirstSemanticSec != 337 || l2After.Stages.FirstSemantic != 337000 || revisioncodec.ProbeSettingsFingerprint(l2Before) == revisioncodec.ProbeSettingsFingerprint(l2After) || revisioncodec.ProbeSettingsFingerprint(realBefore) != revisioncodec.ProbeSettingsFingerprint(realAfter) {
		t.Fatal("published snapshot, runtime stage and purpose fingerprint diverged")
	}
}

func TestSettingsFinalHTTPRejectsImplicitRevisionAndLegacyWrites(t *testing.T) {
	_, handler := newTestServer(t)
	for _, body := range []string{`{"sample_enabled":false}`, `{"expected_revision":0,"sample_enabled":false}`, `{"expected_revision":1,"real_first_token_sec":900}`, `{"expected_revision":1,"l2_first_token_sec":30}`, `{"expected_revision":1,"count_tokens_sec":30}`} {
		response := do(t, handler, http.MethodPut, "/admin/api/settings", body, true)
		if response.Code != 400 {
			t.Errorf("invalid final contract accepted: %d %s", response.Code, response.Body.String())
		}
	}
}
