package proxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/transform"
)

func TestCompressedRequestDiagnosticsUseDecodedKnownSecretFact(t *testing.T) {
	const secret = "fixture-compressed-request-secret"
	hs := newHarness(t, nil)
	hs.cfg.snap.Upstreams[10].APIKey = secret
	reg := transform.NewRegistry(8)
	set, _ := reg.CreateSet("compressed-hashes")
	if _, err := reg.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Published", Value: "yes"}}, transform.FailClosed, transform.FailClosed, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.PublishSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Shadow", Value: "yes"}}, transform.FailClosed, transform.FailClosed, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.ShadowSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)
	wire := gzipBody(t, []byte(`{"model":"claude-opus-5","padding":"`+strings.Repeat("ordinary payload ", 500)+`","token":"`+secret+`"}`))
	if containsAttemptSecret(wire, []string{secret}) {
		t.Fatal("fixture credential is visible without decoding")
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(wire))
	req.Header = claudeCodeHeaders()
	req.Header.Set("X-Api-Key", hs.relayPW)
	req.Header.Set("Content-Encoding", "gzip")
	if rec := hs.serve(req); rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	for _, record := range reg.ListExecutions(0) {
		if record.Phase == "request" && (record.InputHash != "" || record.OutputHash != "") {
			t.Fatalf("compressed credential reached request diagnostic hash: %+v", record)
		}
	}
	if m := hs.sink.one(t).Metadata; m.RequestDiffReason != "secret_taint" || m.RequestInputHash != "" || m.RequestOutputHash != "" {
		t.Fatalf("compressed credential reached metadata: %+v", m)
	}
}

func TestCompressedResponseShadowOmitsUnverifiedBodyHashes(t *testing.T) {
	const secret = "fixture-compressed-response-secret"
	wire := gzipBody(t, []byte(`{"padding":"`+strings.Repeat("ordinary payload ", 500)+`","token":"`+secret+`"}`))
	if containsAttemptSecret(wire, []string{secret}) {
		t.Fatal("fixture credential is visible without decoding")
	}
	hs := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(wire)
	})
	hs.cfg.snap.Upstreams[10].APIKey = secret
	reg := transform.NewRegistry(8)
	set, _ := reg.CreateSet("compressed-shadow")
	if _, err := reg.UpdateDraft(set.ID, []transform.Rule{{Kind: transform.KindSetHeader, Name: "X-Shadow", Value: "yes"}}, transform.FailClosed, transform.FailClosed, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.ShadowSnapshot(set.ID, 100, 1); err != nil {
		t.Fatal(err)
	}
	hs.h.WithTransforms(reg)
	if rec := hs.serve(hs.anthropicRequest(`{"model":"claude-opus-5"}`)); rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), wire) {
		t.Fatal("client encoded bytes changed")
	}
	records := shadowPhase(reg, "response")
	if len(records) != 1 {
		t.Fatalf("response shadow records=%d", len(records))
	}
	r := records[0]
	if r.InputHash != "" || r.OutputHash != "" || strings.Contains(r.DiffSummary, transform.HashBytes(wire)) || !strings.Contains(r.DiffSummary, "omitted") {
		t.Fatalf("unverified compressed response hashed: %+v", r)
	}
}
