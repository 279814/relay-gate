package store

import (
	"context"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/security"
	"net/http"
	"testing"
)

func TestSecurityEvidenceUnavailableForUnknownIncompleteOrWrongIdentity(t *testing.T) {
	for _, name := range []string{"legacy_view", "prefix", "sample_truncated", "scan_incomplete", "scan_truncated", "unknown_upstream", "other_upstream", "empty_req_id", "admin_scan"} {
		t.Run(name, func(t *testing.T) {
			st := testStore(t)
			f := security.Finding{ID: "finding", Source: "passive", ReqID: "exact", RouteID: 7, UpstreamID: 42, ScannerVersion: security.ScannerVersion, RuleVersion: security.RuleVersion, BytesScanned: 10}
			a := &model.SampleAttempt{RouteID: 7, UpstreamID: 42, RespStatus: 200, RespHeaders: http.Header{}, RespBody: []byte("private-response-bytes"), ResponseCaptureView: "upstream_response", Metadata: model.AttemptMetadata{Version: 1}}
			switch name {
			case "legacy_view":
				a.ResponseCaptureView = "legacy"
			case "prefix":
				a.ResponseCaptureView = "upstream_attempt_prefix"
			case "sample_truncated":
				a.Truncated = model.TruncRespBody
			case "scan_incomplete":
				f.IncompleteReason = "capture_gap"
			case "scan_truncated":
				f.Truncated = true
			case "unknown_upstream":
				f.UpstreamID = 0
			case "other_upstream":
				f.UpstreamID = 99
			case "empty_req_id":
				f.ReqID = ""
			case "admin_scan":
				f.Source = "admin_scan"
			}
			if err := st.InsertSample(&model.Sample{ReqID: "exact", InMethod: "POST", Endpoint: "/v1/messages", InHeaders: http.Header{}, Attempts: []*model.SampleAttempt{a}}); err != nil {
				t.Fatal(err)
			}
			if err := st.InsertSecurityFinding(f); err != nil {
				t.Fatal(err)
			}
			for _, body := range []bool{false, true} {
				got, err := st.SecurityFindingEvidence(context.Background(), f.ID, body)
				if err != nil || got.Available || len(got.Body) > 0 || got.Reason == "" {
					t.Fatalf("unsafe unavailable state=%+v err=%v", got, err)
				}
			}
		})
	}
}
