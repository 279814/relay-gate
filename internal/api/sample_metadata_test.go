package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestSampleMetadataReadsEveryAttemptWithoutHeadersOrCipherBodies(t *testing.T) {
	s, h := newTestServer(t)
	smp := &model.Sample{ReqID: "exact-metadata-group", Endpoint: "/v1/messages", InBody: []byte("PRIVATE-IN"), Attempts: []*model.SampleAttempt{
		{RouteID: 1, OutBody: []byte("PRIVATE-OUT"), RespBody: []byte("PRIVATE-RESP"), Metadata: model.AttemptMetadata{Version: 1, TransformVersionID: 7, Attempt: 1, Attempts: 2, Retried: true}},
		{RouteID: 2, Metadata: model.AttemptMetadata{Version: 1, TransformVersionID: 8, Attempt: 2, Attempts: 2, SyntheticCompletion: true}},
	}}
	if err := s.st.InsertSample(smp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB().Exec(`UPDATE sample_request SET in_headers='invalid',in_body='v2:broken';UPDATE sample_attempt SET out_headers='invalid',resp_headers='invalid',out_body='v2:broken',resp_body='v2:broken'`); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/admin/api/samples/%d/metadata", smp.ID)
	rec := do(t, h, "GET", path, "", true)
	if rec.Code != 200 {
		t.Fatalf("metadata loaded body or unavailable: %d %s", rec.Code, rec.Body.String())
	}
	for _, forbidden := range []string{"PRIVATE-", "in_body", "out_body", "resp_body", "in_headers", "out_headers", "resp_headers", "out_url", "v2:broken"} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Fatalf("metadata exposed %s", forbidden)
		}
	}
	var got struct {
		ReqID    string `json:"req_id"`
		Attempts []struct {
			RouteID  int64                 `json:"route_id"`
			Metadata model.AttemptMetadata `json:"metadata"`
		} `json:"attempts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ReqID != smp.ReqID || len(got.Attempts) != 2 || got.Attempts[0].Metadata.TransformVersionID != 7 || !got.Attempts[0].Metadata.Retried || !got.Attempts[1].Metadata.SyntheticCompletion {
		t.Fatalf("not actual per-attempt metadata: %+v", got)
	}
	if rec := do(t, h, "GET", path, "", false); rec.Code != 401 {
		t.Fatalf("metadata bypassed admin auth: %d", rec.Code)
	}
}
