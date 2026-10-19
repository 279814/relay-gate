package store

import (
	"context"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestSampleCaptureViewPersistsExplicitRawFactsWithoutGuessingLegacy(t *testing.T) {
	st := testStore(t)
	for _, tc := range []struct {
		name, marker, want string
		version            int
		retired            bool
	}{
		{"legacy metadata", "", "client_response", 1, false},
		{"legacy retry", "", "upstream_attempt_prefix", 1, true},
		{"no metadata", "", "unknown", 0, false},
		{"raw response", "upstream_response", "upstream_response", 1, false},
		{"raw prefix", "upstream_attempt_prefix", "upstream_attempt_prefix", 1, true},
		{"final raw prefix", "upstream_attempt_prefix", "upstream_attempt_prefix", 1, false},
		{"complete retry", "upstream_response", "upstream_response", 1, true},
		{"no response", "no_response", "no_response", 1, false},
		{"Secret omission", "omitted_secret", "omitted_secret", 1, false},
		{"unverified omission", "omitted_unverified", "omitted_unverified", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			smp := &model.Sample{ReqID: tc.name, Attempts: []*model.SampleAttempt{{ResponseCaptureView: tc.marker, RespBody: []byte("saved bytes"), Metadata: model.AttemptMetadata{Version: tc.version, Retried: tc.retired, ResponseView: "upstream_response"}}}}
			if err := st.InsertSample(smp); err != nil {
				t.Fatal(err)
			}
			got, err := st.GetSample(smp.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Metadata.ResponseView != tc.want {
				t.Fatalf("view guessed from current code/unpersisted marker: got %s want %s", got.Metadata.ResponseView, tc.want)
			}
			if _, err := st.db.Exec(`UPDATE sample_request SET in_body='v2:broken';UPDATE sample_attempt SET resp_body='v2:broken' WHERE request_id=?`, smp.ID); err != nil {
				t.Fatal(err)
			}
			metadata, err := st.GetSampleMetadata(context.Background(), smp.ID)
			if err != nil {
				t.Fatal(err)
			}
			if metadata.Attempts[0].Metadata.ResponseView != tc.want {
				t.Fatalf("metadata lost persisted view: %+v", metadata.Attempts[0].Metadata)
			}
		})
	}
}

func TestSampleCaptureViewRejectsUnknownMarkerAtomically(t *testing.T) {
	for _, version := range []int{0, 1} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			st := testStore(t)
			smp := &model.Sample{Attempts: []*model.SampleAttempt{{ResponseCaptureView: "guessed_raw", Metadata: model.AttemptMetadata{Version: version}}}}
			if err := st.InsertSample(smp); err == nil {
				t.Fatal("accepted an unknown/non-versioned raw marker")
			}
			if n, err := st.CountSamples(); err != nil || n != 0 {
				t.Fatalf("marker failure partially inserted sample: count=%d err=%v", n, err)
			}
		})
	}
}
