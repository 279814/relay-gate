package api

import (
	"context"
	"net/http"

	"github.com/279814/relay-gate/internal/probe"
)

type SampleRecipeCandidateBuilder interface {
	BuildSampleCandidate(context.Context, int64) (probe.SampleRecipeCandidate, error)
}

// sampleProbeHeaders keeps the old read-only URL while exporting only a safe
// Recipe draft candidate from the shared sanitizer, never legacy overrides.
func (s *Server) sampleProbeHeaders(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if s.sampleCandidates == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"样本候选服务未装配"})
		return
	}
	candidate, err := s.sampleCandidates.BuildSampleCandidate(r.Context(), id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	version := candidate.Version
	writeJSON(w, http.StatusOK, map[string]any{
		"sample_id": candidate.SampleID, "upstream_id": candidate.UpstreamID, "skipped": candidate.Skipped,
		"candidate": map[string]any{"upstream_id": candidate.UpstreamID, "endpoint": candidate.Endpoint,
			"method": version.Method, "fixed_raw_query": version.FixedRawQuery, "headers": version.Headers,
			"body_text": string(version.Body), "stream_expected": version.StreamExpected, "timeout_profile": version.TimeoutProfile},
	})
}
