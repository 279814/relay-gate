package proxy

import (
	"bytes"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/router"
	"github.com/279814/relay-gate/internal/sample"
	"github.com/279814/relay-gate/internal/transform"
)

type bodyDiffFacts struct {
	inputHash, outputHash, reason string
	bodyChanged, headersChanged   bool
}

func preparedAttemptMetadata(pre *preambleResult, cand *router.Candidate, target outbound.ResolvedTarget, prepared preparedRequest, executionID string, observed bool) model.AttemptMetadata {
	m := prepared.metadata
	m.Version = 1
	m.ExecutionID = executionID
	m.ConfigGeneration = pre.snapshot.Generation
	if pre.published != nil {
		m.ConfigGeneration = pre.published.Generation
		if pre.published.Probe != nil {
			m.SettingsRevision = pre.published.Probe.SettingsRowRevision
		}
	}
	m.EndpointID, m.EndpointRevision, m.AuthProfileRevision = target.EndpointID, target.EndpointRevision, target.AuthProfile.Revision
	m.UpstreamNetworkRevision, m.UpstreamCredentialRevision = cand.Upstream.NetworkRevision, cand.Upstream.CredentialRevision
	m.RouteRevision, m.RouteCapabilityRevision = cand.Route.Revision, cand.Route.CapabilityRevision
	m.ModelRevision, m.ModelCapabilityRevision = cand.ModelName.Revision, cand.ModelName.CapabilityRevision
	m.TransformVersionID = prepared.version
	m.RequestTransformRevision = pre.transforms.BindingRevision(cand.Route.ID, target.EndpointID)
	m.RetryPolicy = pre.settings.RetryPolicy.Normalize()
	m.RequestWriteState, m.ErrorClass = "unknown", "unknown"
	m.CapabilityEffect = "unavailable"
	if observed {
		m.CapabilityEffect = "pending"
	}
	m.ResponseDiffReason = "incomplete"
	if m.RequestDiffReason == "sample_disabled" {
		m.ResponseDiffReason = "sample_disabled"
	}
	return m
}
func safeAttemptBodyHashes(before, after []byte, keys []string, tainted bool) (string, string, string) {
	if tainted || containsAttemptSecret(before, keys) || containsAttemptSecret(after, keys) {
		return "", "", "secret_taint"
	}
	return transform.HashBytes(before), transform.HashBytes(after), "recorded"
}

func containsAttemptSecret(body []byte, keys []string) bool {
	return !bytes.Equal(sample.RedactBodyKeys(body, keys), body)
}

func safeAttemptBodyHash(body []byte, keys []string) string {
	if containsAttemptSecret(body, keys) {
		return ""
	}
	return transform.HashBytes(body)
}
func attemptRequestWriteState(la *liveAttempt) string {
	if la.trace == nil {
		return "unknown"
	}
	trace := la.trace.Snapshot()
	if !trace.RequestWrittenAt.IsZero() && !trace.RequestWriteFailed {
		return "written"
	}
	if !trace.GotConnAt.IsZero() || !trace.RequestWrittenAt.IsZero() {
		return "possibly_written"
	}
	if la.at != nil && la.at.Result() != nil && la.at.Result().Status > 0 {
		return "possibly_written"
	}
	if !trace.SentAt.IsZero() {
		return "not_written"
	}
	return "unknown"
}
