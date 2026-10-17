package probe

import (
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

// recordRealModelNotFound applies the same §8.12 Route config_error observation
// probes record when ErrBody carries a structured code in modelNotFoundCodes.
//
// Returns true when the observation was handled as model_not_found (caller must
// not also feed RouteHealth Tracker — config_error excludes via Capability, not
// dead). generation mirrors Tracker.Report: after Semantic InvalidateRoute /
// Forget, a late in-flight result must not ApplyCommitted onto a new Route that
// reused the same numeric id (probe CommitProbeObservation uses RouteCreatedAt
// for the same incarnation hole).
func (r *Reporter) recordRealModelNotFound(routeID int64, generation uint64, res *health.ResultView) bool {
	if r == nil || r.caps == nil || res == nil || routeID <= 0 {
		return false
	}
	if !res.Endpoint.Valid() {
		return false
	}
	// Transport / client errors are not model-not-found evidence.
	if res.Err != nil && !health.IsUpstreamFault(res.Err) {
		return false
	}
	ct := ""
	if res.Header != nil {
		ct = res.Header.Get("Content-Type")
	}
	event := structuredRemoteErrorFromBody(res.ErrBody, ct)
	if !isModelNotFound(event) {
		return false
	}
	if res.CapabilityObserved {
		// The send-time observer commits this evidence through the shared order
		// and token checks. Do not block forwarding or race a manual retest with
		// the legacy synchronous persistence path.
		return true
	}
	if !r.routeGenerationCurrent(routeID, generation) {
		// Stale incarnation: drop ApplyCommitted, still suppress RouteHealth.
		return true
	}
	r.applyRouteModelNotFound(routeID, res.Endpoint, res.Status)
	return true
}

// routeGenerationCurrent is the real-traffic analogue of CommitProbeObservation's
// RouteCreatedAt incarnation check. generation == 0 means unbound (tests /
// first mark before TryAcquire): apply only when the live RouteHealth generation
// is also 0. A zero argument against a non-zero live generation is dropped so a
// caller that forgot the generation cannot poison a reused id. generation > 0
// must match the current RouteHealth entry after Claim / EnsureGeneration.
func (r *Reporter) routeGenerationCurrent(routeID int64, generation uint64) bool {
	viewer, ok := r.track.(interface {
		GenerationOf(routeID int64) uint64
	})
	if !ok {
		return true
	}
	live := viewer.GenerationOf(routeID)
	if generation == 0 {
		return live == 0
	}
	return live == generation
}

func (r *Reporter) applyRouteModelNotFound(routeID int64, endpoint model.EndpointKind, status int) {
	selector := model.EvidencePolicySelector{
		Kind:     model.EvidenceRealTraffic,
		Endpoint: endpoint,
	}
	settings := model.DefaultSettings()
	if r.caps.settings != nil {
		if s, err := r.caps.settings.Settings(); err == nil {
			settings = s
		}
	}
	policy, err := revisioncodec.BuildCapabilityEvidencePolicy(settings, selector)
	if err != nil {
		return
	}
	fp := revisioncodec.ProbeSettingsFingerprint(policy)
	nowMS := time.Now().UnixMilli()
	r.caps.ApplyCommitted(&model.EndpointCapability{
		ScopeType:                model.RecipeScopeRoute,
		ScopeID:                  routeID,
		Endpoint:                 endpoint,
		PolicySelector:           selector,
		State:                    model.CapabilityConfigError,
		ErrorClass:               model.ErrorModelNotFound,
		StatusCode:               status,
		ObservationToken:         "",
		ProbeSettingsFingerprint: fp,
		LastObservationOrder:     nowMS,
		ObservedAt:               nowMS,
		ExpiresAt:                0, // §8.13: config_error 不自动过期
		RedactedDetail:           string(model.ErrorModelNotFound),
	})
	r.caps.persistRouteConfigError(routeID, endpoint, status, model.ErrorModelNotFound, nowMS)
}

// structuredRemoteErrorFromBody builds a ProtocolEvent from a real-traffic
// ErrBody sample. Only structured error payloads are considered — the same
// gate as classifyReal's IsStructuredErrorPayload path — so assistant text
// that merely mentions "model_not_found" never matches.
func structuredRemoteErrorFromBody(body []byte, contentType string) ProtocolEvent {
	if len(body) == 0 || len(body) > 64<<10 {
		return ProtocolEvent{}
	}
	decoder, err := NewDecoder(DecoderSpec{Endpoint: model.EndpointMessages, Protocol: model.ProtoAnthropic}, WireAuto, 64<<10, 64<<10)
	if err != nil {
		return ProtocolEvent{}
	}
	events, err := decoder.Feed(body)
	if err != nil {
		return ProtocolEvent{}
	}
	tail, err := decoder.Finish()
	if err != nil {
		return ProtocolEvent{}
	}
	events = append(events, tail...)
	for _, event := range events {
		if event.Kind == EventRemoteError {
			return event
		}
	}
	return ProtocolEvent{}
}
