package probe

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/proxy"
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
func (r *Reporter) recordRealModelNotFound(routeID int64, generation uint64, res *proxy.ResultView) bool {
	if r == nil || r.caps == nil || res == nil || routeID <= 0 {
		return false
	}
	if !res.Endpoint.Valid() {
		return false
	}
	// Transport / client errors are not model-not-found evidence.
	if res.Err != nil && !proxy.IsUpstreamFault(res.Err) {
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
}

// structuredRemoteErrorFromBody builds a ProtocolEvent from a real-traffic
// ErrBody sample. Only structured error payloads are considered — the same
// gate as classifyReal's IsStructuredErrorPayload path — so assistant text
// that merely mentions "model_not_found" never matches.
func structuredRemoteErrorFromBody(body []byte, contentType string) ProtocolEvent {
	if !proxy.IsStructuredErrorPayload(body, contentType) {
		return ProtocolEvent{}
	}
	raw := extractStructuredErrorJSON(body, contentType)
	if len(raw) == 0 {
		return ProtocolEvent{}
	}
	return remoteErrorEvent("", raw)
}

func extractStructuredErrorJSON(body []byte, contentType string) json.RawMessage {
	payload := body
	if strings.Contains(strings.ToLower(contentType), "text/event-stream") {
		payload = firstSSEErrorData(body)
		if len(payload) == 0 {
			return nil
		}
	}
	payload = bytes.TrimSpace(payload)
	if len(payload) == 0 || payload[0] != '{' {
		return nil
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(payload, &top) != nil {
		return nil
	}
	// Decoder path: nested error object is the classification input.
	if nested, ok := top["error"]; ok && len(bytes.TrimSpace(nested)) > 0 &&
		!bytes.Equal(bytes.TrimSpace(nested), []byte("null")) {
		trimmed := bytes.TrimSpace(nested)
		if len(trimmed) > 0 && trimmed[0] == '{' {
			return nested
		}
	}
	return payload
}

func firstSSEErrorData(body []byte) []byte {
	var curEvent []byte
	for _, raw := range bytes.Split(body, []byte("\n")) {
		line := bytes.TrimRight(raw, "\r")
		switch {
		case len(bytes.TrimSpace(line)) == 0:
			curEvent = nil
		case bytes.HasPrefix(line, []byte("event:")):
			curEvent = bytes.TrimSpace(line[len("event:"):])
		case bytes.HasPrefix(line, []byte("data:")):
			data := bytes.TrimSpace(line[len("data:"):])
			if bytes.Equal(curEvent, []byte("error")) {
				return data
			}
			if proxy.IsStructuredErrorPayload(data, "application/json") {
				return data
			}
		}
	}
	return nil
}
