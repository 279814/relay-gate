package probe

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/revisioncodec"
	"github.com/279814/relay-gate/internal/sample"
)

// capabilityTraffic reuses the bounded observer queue and committed observation
// path for count_tokens and structured model_not_found. It retains summaries.
type capabilityTraffic struct {
	recipe     ResolvedRecipe
	req        ExecutionRequest
	decoder    Decoder
	classifier *ResponseClassifier
	decodeErr  error
}

func prepareCapabilityTraffic(ctx context.Context, snap *livecfg.ProbeSnapshot, target health.AttemptTarget, order int64) *capabilityTraffic {
	if !target.Endpoint.Valid() || target.Endpoint == model.EndpointModels || order <= 0 {
		return nil
	}
	route := snap.Routes[target.RouteID]
	if route == nil || route.UpstreamID != target.UpstreamID {
		return nil
	}
	mn := snap.ModelNames[route.ModelNameID]
	if mn == nil {
		return nil
	}
	upConfig := snap.Upstreams[target.UpstreamID]
	endpoint := snap.Endpoints[target.UpstreamID][target.Endpoint]
	if upConfig == nil || endpoint == nil {
		return nil
	}
	// A request may already hold an older routing snapshot. Never assign its
	// response the token of a configuration it did not actually use.
	for _, revision := range [][2]int64{
		{target.Config.EndpointID, endpoint.ID},
		{target.Config.EndpointRevision, endpoint.Revision},
		{target.Config.AuthProfileRevision, endpoint.AuthProfile.Revision},
		{target.Config.UpstreamNetworkRevision, upConfig.NetworkRevision},
		{target.Config.UpstreamCredentialRevision, upConfig.CredentialRevision},
		{target.Config.RouteCapabilityRevision, route.CapabilityRevision},
		{target.Config.ModelCapabilityRevision, mn.CapabilityRevision},
		{target.Config.UpstreamCreatedAt, upConfig.CreatedAt},
		{target.Config.RouteCreatedAt, route.CreatedAt},
	} {
		if revision[0] != 0 && revision[0] != revision[1] {
			return nil
		}
	}
	resolver := NewRecipeResolver(snapshotRecipeSource{snap}).WithNotFound(func(err error) bool {
		return errors.Is(err, errSnapshotRecipeNotFound)
	})
	recipe, err := resolver.Resolve(ctx, RecipeQuery{UpstreamID: target.UpstreamID, RouteID: target.RouteID, Endpoint: target.Endpoint})
	if err != nil {
		return nil
	}
	recipe.Facts.Use = model.BindingRealTrafficContext
	up := &model.Upstream{ID: target.UpstreamID}
	_, _, expectation, policy, err := buildL2Expectations(snap, up, route, target.Endpoint, recipe)
	if err != nil {
		return nil
	}
	return &capabilityTraffic{recipe: recipe, req: ExecutionRequest{
		ExecutionID: sample.NewReqID(), Trigger: model.TriggerRealTraffic, Upstream: up, Route: route, ModelName: mn,
		Endpoint: target.Endpoint, ObservationOrder: order, CapabilityExpectation: expectation, CapabilityPolicy: policy,
	}}
}

func (c *capabilityTraffic) consume(event trafficEvent) {
	if c == nil || c.decodeErr != nil {
		return
	}
	if event.kind == "headers" {
		// The count_tokens forwarding path preserves wire bytes. Until it also
		// supplies decoded bytes, encoded responses are unobserved, not failures.
		encoding := strings.TrimSpace(event.header.Get("Content-Encoding"))
		if encoding != "" && !strings.EqualFold(encoding, "identity") {
			c.decodeErr = errors.New("observer_content_encoding")
			return
		}
		c.classifier = NewResponseClassifier(ObserveReal, c.req.Endpoint, event.status, event.header, event.at)
		c.decoder, c.decodeErr = NewDecoder(DecoderSpec{Endpoint: c.req.Endpoint, Protocol: c.req.ModelName.Protocol}, WireAuto, perAttemptCopyBudget, perAttemptCopyBudget)
		return
	}
	if c.decoder != nil && len(event.chunk) > 0 {
		var events []ProtocolEvent
		events, c.decodeErr = c.decoder.Feed(event.chunk)
		for _, value := range events {
			c.classifier.Observe(value)
		}
	}
}

func (c *capabilityTraffic) observation(v health.AttemptFinish, timing sendTiming, incomplete bool, status int, header http.Header, resolvedURLHash string) *model.ProbeObservation {
	if c == nil {
		return nil
	}
	if v.ConfigFacts != nil {
		revision := c.req.CapabilityExpectation.Revision
		for _, fact := range [][2]int64{
			{v.ConfigFacts.EndpointID, revision.EndpointID},
			{v.ConfigFacts.EndpointRevision, revision.EndpointRevision},
			{v.ConfigFacts.AuthProfileRevision, revision.AuthProfile},
		} {
			if fact[0] != 0 && fact[0] != fact[1] {
				return nil
			}
		}
		resolvedURLHash = v.ConfigFacts.ResolvedURLHash
	}
	if c.classifier == nil {
		c.classifier = NewResponseClassifier(ObserveReal, c.req.Endpoint, status, header, time.UnixMilli(timing.responseHeaderAtMS))
	}
	if c.decoder != nil && c.decodeErr == nil {
		var tail []ProtocolEvent
		tail, c.decodeErr = c.decoder.Finish()
		for _, event := range tail {
			c.classifier.Observe(event)
		}
	}
	var cause error
	if v.ClientCanceled {
		cause = ErrClientCanceled
	} else if v.ServiceCanceled {
		cause = ErrServiceShutdown
	}
	decision := c.classifier.Finish(v.ReadErr, cause)
	if v.ConfigError && cause == nil {
		decision = Decision{Final: true, Capability: model.CapabilityConfigError, ErrorClass: model.ErrorConfig, Scope: model.ScopeRouteEndpoint}
	}
	if c.req.Endpoint != model.EndpointCountTokens && cause == nil &&
		c.classifier.remoteError != nil && isModelNotFound(*c.classifier.remoteError) {
		decision.Capability = model.CapabilityConfigError
		decision.ErrorClass = model.ErrorModelNotFound
		decision.Scope = model.ScopeRouteEndpoint
	}
	// count_tokens has no auth calibration (§10.3); its live 401/403 is an
	// endpoint config_error, while model probes retain the calibration path.
	if c.req.Endpoint == model.EndpointCountTokens && decision.ErrorClass == model.ErrorAuthRejected {
		decision.Capability = model.CapabilityConfigError
	}
	statusEvidence := c.req.Endpoint == model.EndpointCountTokens &&
		(status == http.StatusUnauthorized || status == http.StatusForbidden ||
			status == http.StatusNotFound || status == http.StatusMethodNotAllowed)
	if (incomplete || c.decodeErr != nil) && !statusEvidence && !v.ConfigError {
		decision = Decision{Final: true, ErrorClass: model.ErrorIgnored, Scope: model.ScopeNone, StatusCode: decision.StatusCode}
	}
	// Existing RouteHealth reporting remains authoritative for other model
	// outcomes. Only this structured configuration error belongs to this path.
	if c.req.Endpoint != model.EndpointCountTokens && decision.ErrorClass != model.ErrorModelNotFound && decision.ErrorClass != model.ErrorConfig {
		return nil
	}
	exec := (&Executor{}).buildExecution(c.req, c.recipe, decision, timing, 0, 0, 0, false, resolvedURLHash, "")
	exec.RealRequestShapeUnavailableReason = model.ShapeUnsupported
	exec.ObserverIncomplete = incomplete || c.decodeErr != nil
	if incomplete {
		exec.ObserverIncompleteReason = model.ObserverCapacity
	} else if c.decodeErr != nil {
		exec.ObserverIncompleteReason = model.ObserverDecodeFailure
	}
	obs := &model.ProbeObservation{Execution: exec, CapabilityExpectation: c.req.CapabilityExpectation, CapabilityPolicy: c.req.CapabilityPolicy}
	hash, err := revisioncodec.NewProbeEvidenceHash(*obs)
	if err != nil {
		return nil
	}
	obs.Execution.EvidenceHash = hash
	return obs
}

func (o *trafficObserver) queueCapabilityObservation() {
	snap := o.trace.Snapshot()
	observation := o.capability.observation(o.finishView,
		trafficTiming(snap.SentAt, snap.ResponseHeaderAt, snap.DoneAt), o.incomplete != "" || !o.full,
		o.status, o.header, o.target.Config.ResolvedURLHash)
	if observation == nil {
		return
	}
	select {
	case o.m.queue <- observation:
	default:
		o.m.persistDrops.Add(1)
	}
}

func trafficTiming(sent, header, done time.Time) sendTiming {
	return sendTiming{sentAtMS: msOrZero(sent), responseHeaderAtMS: msOrZero(header), doneAtMS: msOrZero(done)}
}
