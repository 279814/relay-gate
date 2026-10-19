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

// capabilityTraffic parses original upstream bytes into bounded summaries and
// commits real observations through the same expectations as synthetic probes.
type capabilityTraffic struct {
	progress      *trafficProgress
	recipe        ResolvedRecipe
	req           ExecutionRequest
	decoder       Decoder
	classifier    *ResponseClassifier
	decodeErr     error
	encoding      string
	responseBytes int64
	decodeWork    time.Duration
	shape         model.ClientRequestShape
	shapeReason   model.RequestShapeUnavailableReason
	requestBytes  int64

	firstByteAt     time.Time
	firstEventAt    time.Time
	firstSemanticAt time.Time
	lastInputAt     time.Time
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
	reach, reachPolicy, expectation, policy, err := buildRealExpectations(snap, up, route, target.Endpoint, recipe)
	if err != nil {
		return nil
	}
	executionID := target.ExecutionID
	if executionID == "" {
		executionID = sample.NewReqID()
	}
	return &capabilityTraffic{recipe: recipe, req: ExecutionRequest{
		ExecutionID: executionID, Trigger: model.TriggerRealTraffic, Upstream: up, Route: route, ModelName: mn,
		Endpoint: target.Endpoint, ObservationOrder: order, CapabilityExpectation: expectation, CapabilityPolicy: policy,
		ReachabilityExpectation: reach, ReachabilityPolicy: reachPolicy,
		healthIdentity: capturedRouteHealthIdentity(snap, expectation, reach, nil),
	}, shapeReason: model.ShapeUnsupported}
}

func (o *trafficObserver) TryRequest(view health.AttemptRequestView) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.finished || o.capability == nil {
		return
	}
	c := o.capability
	c.requestBytes = int64(len(view.Body))
	c.shape, c.shapeReason = SanitizeRequestShape(c.req.Endpoint, view)
}

func (c *capabilityTraffic) consume(event trafficEvent) {
	if c == nil || c.decodeErr != nil {
		return
	}
	if event.kind == "headers" {
		c.encoding = strings.ToLower(strings.TrimSpace(event.header.Get("Content-Encoding")))
		c.classifier = NewResponseClassifier(ObserveReal, c.req.Endpoint, event.status, event.header, event.at)
		c.decoder, c.decodeErr = NewDecoder(DecoderSpec{Endpoint: c.req.Endpoint, Protocol: c.req.ModelName.Protocol}, WireAuto, trafficDecodedLimit, trafficDecodedLimit)
		return
	}
	if c.decoder != nil && len(event.chunk) > 0 {
		c.lastInputAt = event.at
		if c.firstByteAt.IsZero() {
			c.firstByteAt = event.at
		}
		c.feed(event.chunk, event.at)
	}
}

const trafficDecodedLimit = 1 << 20
const trafficDecodeCPULimit = 25 * time.Millisecond

var errTrafficDecodeDeadline = errors.New("observer decode deadline")
var errTrafficObserverPanic = errors.New("observer worker panic")

func (c *capabilityTraffic) feed(body []byte, at time.Time) {
	started := time.Now()
	events, err := c.decoder.Feed(body)
	c.decodeWork += time.Since(started)
	c.accept(events, at)
	if err != nil {
		c.decodeErr = err
	} else if c.decodeWork > trafficDecodeCPULimit {
		c.decodeErr = errTrafficDecodeDeadline
	}
}

func (c *capabilityTraffic) accept(events []ProtocolEvent, at time.Time) {
	for _, event := range events {
		if c.progress != nil {
			c.progress.accept(event, at)
		}
		if c.firstEventAt.IsZero() {
			c.firstEventAt = at
		}
		if event.Semantic && c.firstSemanticAt.IsZero() {
			c.firstSemanticAt = at
		}
		c.classifier.Observe(event)
	}
}

func (c *capabilityTraffic) finishDecode() {
	defer func() {
		if recover() != nil {
			c.decodeErr = errTrafficObserverPanic
		}
	}()
	if c.decoder == nil || c.decodeErr != nil {
		return
	}
	events, err := c.decoder.Finish()
	c.accept(events, c.lastInputAt)
	c.decodeErr = err
}

func (c *capabilityTraffic) observation(v health.AttemptFinish, timing sendTiming, incomplete model.ObserverIncompleteReason, status int, header http.Header, resolvedURLHash string) *model.ProbeObservation {
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
	c.finishDecode()
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
	capExpectation, capPolicy := c.req.CapabilityExpectation, c.req.CapabilityPolicy
	reachExpectation, reachPolicy := c.req.ReachabilityExpectation, c.req.ReachabilityPolicy
	if (incomplete != "" || c.decodeErr != nil) && !v.ConfigError {
		// Missing body evidence never turns an otherwise successful response
		// into a Capability failure. Headers/transport still carry evidence.
		transportPartial := v.ReadErr != nil && c.classifier.semanticSeen
		if !transportPartial {
			decision = NewResponseClassifier(ObserveReal, c.req.Endpoint, status, header, time.UnixMilli(timing.responseHeaderAtMS)).Finish(v.ReadErr, cause)
		}
		if status >= 200 && status < 300 && v.ReadErr == nil {
			decision.ErrorClass = model.ErrorIgnored
			capExpectation, capPolicy = nil, nil
		}
		if c.req.Endpoint == model.EndpointCountTokens && decision.ErrorClass == model.ErrorAuthRejected {
			decision.Capability = model.CapabilityConfigError
		}
	}
	if cause != nil {
		reachExpectation, reachPolicy, capExpectation, capPolicy = nil, nil, nil, nil
	}
	if status == 0 && !v.ConfigError {
		capExpectation, capPolicy = nil, nil
	}
	if v.ConfigError {
		reachExpectation, reachPolicy = nil, nil
	}
	timing.firstByteAtMS = msOrZero(c.firstByteAt)
	timing.firstEventAtMS = msOrZero(c.firstEventAt)
	timing.firstSemanticAtMS = msOrZero(c.firstSemanticAt)
	// Remote identifiers can themselves contain unknown credentials. Real
	// traffic persists classified vocabulary, never remote text or fields.
	decision.RedactedDetail = string(decision.ErrorClass)
	exec := (&Executor{}).buildExecution(c.req, c.recipe, decision, timing, c.requestBytes, c.responseBytes, 0, false, resolvedURLHash, "")
	exec.RealRequestShapeUnavailableReason = c.shapeReason
	if c.shapeReason == "" {
		exec.RealRequestShapeHash = ShapeHash(c.shape)
		exec.RealRequestShapeLearnable = exec.RealRequestShapeHash != ""
		if !exec.RealRequestShapeLearnable {
			exec.RealRequestShapeUnavailableReason = model.ShapeSanitizerFailure
		}
	}
	exec.ObserverIncomplete = incomplete != "" || c.decodeErr != nil
	if incomplete != "" {
		exec.ObserverIncompleteReason = incomplete
	} else if c.decodeErr != nil {
		exec.ObserverIncompleteReason = model.ObserverDecodeFailure
		if errors.Is(c.decodeErr, errTrafficDecodeDeadline) || errors.Is(c.decodeErr, ErrDecoderWorkBudget) || errors.Is(c.decodeErr, ErrContentDecoderWorkBudget) {
			exec.ObserverIncompleteReason = model.ObserverDeadline
		}
		if errors.Is(c.decodeErr, errTrafficObserverPanic) {
			exec.ObserverIncompleteReason = model.ObserverPanic
		}
		if errors.Is(c.decodeErr, ErrDecodedBodyTooLarge) || errors.Is(c.decodeErr, ErrEventTooLarge) {
			exec.ObserverIncompleteReason = model.ObserverOutputLimit
		}
		if errors.Is(c.decodeErr, ErrEncodedBodyTooLarge) {
			exec.ObserverIncompleteReason = model.ObserverInputLimit
		}
	}
	obs := &model.ProbeObservation{Execution: exec, CapabilityExpectation: capExpectation, CapabilityPolicy: capPolicy, ReachabilityExpectation: reachExpectation, ReachabilityPolicy: reachPolicy}
	hash, err := revisioncodec.NewProbeEvidenceHash(*obs)
	if err != nil {
		return nil
	}
	obs.Execution.EvidenceHash = hash
	return obs
}

func (o *trafficObserver) queueCapabilityObservation() {
	defer func() {
		if recover() != nil {
			o.m.persistDrops.Add(1)
		}
	}()
	snap := o.trace.Snapshot()
	timing := trafficTiming(snap.SentAt, snap.ResponseHeaderAt, snap.DoneAt)
	timing.gotConnAtMS = msOrZero(snap.GotConnAt)
	timing.tlsHandshakeStartAtMS = msOrZero(snap.TLSStartAt)
	timing.tlsHandshakeDoneAtMS = msOrZero(snap.TLSDoneAt)
	incomplete := o.incomplete
	o.capability.responseBytes = o.wireBytes
	if o.capability.firstByteAt.IsZero() {
		o.capability.firstByteAt = o.firstByteAt
	}
	if !o.full && incomplete == "" {
		incomplete = model.ObserverCapacity
	}
	observation := o.capability.observation(o.finishView,
		timing, incomplete,
		o.status, o.header, o.target.Config.ResolvedURLHash)
	if observation == nil {
		return
	}
	select {
	case <-o.m.stop:
		o.m.persistDrops.Add(1)
	case o.m.queue <- trafficWrite{observation: observation, target: o.target, finish: o.finishView, shape: o.capability.shape, healthIdentity: o.capability.req.healthIdentity}:
	default:
		o.m.persistDrops.Add(1)
	}
}

func trafficTiming(sent, header, done time.Time) sendTiming {
	return sendTiming{sentAtMS: msOrZero(sent), responseHeaderAtMS: msOrZero(header), doneAtMS: msOrZero(done)}
}
