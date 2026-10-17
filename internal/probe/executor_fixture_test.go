package probe

import (
	"context"
	"net/http"
	"strings"

	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
)

func contains(value, part string) bool { return strings.Contains(value, part) }

func nativeSemanticWire(protocol model.Protocol) string {
	switch protocol {
	case model.ProtoOpenAIChat:
		return "data: {\"choices\":[{\"delta\":{\"content\":\"2\"}}]}\n\n"
	case model.ProtoOpenAIResponses:
		return "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"2\"}\n\n"
	default:
		return aliveSSE
	}
}

// executorProbeHarness only supplies fixture inputs to the production Executor.
// It owns no transport, template, parser, authentication or classification logic.
type executorProbeHarness struct {
	Transport http.RoundTripper
	Targets   TargetResolver
	Recipes   *RecipeResolver
	Secrets   outbound.SecretSource
	Last      ExecutionResult
}

func (h *executorProbeHarness) execute(ctx context.Context, up *model.Upstream, mn *model.ModelName, route *model.Route, settings model.Settings, endpoint model.EndpointKind) Outcome {
	budget := outbound.L2Budget(settings)
	if endpoint == model.EndpointModels {
		budget = outbound.L1Budget(settings)
	} else if endpoint == model.EndpointCountTokens {
		budget = outbound.CountTokensBudget(settings)
	}
	executor := NewExecutor(h.Targets, h.Secrets, h.Recipes, fakeTransports{rt: h.Transport}, nil, AlwaysOpenAdmission(), WallClock(), nil)
	result, err := executor.Execute(ctx, ExecutionRequest{ExecutionID: "executor-fixture", Trigger: model.TriggerManual, Upstream: up, ModelName: mn, Route: route, Endpoint: endpoint, Mode: ObserveProbe, Budget: budget, ObservationOrder: 1})
	h.Last = result
	if err != nil {
		return Outcome{Verdict: health.VerdictIgnore, Err: err}
	}
	return result.Outcome
}

func (h *executorProbeHarness) L1(ctx context.Context, up *model.Upstream, settings model.Settings) Outcome {
	return h.execute(ctx, up, nil, nil, settings, model.EndpointModels)
}
func (h *executorProbeHarness) L2(ctx context.Context, up *model.Upstream, mn *model.ModelName, route *model.Route, settings model.Settings) Outcome {
	endpoint := model.EndpointKind("")
	if mn != nil {
		endpoint, _ = mn.Protocol.Endpoint()
	}
	return h.execute(ctx, up, mn, route, settings, endpoint)
}
