package probe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/probetemplate"
	"github.com/279814/relay-gate/internal/sample"
)

const canaryTemplateID = "builtin:canary-v1"

func canaryRecipe(endpoint model.EndpointKind, nonce string) (*ResolvedRecipe, error) {
	schema := map[string]any{"type": "object", "properties": map[string]any{"nonce": map[string]any{"type": "string", "enum": []string{nonce}}}, "required": []string{"nonce"}, "additionalProperties": false}
	prompt := "Call " + model.CanaryTool + " exactly once with nonce " + nonce + ". Emit no text and no other tool calls."
	var body map[string]any
	switch endpoint {
	case model.EndpointMessages:
		body = map[string]any{"model": "{{UPSTREAM_MODEL}}", "max_tokens": 128, "stream": true,
			"messages":    []any{map[string]any{"role": "user", "content": prompt}},
			"tools":       []any{map[string]any{"name": model.CanaryTool, "description": "Inert output check; never executed.", "input_schema": schema}},
			"tool_choice": map[string]any{"type": "tool", "name": model.CanaryTool, "disable_parallel_tool_use": true}}
	case model.EndpointResponses:
		body = map[string]any{"model": "{{UPSTREAM_MODEL}}", "max_output_tokens": 128, "stream": true, "input": prompt,
			"tools":       []any{map[string]any{"type": "function", "name": model.CanaryTool, "description": "Inert output check; never executed.", "parameters": schema, "strict": true}},
			"tool_choice": map[string]any{"type": "function", "name": model.CanaryTool}, "parallel_tool_calls": false}
	case model.EndpointChatCompletions:
		body = map[string]any{"model": "{{UPSTREAM_MODEL}}", "max_completion_tokens": 128, "stream": true,
			"messages":    []any{map[string]any{"role": "user", "content": prompt}},
			"tools":       []any{map[string]any{"type": "function", "function": map[string]any{"name": model.CanaryTool, "description": "Inert output check; never executed.", "parameters": schema, "strict": true}}},
			"tool_choice": map[string]any{"type": "function", "function": map[string]any{"name": model.CanaryTool}}, "parallel_tool_calls": false}
	default:
		return nil, model.WrapValidation("Canary 只支持模型端点")
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	compiled, err := probetemplate.CompileContent(endpoint, probetemplate.TemplateContent{Method: "POST", Body: raw, Headers: []model.HeaderTemplate{{Name: "Content-Type", Values: []string{"application/json"}}}})
	if err != nil {
		return nil, err
	}
	return &ResolvedRecipe{Layer: model.ResolvedEmbedded, Identity: model.RecipeIdentity{Storage: model.RecipeStorageEmbedded, Origin: model.RecipeBasic, TemplateID: canaryTemplateID, Revision: 1},
		Facts: model.RecipeBindingFacts{Use: model.BindingExplicitTest, ResolvedLayer: model.ResolvedEmbedded}, Compiled: compiled, StreamExpected: true, TimeoutProfile: model.TimeoutL2Standard}, nil
}

// RunCanary is an explicit one-shot diagnostic. Lazy permits this manual call;
// periodic scheduling uses the same executor with a distinct durable source.
func (s *Service) RunCanary(ctx context.Context, routeID int64) (model.ProbeExecution, error) {
	return s.runCanary(ctx, routeID, model.CanaryManual, 0)
}

func (s *Service) runCanary(ctx context.Context, routeID int64, source model.CanarySource, revision int64) (model.ProbeExecution, error) {
	if s == nil || s.store == nil || s.executor == nil || s.snapshots == nil {
		return model.ProbeExecution{}, model.WrapValidation("Canary 未装配")
	}
	rt, err := s.store.GetRoute(routeID)
	if err != nil {
		return model.ProbeExecution{}, err
	}
	up, err := s.store.GetUpstream(rt.UpstreamID)
	if err != nil {
		return model.ProbeExecution{}, err
	}
	if err := errDisabledProbeTarget(rt, up); err != nil {
		return model.ProbeExecution{}, err
	}
	if source == model.CanaryPeriodic && up.ProbeMode != model.ProbeModeActive {
		return model.ProbeExecution{}, model.WrapValidation("只有 Active Upstream 可发周期 Canary")
	}
	mn, err := s.store.GetModelName(rt.ModelNameID)
	if err != nil {
		return model.ProbeExecution{}, err
	}
	if !mn.Enabled {
		return model.ProbeExecution{}, model.WrapValidation("Canary ModelName 已停用")
	}
	endpoint, ok := mn.Protocol.Endpoint()
	if !ok {
		return model.ProbeExecution{}, model.WrapValidation("Canary 协议不支持")
	}
	settings, err := s.snapshots.Settings()
	if err != nil {
		return model.ProbeExecution{}, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return model.ProbeExecution{}, fmt.Errorf("生成 Canary nonce: %w", err)
	}
	nonceText := hex.EncodeToString(nonce[:])
	recipe, err := canaryRecipe(endpoint, nonceText)
	if err != nil {
		return model.ProbeExecution{}, err
	}
	trigger := model.TriggerManual
	if source == model.CanaryPeriodic {
		trigger = model.TriggerScheduled
	}
	req := ExecutionRequest{ExecutionID: sample.NewReqID(), Trigger: trigger, Upstream: up, ModelName: mn, Route: rt, Endpoint: endpoint,
		Mode: ObserveReal, Budget: outbound.L2Budget(settings), ExplicitRecipe: recipe, canary: newCanaryCheck(endpoint, nonceText, source, revision)}
	req.canary.beforeSend = func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		snapshot, err := s.snapshots.Snapshot()
		if err != nil {
			return err
		}
		currentRoute := findRoute(snapshot, routeID)
		if currentRoute == nil || currentRoute.UpstreamID != up.ID {
			return model.WrapValidation("Canary Route 已改变")
		}
		currentUpstream := snapshot.Upstreams[up.ID]
		currentModel := findModelName(snapshot, currentRoute.ModelNameID)
		if currentUpstream == nil || currentUpstream.CreatedAt != up.CreatedAt || currentRoute.CreatedAt != rt.CreatedAt {
			return model.WrapValidation("Canary 目标已被替换")
		}
		if err := errDisabledProbeTarget(currentRoute, currentUpstream); err != nil {
			return err
		}
		if currentModel == nil || !currentModel.Enabled {
			return model.WrapValidation("Canary ModelName 已停用")
		}
		if source == model.CanaryPeriodic {
			policies, ok := s.store.(CanaryPolicySource)
			if !ok || currentUpstream.ProbeMode != model.ProbeModeActive {
				return model.WrapValidation("周期 Canary 需要 Active 策略来源")
			}
			policy, err := policies.GetCanaryPolicy(ctx, up.ID)
			if err != nil {
				return err
			}
			if !policy.Enabled || policy.RouteID != routeID || policy.Revision != revision {
				return model.WrapValidation("周期 Canary 策略已改变")
			}
		}
		return nil
	}
	preparer, ok := s.manual.(interface {
		PrepareCanary(context.Context, *ExecutionRequest) error
	})
	if !ok {
		return model.ProbeExecution{}, livecfg.ErrProbeSnapshotUnavailable
	}
	if err := preparer.PrepareCanary(ctx, &req); err != nil {
		return model.ProbeExecution{}, err
	}
	if req.ObservationOrder <= 0 {
		return model.ProbeExecution{}, livecfg.ErrProbeSnapshotUnavailable
	}
	result, err := s.executor.Execute(ctx, req)
	return result.Execution, err
}

// PrepareCanary allocates from Scheduler's existing observation sequencer. A
// diagnostic never attaches ordinary Recipe/health expectations.
func (s *Scheduler) PrepareCanary(ctx context.Context, req *ExecutionRequest) error {
	if req == nil || req.canary == nil || req.Route == nil || req.Upstream == nil || !req.canary.source.Valid() {
		return model.WrapValidation("Canary 准备输入无效")
	}
	source, ok := s.cfg.(ProbeSnapshotSource)
	if !ok {
		return livecfg.ErrProbeSnapshotUnavailable
	}
	if _, err := source.ProbeSnapshot(); err != nil {
		return err
	}
	snapshot, err := s.cfg.Snapshot()
	if err != nil {
		return err
	}
	route := findRoute(snapshot, req.Route.ID)
	if route == nil || route.UpstreamID != req.Upstream.ID {
		return model.WrapValidation("Canary Route 已改变")
	}
	upstream := snapshot.Upstreams[route.UpstreamID]
	name := findModelName(snapshot, route.ModelNameID)
	if upstream == nil {
		return model.WrapValidation("Canary Upstream 不存在")
	}
	if err := errDisabledProbeTarget(route, upstream); err != nil {
		return err
	}
	if name == nil || !name.Enabled {
		return model.WrapValidation("Canary ModelName 已停用")
	}
	if req.canary.source == model.CanaryPeriodic && upstream.ProbeMode != model.ProbeModeActive {
		return model.WrapValidation("只有 Active Upstream 可发周期 Canary")
	}
	endpoint, ok := name.Protocol.Endpoint()
	if !ok || endpoint != req.Endpoint {
		return model.WrapValidation("Canary Endpoint 已改变")
	}
	req.Route, req.Upstream, req.ModelName = route, upstream, name
	order, err := s.nextOrder(ctx, req.Trigger)
	if err != nil {
		return err
	}
	req.ObservationOrder = order
	req.ReachabilityExpectation, req.CapabilityExpectation = nil, nil
	req.ReachabilityPolicy, req.CapabilityPolicy = nil, nil
	return nil
}
