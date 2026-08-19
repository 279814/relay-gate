package revisioncodec

import (
	"time"

	"github.com/279814/relay-gate/internal/model"
)

const (
	probeEvidenceDomain     = "relay-gate/probe-evidence/v1"
	probeCostEvidenceDomain = "relay-gate/probe-cost-evidence/v1"
)

func NewProbeEvidenceHash(observation model.ProbeObservation) (string, error) {
	execution := observation.Execution
	if execution.ObservationOrder < 0 || execution.RequestBytes < 0 || execution.ResponseBytes < 0 ||
		execution.EstimatedInputTokens < 0 || execution.ObservedInputTokens < 0 || execution.ObservedOutputTokens < 0 {
		return "", model.WrapValidation("probe evidence 数值不能为负")
	}
	encoder := newCanonicalEncoder(probeEvidenceDomain)
	encoder.string(execution.ID)
	encoder.string(string(execution.Trigger))
	encoder.int64(execution.UpstreamID)
	encoder.int64(execution.UpstreamNetworkRevision)
	encoder.int64(execution.UpstreamCredentialRevision)
	encoder.selector(execution.ReachabilityPolicySelector)
	encoder.selector(execution.CapabilityPolicySelector)
	encoder.string(execution.ReachabilitySettingsFingerprint)
	encoder.string(execution.ProbeSettingsFingerprint)
	encoder.int64(execution.EndpointID)
	encoder.int64(execution.EndpointRevision)
	encoder.int64(execution.ModelCapabilityRevision)
	encoder.int64(execution.RouteCapabilityRevision)
	encoder.int64(execution.AuthProfileRevision)
	encoder.string(execution.ProbeSecretRevisionsHash)
	encoder.int64(execution.RequestTransformBindingRevision)
	encoder.int64(execution.RouteID)
	encoder.string(string(execution.Endpoint))
	encoder.string(string(execution.RecipeBindingUse))
	encoder.int64(execution.RecipeID)
	encoder.int64(execution.RecipeVersionID)
	encoder.recipeIdentity(model.RecipeIdentity{
		Storage: execution.RecipeStorage, Origin: execution.RecipeOrigin,
		DBVersionID: execution.RecipeVersionID, ClientProfileID: execution.ClientProfileID,
		TemplateID: execution.TemplateID, Revision: execution.RecipeIdentityRevision,
	})
	encoder.int64(execution.RecipeBindingRevision)
	encoder.recipeBindingFacts(execution.RecipeBindingFacts)
	encoder.string(execution.RealRequestShapeHash)
	encoder.boolean(execution.RealRequestShapeLearnable)
	encoder.string(string(execution.RealRequestShapeUnavailableReason))
	encoder.string(execution.ReachabilityToken)
	encoder.string(execution.CapabilityToken)
	encoder.string(execution.ResolvedURLHash)
	encoder.string(execution.RequestURLHash)
	encoder.int64(int64(execution.StatusCode))
	encoder.string(string(execution.ErrorClass))
	encoder.string(string(execution.Capability))
	encoder.string(string(execution.Scope))
	encoder.boolean(execution.Reachable)
	encoder.boolean(execution.Final)
	encoder.boolean(execution.Success)
	encoder.boolean(execution.SemanticSeen)
	encoder.boolean(execution.NormalEndSeen)
	encoder.boolean(execution.Partial)
	encoder.string(string(execution.CandidateDisposition))
	encoder.string(execution.RedactedDetail)
	encoder.int64(execution.SentAtMS)
	encoder.int64(execution.TLSHandshakeStartAtMS)
	encoder.int64(execution.TLSHandshakeDoneAtMS)
	encoder.int64(execution.GotConnAtMS)
	encoder.int64(execution.ResponseHeaderAtMS)
	encoder.int64(execution.FirstByteAtMS)
	encoder.int64(execution.FirstEventAtMS)
	encoder.int64(execution.FirstSemanticAtMS)
	encoder.int64(execution.DoneAtMS)
	encoder.int64(execution.RequestBytes)
	encoder.int64(execution.ResponseBytes)
	encoder.int64(execution.EstimatedInputTokens)
	encoder.int64(execution.ObservedInputTokens)
	encoder.int64(execution.ObservedOutputTokens)
	encoder.int64(execution.RetryAfterUntilMS)
	encoder.int64(execution.ObservationOrder)
	encoder.boolean(execution.ExpectedCancel)
	encoder.boolean(execution.ObserverIncomplete)
	encoder.string(string(execution.ObserverIncompleteReason))
	encoder.string(execution.CalibrationRunID)
	encoder.int64(int64(execution.CandidateOrdinal))
	encoder.optionalReachabilityExpectation(observation.ReachabilityExpectation)
	encoder.optionalSemanticExpectation(observation.CapabilityExpectation)
	encoder.optionalReachabilityPolicy(observation.ReachabilityPolicy)
	encoder.optionalCapabilityPolicy(observation.CapabilityPolicy)
	return encoder.digest(), nil
}

func CostEvidenceFromExecution(execution model.ProbeExecution) (model.ProbeCostEvidenceV1, error) {
	if execution.Trigger == model.TriggerRealTraffic || !execution.Trigger.Valid() {
		return model.ProbeCostEvidenceV1{}, model.WrapValidation("真实流量或未知 trigger 不计入 Probe 成本")
	}
	if !execution.RecipeOrigin.Valid() || !execution.Endpoint.Valid() || execution.UpstreamID < 0 || execution.RouteID < 0 ||
		execution.EstimatedInputTokens < 0 || execution.ObservedOutputTokens < 0 {
		return model.ProbeCostEvidenceV1{}, model.WrapValidation("execution cost 字段无效")
	}
	timestamp := execution.SentAtMS
	if timestamp <= 0 {
		timestamp = execution.DoneAtMS
	}
	if timestamp <= 0 {
		return model.ProbeCostEvidenceV1{}, model.WrapValidation("execution cost 缺少 UTC day 时间")
	}
	result := model.ProbeCostEvidenceV1{
		Kind: model.CostEventExecution, DayUTC: time.UnixMilli(timestamp).UTC().Format("2006-01-02"),
		Trigger: execution.Trigger, Origin: execution.RecipeOrigin, Endpoint: execution.Endpoint,
		RouteID: execution.RouteID, UpstreamID: execution.UpstreamID,
	}
	if execution.SentAtMS <= 0 {
		return result, nil
	}
	result.Requests = 1
	result.EstimatedInputTokens = execution.EstimatedInputTokens
	result.ObservedOutputTokens = execution.ObservedOutputTokens
	switch {
	case execution.Success:
		result.Succeeded = 1
	case execution.ErrorClass == model.ErrorIgnored:
		result.Canceled = 1
	default:
		result.Failed = 1
	}
	if execution.ExpectedCancel && execution.SemanticSeen {
		result.CanceledAfterSemantic = 1
	}
	return result, nil
}

func CostEvidenceFromPiggyback(value model.ProbeCostDaily) (model.ProbeCostEvidenceV1, error) {
	if value.Trigger == model.TriggerRealTraffic || !value.Trigger.Valid() || !value.Origin.Valid() || !value.Endpoint.Valid() ||
		value.RouteID < 0 || value.UpstreamID < 0 || value.Requests != 0 || value.Succeeded != 0 ||
		value.Failed != 0 || value.Canceled != 0 || value.EstimatedInputTokens != 0 ||
		value.ObservedOutputTokens != 0 || value.CanceledAfterSemantic != 0 || value.PiggybackL2Saved != 0 {
		return model.ProbeCostEvidenceV1{}, model.WrapValidation("piggyback cost 输入必须只含规范维度")
	}
	if err := validateUTCDay(value.DayUTC); err != nil {
		return model.ProbeCostEvidenceV1{}, err
	}
	return model.ProbeCostEvidenceV1{
		Kind: model.CostEventPiggybackL2, DayUTC: value.DayUTC, Trigger: value.Trigger,
		Origin: value.Origin, Endpoint: value.Endpoint, RouteID: value.RouteID,
		UpstreamID: value.UpstreamID, PiggybackL2Saved: 1,
	}, nil
}

func NewProbeCostEvidenceHash(value model.ProbeCostEvidenceV1) (string, error) {
	if err := validateProbeCostEvidence(value); err != nil {
		return "", err
	}
	encoder := newCanonicalEncoder(probeCostEvidenceDomain)
	encoder.string(string(value.Kind))
	encoder.string(value.DayUTC)
	encoder.string(string(value.Trigger))
	encoder.string(string(value.Origin))
	encoder.string(string(value.Endpoint))
	encoder.int64(value.RouteID)
	encoder.int64(value.UpstreamID)
	encoder.int64(value.Requests)
	encoder.int64(value.Succeeded)
	encoder.int64(value.Failed)
	encoder.int64(value.Canceled)
	encoder.int64(value.EstimatedInputTokens)
	encoder.int64(value.ObservedOutputTokens)
	encoder.int64(value.CanceledAfterSemantic)
	encoder.int64(value.PiggybackL2Saved)
	return encoder.digest(), nil
}

func validateProbeCostEvidence(value model.ProbeCostEvidenceV1) error {
	if value.Kind != model.CostEventExecution && value.Kind != model.CostEventPiggybackL2 {
		return model.WrapValidation("cost event kind 无效")
	}
	if err := validateUTCDay(value.DayUTC); err != nil {
		return err
	}
	if value.Trigger == model.TriggerRealTraffic || !value.Trigger.Valid() || !value.Origin.Valid() ||
		!value.Endpoint.Valid() || value.RouteID < 0 || value.UpstreamID < 0 {
		return model.WrapValidation("cost evidence 维度无效")
	}
	values := []int64{value.Requests, value.Succeeded, value.Failed, value.Canceled,
		value.EstimatedInputTokens, value.ObservedOutputTokens, value.CanceledAfterSemantic,
		value.PiggybackL2Saved}
	for _, number := range values {
		if number < 0 {
			return model.WrapValidation("cost evidence delta 不能为负")
		}
	}
	if value.Kind == model.CostEventExecution {
		if value.PiggybackL2Saved != 0 || value.Requests > 1 ||
			value.Succeeded+value.Failed+value.Canceled != value.Requests ||
			value.CanceledAfterSemantic > value.Canceled {
			return model.WrapValidation("execution cost evidence outcome 无效")
		}
	} else if value.Requests != 0 || value.Succeeded != 0 || value.Failed != 0 || value.Canceled != 0 ||
		value.EstimatedInputTokens != 0 || value.ObservedOutputTokens != 0 ||
		value.CanceledAfterSemantic != 0 || value.PiggybackL2Saved != 1 {
		return model.WrapValidation("piggyback cost evidence delta 无效")
	}
	return nil
}

func validateUTCDay(day string) error {
	parsed, err := time.Parse("2006-01-02", day)
	if err != nil || parsed.Format("2006-01-02") != day {
		return model.WrapValidation("day_utc 必须是 YYYY-MM-DD，收到 %q", day)
	}
	return nil
}

func (encoder *canonicalEncoder) recipeBindingFacts(value model.RecipeBindingFacts) {
	encoder.string(string(value.Use))
	encoder.string(string(value.ResolvedLayer))
	encoder.int64(value.RouteRecipeID)
	encoder.int64(value.RoutePublishedVersionID)
	encoder.int64(value.RouteBindingRevision)
	encoder.int64(value.UpstreamRecipeID)
	encoder.int64(value.UpstreamPublishedVersionID)
	encoder.int64(value.UpstreamBindingRevision)
	encoder.int64(value.TestedProfileID)
	encoder.int64(value.TestedProfileRevision)
	encoder.int64(value.ExplicitRecipeID)
	encoder.int64(value.ExplicitVersionID)
	encoder.int64(value.ExplicitRecipeRowRevision)
	encoder.int64(value.ExplicitProfileID)
	encoder.int64(value.ExplicitProfileRevision)
	encoder.string(string(value.ExplicitProfileStatus))
}

func (encoder *canonicalEncoder) semanticRevision(value model.SemanticRevision) {
	encoder.int64(value.UpstreamNetwork)
	encoder.int64(value.UpstreamCredential)
	encoder.int64(value.EndpointID)
	encoder.int64(value.EndpointRevision)
	encoder.int64(value.ModelCapability)
	encoder.int64(value.RouteCapability)
	encoder.int64(value.AuthProfile)
	encoder.recipeIdentity(value.RecipeIdentity)
	encoder.int64(value.RecipeBindingRevision)
	encoder.string(value.ProbeSettingsFingerprint)
	encoder.secretRevisions(value.ProbeSecrets)
	encoder.int64(value.RequestTransform)
}

func (encoder *canonicalEncoder) optionalReachabilityExpectation(value *model.ReachabilityExpectation) {
	encoder.boolean(value != nil)
	if value == nil {
		return
	}
	encoder.int64(value.UpstreamID)
	encoder.selector(value.PolicySelector)
	encoder.int64(value.Revision.NetworkRevision)
	encoder.string(value.Revision.SettingsFingerprint)
	encoder.string(value.ObservationToken)
}

func (encoder *canonicalEncoder) optionalSemanticExpectation(value *model.SemanticExpectation) {
	encoder.boolean(value != nil)
	if value == nil {
		return
	}
	encoder.string(string(value.Target.Scope))
	encoder.int64(value.Target.UpstreamID)
	encoder.int64(value.Target.RouteID)
	encoder.string(string(value.Target.Endpoint))
	encoder.selector(value.PolicySelector)
	encoder.semanticRevision(value.Revision)
	encoder.recipeBindingFacts(value.BindingFacts)
	encoder.string(value.ObservationToken)
}

func (encoder *canonicalEncoder) optionalReachabilityPolicy(value *model.ReachabilityReductionPolicy) {
	encoder.boolean(value != nil)
	if value == nil {
		return
	}
	encoder.int64(int64(value.ReachableThreshold))
	encoder.int64(int64(value.UnreachableThreshold))
}

func (encoder *canonicalEncoder) optionalCapabilityPolicy(value *model.CapabilityReductionPolicy) {
	encoder.boolean(value != nil)
	if value == nil {
		return
	}
	encoder.int64(int64(value.SupportedTTL))
	encoder.int64(int64(value.UnsupportedTTL))
	encoder.int64(int64(value.TransientTTL))
}
