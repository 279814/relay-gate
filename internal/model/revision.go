package model

import "time"

type EvidenceKind string

const (
	EvidenceL1          EvidenceKind = "l1"
	EvidenceL2          EvidenceKind = "l2"
	EvidenceCountTokens EvidenceKind = "count_tokens"
	EvidenceRealTraffic EvidenceKind = "real_traffic"
)

type EvidencePolicySelector struct {
	Kind           EvidenceKind
	Endpoint       EndpointKind
	TimeoutProfile ProbeTimeoutProfile
}

func (selector EvidencePolicySelector) Validate() error {
	switch selector.Kind {
	case EvidenceL1:
		if selector.Endpoint != EndpointModels || selector.TimeoutProfile != "" {
			return invalid("L1 selector 只允许 models 且 timeout_profile 为空")
		}
	case EvidenceL2:
		if selector.Endpoint != EndpointMessages && selector.Endpoint != EndpointResponses && selector.Endpoint != EndpointChatCompletions {
			return invalid("L2 selector endpoint 无效: %q", selector.Endpoint)
		}
		if selector.TimeoutProfile != TimeoutL2Standard && selector.TimeoutProfile != TimeoutL2LongThink {
			return invalid("L2 selector timeout_profile 无效: %q", selector.TimeoutProfile)
		}
	case EvidenceCountTokens:
		if selector.Endpoint != EndpointCountTokens || selector.TimeoutProfile != "" {
			return invalid("count_tokens selector 只允许 count_tokens 且 timeout_profile 为空")
		}
	case EvidenceRealTraffic:
		if selector.Endpoint != EndpointMessages && selector.Endpoint != EndpointResponses &&
			selector.Endpoint != EndpointChatCompletions && selector.Endpoint != EndpointCountTokens {
			return invalid("real_traffic selector endpoint 无效: %q", selector.Endpoint)
		}
		if selector.TimeoutProfile != "" {
			return invalid("real_traffic selector timeout_profile 必须为空")
		}
	default:
		return invalid("evidence kind 无效: %q", selector.Kind)
	}
	return nil
}

type StageBudgetMS struct {
	Connect        int64
	ResponseHeader int64
	FirstByte      int64
	FirstEvent     int64
	FirstSemantic  int64
	Idle           int64
	Total          int64
}

type ReachabilityReductionPolicy struct {
	ReachableThreshold   int
	UnreachableThreshold int
}

type CapabilityReductionPolicy struct {
	SupportedTTL   time.Duration
	UnsupportedTTL time.Duration
	TransientTTL   time.Duration
}

type CapabilityEvidencePolicy struct {
	Selector            EvidencePolicySelector
	Stages              StageBudgetMS
	ParserPolicyVersion int
	MaxEventBytes       int64
	MaxTotalBytes       int64
	State               CapabilityReductionPolicy
}

type ReachabilityEvidencePolicy struct {
	Selector         EvidencePolicySelector
	ConnectMS        int64
	ResponseHeaderMS int64
	TotalMS          int64
	State            ReachabilityReductionPolicy
}

type SecretRevision struct {
	ID       int64
	Name     string
	Revision int64
	Resolved bool
}

type SemanticRevision struct {
	UpstreamNetwork          int64
	UpstreamCredential       int64
	EndpointID               int64
	EndpointRevision         int64
	ModelCapability          int64
	RouteCapability          int64
	AuthProfile              int64
	RecipeIdentity           RecipeIdentity
	RecipeBindingRevision    int64
	ProbeSettingsFingerprint string
	ProbeSecrets             []SecretRevision
	RequestTransform         int64
}

type ReachabilityRevision struct {
	NetworkRevision     int64
	SettingsFingerprint string
}

type RequiredSecretRef struct {
	Name          string
	BoundSecretID int64
}

type RecipeResolvedLayer string

const (
	ResolvedRoute    RecipeResolvedLayer = "route"
	ResolvedUpstream RecipeResolvedLayer = "upstream"
	ResolvedProfile  RecipeResolvedLayer = "profile"
	ResolvedEmbedded RecipeResolvedLayer = "embedded"
)

type RecipeBindingUse string

const (
	BindingResolved            RecipeBindingUse = "resolved"
	BindingExplicitTest        RecipeBindingUse = "explicit_test"
	BindingExplicitProfileTest RecipeBindingUse = "explicit_profile_test"
	BindingRealTrafficContext  RecipeBindingUse = "real_traffic_context"
)

type RecipeBindingFacts struct {
	Use                        RecipeBindingUse
	ResolvedLayer              RecipeResolvedLayer
	RouteRecipeID              int64
	RoutePublishedVersionID    int64
	RouteBindingRevision       int64
	UpstreamRecipeID           int64
	UpstreamPublishedVersionID int64
	UpstreamBindingRevision    int64
	TestedProfileID            int64
	TestedProfileRevision      int64
	ExplicitRecipeID           int64
	ExplicitVersionID          int64
	ExplicitRecipeRowRevision  int64
	ExplicitProfileID          int64
	ExplicitProfileRevision    int64
	ExplicitProfileStatus      ProbeProfileStatus
}

type SemanticExpectation struct {
	Target           SemanticTarget
	PolicySelector   EvidencePolicySelector
	Revision         SemanticRevision
	BindingFacts     RecipeBindingFacts
	ObservationToken string
}

type ReachabilityExpectation struct {
	UpstreamID       int64
	PolicySelector   EvidencePolicySelector
	Revision         ReachabilityRevision
	ObservationToken string
}

type SemanticTarget struct {
	Scope      RecipeScope
	UpstreamID int64
	RouteID    int64
	Endpoint   EndpointKind
}

func (target SemanticTarget) Validate() error {
	if target.UpstreamID <= 0 {
		return invalid("semantic target upstream_id 必须为正数")
	}
	if !target.Endpoint.Valid() {
		return invalid("semantic target endpoint 无效: %q", target.Endpoint)
	}
	switch target.Scope {
	case RecipeScopeUpstream:
		if target.RouteID != 0 {
			return invalid("upstream scope 的 route_id 必须为 0")
		}
	case RecipeScopeRoute:
		if target.RouteID <= 0 {
			return invalid("route scope 的 route_id 必须为正数")
		}
	default:
		return invalid("semantic target scope 无效: %q", target.Scope)
	}
	return nil
}
