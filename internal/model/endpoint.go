package model

import "strings"

// EndpointKind identifies the upstream API surface without coupling it to a
// particular logical model or route.
type EndpointKind string

const (
	EndpointModels          EndpointKind = "models"
	EndpointMessages        EndpointKind = "messages"
	EndpointResponses       EndpointKind = "responses"
	EndpointChatCompletions EndpointKind = "chat_completions"
	EndpointCountTokens     EndpointKind = "count_tokens"
)

func (kind EndpointKind) Valid() bool { return kind.CanonicalPath() != "" }

func (kind EndpointKind) Method() string {
	if kind == EndpointModels {
		return "GET"
	}
	if kind.Valid() {
		return "POST"
	}
	return ""
}

func (kind EndpointKind) CanonicalPath() string {
	switch kind {
	case EndpointModels:
		return "/v1/models"
	case EndpointMessages:
		return "/v1/messages"
	case EndpointResponses:
		return "/v1/responses"
	case EndpointChatCompletions:
		return "/v1/chat/completions"
	case EndpointCountTokens:
		return "/v1/messages/count_tokens"
	default:
		return ""
	}
}

type ProbeMode string

const (
	ProbeModeActive ProbeMode = "active"
	ProbeModeLazy   ProbeMode = "lazy"
)

func (mode ProbeMode) Valid() bool { return mode == ProbeModeActive || mode == ProbeModeLazy }

type RunState string

const (
	RunStateRunning RunState = "running"
	RunStatePaused  RunState = "paused"
)

func (state RunState) Valid() bool { return state == RunStateRunning || state == RunStatePaused }

type EndpointURLMode string

const (
	EndpointURLCanonical   EndpointURLMode = "canonical"
	EndpointURLLegacyExact EndpointURLMode = "legacy_exact"
)

func (mode EndpointURLMode) Valid() bool {
	return mode == EndpointURLCanonical || mode == EndpointURLLegacyExact
}

type ReachabilityState string

const (
	ReachabilityUnknown     ReachabilityState = "unknown"
	ReachabilityReachable   ReachabilityState = "reachable"
	ReachabilityUnreachable ReachabilityState = "unreachable"
)

type CapabilityState string

const (
	CapabilityUnknown        CapabilityState = "unknown"
	CapabilitySupported      CapabilityState = "supported"
	CapabilityUnsupported    CapabilityState = "unsupported"
	CapabilityTransientError CapabilityState = "transient_error"
	CapabilityConfigError    CapabilityState = "config_error"
)

type ErrorClass string

const (
	ErrorNone          ErrorClass = "none"
	ErrorUnreachable   ErrorClass = "unreachable"
	ErrorAuthRejected  ErrorClass = "auth_rejected"
	ErrorShapeRejected ErrorClass = "request_shape_rejected"
	ErrorConfig        ErrorClass = "config_error"
	ErrorUnsupported   ErrorClass = "unsupported"
	ErrorModelNotFound ErrorClass = "model_not_found"
	ErrorRateLimited   ErrorClass = "rate_limited"
	ErrorTransient     ErrorClass = "transient_error"
	ErrorFakeAlive     ErrorClass = "fake_alive"
	ErrorPartial       ErrorClass = "partial_failure"
	ErrorIgnored       ErrorClass = "ignored"
)

type ObservationScope string

const (
	ScopeNone                 ObservationScope = "none"
	ScopeUpstreamReachability ObservationScope = "upstream_reachability"
	ScopeUpstreamEndpoint     ObservationScope = "upstream_endpoint"
	ScopeRouteEndpoint        ObservationScope = "route_endpoint"
)

// AuthMode uses an explicit Mode suffix because the legacy AuthStyle type
// already exports AuthXAPIKey. Keeping the names distinct lets schema-2 code
// coexist with the compatibility adapter until P0-17.
type AuthMode string

const (
	AuthModeBearer             AuthMode = "header_bearer"
	AuthModeXAPIKey            AuthMode = "x_api_key"
	AuthModeAPIKey             AuthMode = "api_key"
	AuthModeFixedQuery         AuthMode = "fixed_query_secret"
	AuthModeManualHeaders      AuthMode = "manual_headers"
	AuthModeAutoCalibrated     AuthMode = "auto_calibrated"
	AuthModeLegacyAutoRealOnly AuthMode = "legacy_auto_real_only"
)

func (mode AuthMode) Valid() bool {
	switch mode {
	case AuthModeBearer, AuthModeXAPIKey, AuthModeAPIKey, AuthModeFixedQuery,
		AuthModeManualHeaders, AuthModeAutoCalibrated, AuthModeLegacyAutoRealOnly:
		return true
	default:
		return false
	}
}

type EndpointAuthProfile struct {
	Mode           AuthMode         `json:"mode"`
	CalibratedMode AuthMode         `json:"calibrated_mode,omitempty"`
	HeaderName     string           `json:"header_name,omitempty"`
	QueryName      string           `json:"query_name,omitempty"`
	SecretRef      string           `json:"secret_ref"`
	ManualHeaders  []HeaderTemplate `json:"manual_headers,omitempty"`
	Revision       int64            `json:"revision"`
}

type UpstreamEndpoint struct {
	ID                    int64               `json:"id"`
	UpstreamID            int64               `json:"upstream_id"`
	Kind                  EndpointKind        `json:"endpoint"`
	URLMode               EndpointURLMode     `json:"url_mode"`
	LegacyFullURLID       int64               `json:"legacy_full_url_id,omitempty"`
	LegacyFullURLRevision int64               `json:"legacy_full_url_revision,omitempty"`
	LegacyCompatRealOnly  bool                `json:"legacy_compat_real_only,omitempty"`
	URLOverride           string              `json:"url_override,omitempty"`
	FixedQueryTemplate    string              `json:"fixed_query_template,omitempty"`
	AuthProfile           EndpointAuthProfile `json:"auth_profile"`
	Revision              int64               `json:"revision"`
	NeedsReview           bool                `json:"needs_review"`
	CreatedAt             int64               `json:"created_at"`
	UpdatedAt             int64               `json:"updated_at"`
}

type LegacyFullURL struct {
	ID               int64        `json:"id"`
	UpstreamID       int64        `json:"upstream_id"`
	MaskedURL        string       `json:"masked_url"`
	Fingerprint      string       `json:"fingerprint"`
	InferredEndpoint EndpointKind `json:"inferred_endpoint,omitempty"`
	Revision         int64        `json:"revision"`
	NeedsReview      bool         `json:"needs_review"`
}

type ProbeUpstreamConfig struct {
	ID                 int64
	BaseURL            string
	ProxyURL           string
	Enabled            bool
	ProbeMode          ProbeMode
	HostOverride       string
	TLSServerName      string
	Revision           int64
	NetworkRevision    int64
	CredentialRevision int64
}

// EndpointURLOverride 把旧的 full_url_mode 与 l1_path 两个站级开关，翻译成
// 某个 Endpoint 的 url_override。返回空表示该 Endpoint 用 canonical path。
//
// 为什么必须有这个翻译：EndpointResolver 是唯一拼 URL 的地方，而它只认
// Endpoint 上的 url_override。两个旧开关若不落到 Endpoint 上，就会静默失效 ——
// full_url_mode 的站会被拼成 base+/v1/messages（旧行为是 base 本身），
// 自定义 l1_path 的站会被探成 /v1/models。两者都表现为「配置还在、行为变了」。
//
// 创建与更新共用它，避免两条路径各写一份而分叉。
func (u *Upstream) EndpointURLOverride(kind EndpointKind) string {
	base := strings.TrimRight(u.BaseURL, "/")
	if kind == EndpointModels {
		switch u.L1Path {
		case "/v1/models":
			return "" // canonical，不需要 override
		case "":
			// 旧行为是 HEAD base_url（连接层探测）。URL 就是 base 本身，
			// 方法由调用方按 l1_path 为空来决定，不在 URL 里表达。
			return base
		default:
			return base + u.L1Path
		}
	}
	if u.FullURLMode {
		// full_url_mode 的语义就是「base_url 即完整端点，不再拼路径」。
		return base
	}
	return ""
}
func (u *Upstream) ProbeConfig() *ProbeUpstreamConfig {
	return &ProbeUpstreamConfig{
		ID:                 u.ID,
		BaseURL:            u.BaseURL,
		ProxyURL:           u.ProxyURL,
		Enabled:            u.Enabled,
		ProbeMode:          u.ProbeMode,
		HostOverride:       u.HostOverride,
		TLSServerName:      u.TLSServerName,
		Revision:           u.Revision,
		NetworkRevision:    u.NetworkRevision,
		CredentialRevision: u.CredentialRevision,
	}
}
