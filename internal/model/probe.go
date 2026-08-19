package model

import (
	"strings"
	"unicode/utf8"
)

type HeaderTemplate struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

type RecipeScope string

const (
	RecipeScopeUpstream RecipeScope = "upstream"
	RecipeScopeRoute    RecipeScope = "route"
)

func (trigger ProbeTrigger) Valid() bool {
	switch trigger {
	case TriggerScheduled, TriggerManual, TriggerCalibration, TriggerRecovery, TriggerRealTraffic:
		return true
	default:
		return false
	}
}

func (scope RecipeScope) Valid() bool {
	return scope == RecipeScopeUpstream || scope == RecipeScopeRoute
}

type RecipeStatus string

const (
	RecipeDraft       RecipeStatus = "draft"
	RecipePublished   RecipeStatus = "published"
	RecipeDisabled    RecipeStatus = "disabled"
	RecipeArchived    RecipeStatus = "archived"
	RecipeLegacy      RecipeStatus = "legacy_compat"
	RecipeQuarantined RecipeStatus = "legacy_quarantined"
)

func (status RecipeStatus) Valid() bool {
	switch status {
	case RecipeDraft, RecipePublished, RecipeDisabled, RecipeArchived, RecipeLegacy, RecipeQuarantined:
		return true
	default:
		return false
	}
}

type RecipeSource string

const (
	RecipeManual          RecipeSource = "manual"
	RecipeLearned         RecipeSource = "learned"
	RecipeCompact         RecipeSource = "compact_native"
	RecipeCalibration     RecipeSource = "calibration_native"
	RecipeBasic           RecipeSource = "basic_protocol"
	RecipeLegacyMigration RecipeSource = "legacy_migration"
)

func (source RecipeSource) Valid() bool {
	switch source {
	case RecipeManual, RecipeLearned, RecipeCompact, RecipeCalibration, RecipeBasic, RecipeLegacyMigration:
		return true
	default:
		return false
	}
}

type CandidateDisposition string

const (
	CandidateStop         CandidateDisposition = "stop"
	CandidateTryNextAuth  CandidateDisposition = "try_next_auth"
	CandidateTryNextShape CandidateDisposition = "try_next_shape"
)

type ProbeTimeoutProfile string

const (
	TimeoutL1          ProbeTimeoutProfile = "l1"
	TimeoutL2Standard  ProbeTimeoutProfile = "l2_standard"
	TimeoutL2LongThink ProbeTimeoutProfile = "l2_long_thinking"
	TimeoutCountTokens ProbeTimeoutProfile = "count_tokens"
)

func (profile ProbeTimeoutProfile) Valid() bool {
	switch profile {
	case TimeoutL1, TimeoutL2Standard, TimeoutL2LongThink, TimeoutCountTokens:
		return true
	default:
		return false
	}
}

type ProbeRecipe struct {
	ID                    int64
	ScopeType             RecipeScope
	ScopeID               int64
	Endpoint              EndpointKind
	Status                RecipeStatus
	Pinned                bool
	DraftVersionID        int64
	PublishedVersionID    int64
	LastPublishForced     bool
	LastTestExecutionID   string
	PublishedAt           int64
	Revision              int64
	ActiveBindingRevision int64
	CreatedAt             int64
	UpdatedAt             int64
}

type ProbeRecipeVersion struct {
	ID             int64
	RecipeID       int64
	Version        int
	Origin         RecipeSource
	Method         string
	FixedRawQuery  string
	Headers        []HeaderTemplate
	Body           []byte
	BodyIsText     bool
	StreamExpected bool
	TimeoutProfile ProbeTimeoutProfile
	CreatedAt      int64
}

func (version ProbeRecipeVersion) ValidateForEndpoint(endpoint EndpointKind) error {
	if !endpoint.Valid() {
		return invalid("endpoint 无效: %q", endpoint)
	}
	if !version.TimeoutProfile.Valid() {
		return invalid("timeout_profile 无效: %q", version.TimeoutProfile)
	}
	if version.BodyIsText && !utf8.Valid(version.Body) {
		return invalid("body_text 必须是合法 UTF-8")
	}
	if version.Method != strings.ToUpper(version.Method) {
		return invalid("method 必须是大写 GET / HEAD / POST，收到 %q", version.Method)
	}
	if endpoint == EndpointModels {
		if version.Method != "GET" && version.Method != "HEAD" {
			return invalid("models endpoint 只允许 GET 或 HEAD")
		}
		if version.TimeoutProfile != TimeoutL1 {
			return invalid("models endpoint 必须使用 l1 timeout profile")
		}
	} else {
		if version.Method != "POST" {
			return invalid("%s endpoint 只允许 POST", endpoint)
		}
		if endpoint == EndpointCountTokens {
			if version.TimeoutProfile != TimeoutCountTokens {
				return invalid("count_tokens endpoint 必须使用 count_tokens timeout profile")
			}
		} else if version.TimeoutProfile != TimeoutL2Standard && version.TimeoutProfile != TimeoutL2LongThink {
			return invalid("模型 endpoint 必须使用 l2 timeout profile")
		}
	}
	if (version.Method == "GET" || version.Method == "HEAD") && len(version.Body) != 0 {
		return invalid("GET/HEAD recipe 不能包含 body")
	}
	return nil
}

type RecipeStorageKind string

const (
	RecipeStorageDB       RecipeStorageKind = "db"
	RecipeStorageProfile  RecipeStorageKind = "profile"
	RecipeStorageEmbedded RecipeStorageKind = "embedded"
)

type RecipeIdentity struct {
	Storage         RecipeStorageKind
	Origin          RecipeSource
	DBVersionID     int64
	ClientProfileID int64
	TemplateID      string
	Revision        int64
}

func (identity RecipeIdentity) Validate() error {
	if !identity.Origin.Valid() {
		return invalid("recipe origin 无效: %q", identity.Origin)
	}
	switch identity.Storage {
	case RecipeStorageDB:
		if identity.DBVersionID <= 0 || identity.ClientProfileID != 0 || identity.TemplateID != "" || identity.Revision != 0 {
			return invalid("DB recipe identity 判别字段无效")
		}
	case RecipeStorageProfile:
		if identity.ClientProfileID <= 0 || identity.DBVersionID != 0 || identity.TemplateID != "" || identity.Revision <= 0 {
			return invalid("profile recipe identity 判别字段无效")
		}
	case RecipeStorageEmbedded:
		if identity.TemplateID == "" || identity.DBVersionID != 0 || identity.ClientProfileID != 0 || identity.Revision <= 0 {
			return invalid("embedded recipe identity 判别字段无效")
		}
	default:
		return invalid("recipe storage 无效: %q", identity.Storage)
	}
	return nil
}

type ProbeSecret struct {
	ID          int64
	Name        string
	Masked      string
	Fingerprint string
	Revision    int64
	CreatedAt   int64
	UpdatedAt   int64
}

type PublishedRecipeBinding struct {
	Recipe  ProbeRecipe
	Version ProbeRecipeVersion
}

type UpstreamReachability struct {
	UpstreamID              int64
	PolicySelector          EvidencePolicySelector
	State                   ReachabilityState
	ConsecutiveOK           int
	ConsecutiveFail         int
	LastOKAt                int64
	LastErrorAt             int64
	LastError               string
	LastConnectMS           int64
	LastTLSMS               int64
	LastHeaderMS            int64
	ObservedNetworkRevision int64
	SettingsFingerprint     string
	ObservationToken        string
	LastObservationOrder    int64
}

type EndpointCapability struct {
	ScopeType                       RecipeScope
	ScopeID                         int64
	Endpoint                        EndpointKind
	EndpointID                      int64
	PolicySelector                  EvidencePolicySelector
	State                           CapabilityState
	ObservationToken                string
	ResolvedURLHash                 string
	UpstreamNetworkRevision         int64
	UpstreamCredentialRevision      int64
	EndpointRevision                int64
	ModelCapabilityRevision         int64
	RouteCapabilityRevision         int64
	AuthProfileRevision             int64
	RecipeBindingRevision           int64
	ProbeSettingsFingerprint        string
	ProbeSecretRevisionsHash        string
	RequestTransformBindingRevision int64
	ObservedAt                      int64
	ExpiresAt                       int64
	StatusCode                      int
	ErrorClass                      ErrorClass
	RedactedDetail                  string
	LastObservationOrder            int64
	LastRealOKAt                    int64
	LastRealOKToken                 string
}

type ProbeTrigger string

const (
	TriggerScheduled   ProbeTrigger = "scheduled"
	TriggerManual      ProbeTrigger = "manual"
	TriggerCalibration ProbeTrigger = "calibration"
	TriggerRecovery    ProbeTrigger = "recovery"
	TriggerRealTraffic ProbeTrigger = "real_traffic"
)

type ObserverIncompleteReason string

const (
	ObserverCapacity       ObserverIncompleteReason = "observer_capacity"
	ObserverQueueFull      ObserverIncompleteReason = "queue_full"
	ObserverInputLimit     ObserverIncompleteReason = "input_limit"
	ObserverOutputLimit    ObserverIncompleteReason = "output_limit"
	ObserverDecodeFailure  ObserverIncompleteReason = "decode_failure"
	ObserverDeadline       ObserverIncompleteReason = "deadline"
	ObserverPanic          ObserverIncompleteReason = "panic"
	ObserverPrepareFailure ObserverIncompleteReason = "prepare_failure"
)

type RequestShapeUnavailableReason string

const (
	ShapeBodyTruncated    RequestShapeUnavailableReason = "body_truncated"
	ShapeUnsafeValue      RequestShapeUnavailableReason = "unsafe_value"
	ShapeUnsupported      RequestShapeUnavailableReason = "unsupported_shape"
	ShapeSanitizerFailure RequestShapeUnavailableReason = "sanitizer_failure"
)

type ApplyDisposition string

const (
	ApplyNotApplicable ApplyDisposition = "not_applicable"
	ApplyCurrent       ApplyDisposition = "applied"
	ApplyConfigStale   ApplyDisposition = "config_stale"
	ApplySuperseded    ApplyDisposition = "superseded"
)

type ProbeExecution struct {
	ID                                string
	Trigger                           ProbeTrigger
	UpstreamID                        int64
	UpstreamNetworkRevision           int64
	UpstreamCredentialRevision        int64
	ReachabilityPolicySelector        EvidencePolicySelector
	CapabilityPolicySelector          EvidencePolicySelector
	ReachabilitySettingsFingerprint   string
	ProbeSettingsFingerprint          string
	EndpointID                        int64
	EndpointRevision                  int64
	ModelCapabilityRevision           int64
	RouteCapabilityRevision           int64
	AuthProfileRevision               int64
	ProbeSecretRevisionsHash          string
	RequestTransformBindingRevision   int64
	RouteID                           int64
	Endpoint                          EndpointKind
	RecipeBindingUse                  RecipeBindingUse
	RecipeID                          int64
	RecipeVersionID                   int64
	RecipeStorage                     RecipeStorageKind
	RecipeOrigin                      RecipeSource
	ClientProfileID                   int64
	TemplateID                        string
	RecipeBindingRevision             int64
	RecipeIdentityRevision            int64
	RecipeBindingFacts                RecipeBindingFacts
	RealRequestShapeHash              string
	RealRequestShapeLearnable         bool
	RealRequestShapeUnavailableReason RequestShapeUnavailableReason
	ReachabilityToken                 string
	CapabilityToken                   string
	ResolvedURLHash                   string
	RequestURLHash                    string
	EvidenceHash                      string
	StatusCode                        int
	ErrorClass                        ErrorClass
	Capability                        CapabilityState
	Scope                             ObservationScope
	Reachable                         bool
	Final                             bool
	Success                           bool
	SemanticSeen                      bool
	NormalEndSeen                     bool
	Partial                           bool
	CandidateDisposition              CandidateDisposition
	RedactedDetail                    string
	SentAtMS                          int64
	TLSHandshakeStartAtMS             int64
	TLSHandshakeDoneAtMS              int64
	GotConnAtMS                       int64
	ResponseHeaderAtMS                int64
	FirstByteAtMS                     int64
	FirstEventAtMS                    int64
	FirstSemanticAtMS                 int64
	DoneAtMS                          int64
	RequestBytes                      int64
	ResponseBytes                     int64
	EstimatedInputTokens              int64
	ObservedInputTokens               int64
	ObservedOutputTokens              int64
	RetryAfterUntilMS                 int64
	ObservationOrder                  int64
	ExpectedCancel                    bool
	ObserverIncomplete                bool
	ObserverIncompleteReason          ObserverIncompleteReason
	ReachabilityDisposition           ApplyDisposition
	CapabilityDisposition             ApplyDisposition
	CalibrationRunID                  string
	CandidateOrdinal                  int
}

type ProbeObservation struct {
	Execution               ProbeExecution
	ReachabilityExpectation *ReachabilityExpectation
	CapabilityExpectation   *SemanticExpectation
	ReachabilityPolicy      *ReachabilityReductionPolicy
	CapabilityPolicy        *CapabilityReductionPolicy
}

type ProbeApplyResult struct {
	ExecutionStored       bool
	Reachability          ApplyDisposition
	Capability            ApplyDisposition
	CommittedReachability *UpstreamReachability
	CommittedCapability   *EndpointCapability
}

type ProbeRuntimeStats struct {
	FullObserversInFlight    int64
	FullObserverLimit        int64
	ObserverBytesInFlight    int64
	ObserverByteLimit        int64
	ObservationQueueDepth    int64
	ObservationQueueCapacity int64
	DroppedByCapacity        uint64
	DroppedByPersistence     uint64
	DroppedCandidates        uint64
}

type ProbeProfileStatus string

const (
	ProfileCandidate ProbeProfileStatus = "candidate"
	ProfileTested    ProbeProfileStatus = "tested"
	ProfileDisabled  ProbeProfileStatus = "disabled"
)

type ClientRequestShape struct {
	SafeHeaders    []HeaderTemplate
	FixedRawQuery  string
	QueryShapeJSON []byte
	BodyTemplate   []byte
	BodyShapeJSON  []byte
}

type ClientProbeProfile struct {
	ID                int64
	UpstreamID        int64
	Endpoint          EndpointKind
	Status            ProbeProfileStatus
	SafeHeaders       []HeaderTemplate
	FixedRawQuery     string
	QueryShapeJSON    []byte
	BodyTemplate      []byte
	BodyShapeJSON     []byte
	ClientFamily      string
	ShapeHash         string
	Revision          int64
	LastSeenAt        int64
	SeenCount         int64
	TestedExecutionID string
	CreatedAt         int64
	UpdatedAt         int64
}

type ProbeCostEventKind string

const (
	CostEventExecution   ProbeCostEventKind = "execution"
	CostEventPiggybackL2 ProbeCostEventKind = "piggyback_l2"
)

type ProbeCostDaily struct {
	DayUTC                string
	Trigger               ProbeTrigger
	Origin                RecipeSource
	Endpoint              EndpointKind
	RouteID               int64
	UpstreamID            int64
	Requests              int64
	Succeeded             int64
	Failed                int64
	Canceled              int64
	EstimatedInputTokens  int64
	ObservedOutputTokens  int64
	CanceledAfterSemantic int64
	PiggybackL2Saved      int64
}

type ProbeCostEvidenceV1 struct {
	Kind                  ProbeCostEventKind
	DayUTC                string
	Trigger               ProbeTrigger
	Origin                RecipeSource
	Endpoint              EndpointKind
	RouteID               int64
	UpstreamID            int64
	Requests              int64
	Succeeded             int64
	Failed                int64
	Canceled              int64
	EstimatedInputTokens  int64
	ObservedOutputTokens  int64
	CanceledAfterSemantic int64
	PiggybackL2Saved      int64
}

type CalibrationState string

const (
	CalibrationPlanned     CalibrationState = "planned"
	CalibrationRunning     CalibrationState = "running"
	CalibrationSucceeded   CalibrationState = "succeeded"
	CalibrationFailed      CalibrationState = "failed"
	CalibrationCanceled    CalibrationState = "canceled"
	CalibrationInterrupted CalibrationState = "interrupted"
)

type CalibrationCandidateState string

const (
	CalibrationCandidatePlanned       CalibrationCandidateState = "planned"
	CalibrationCandidatePrepared      CalibrationCandidateState = "prepared"
	CalibrationCandidateSendStarted   CalibrationCandidateState = "send_started"
	CalibrationCandidateFinished      CalibrationCandidateState = "finished"
	CalibrationCandidateIndeterminate CalibrationCandidateState = "indeterminate"
)

type CalibrationCandidate struct {
	Ordinal              int
	AuthMode             AuthMode
	SourceRecipe         RecipeIdentity
	MaterializedRecipe   RecipeIdentity
	State                CalibrationCandidateState
	ExecutionID          string
	Disposition          CandidateDisposition
	SendStartedAt        int64
	FinishedAt           int64
	EstimatedInputTokens int64
}

type CalibrationRun struct {
	ID         string
	RouteID    int64
	Endpoint   EndpointKind
	State      CalibrationState
	Candidates []CalibrationCandidate
	Current    int
	Selected   *CalibrationCandidate
	CreatedAt  int64
	StartedAt  int64
	FinishedAt int64
	Revision   int64
}

type CalibrationCommit struct {
	RunID                    string
	ExpectedRunRevision      int64
	CandidateOrdinal         int
	ExecutionID              string
	Endpoint                 UpstreamEndpoint
	ExpectedEndpointRevision int64
	RecipeID                 int64
	ExpectedRecipeRevision   int64
	SelectedVersionID        int64
}
