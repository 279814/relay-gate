package model

type CanarySource string

const (
	CanaryManual   CanarySource = "manual"
	CanaryPeriodic CanarySource = "periodic"
	CanaryTool                  = "relay_canary_noop"
)

func (s CanarySource) Valid() bool { return s == CanaryManual || s == CanaryPeriodic }

type CanaryPolicy struct {
	UpstreamID  int64 `json:"upstream_id"`
	RouteID     int64 `json:"route_id"`
	Enabled     bool  `json:"enabled"`
	IntervalSec int   `json:"interval_sec"`
	Revision    int64 `json:"revision"`
}

type CanaryExecution struct {
	ExecutionID        string       `json:"execution_id"`
	Source             CanarySource `json:"source"`
	PolicyRevision     int64        `json:"policy_revision"`
	ExpectationVersion int          `json:"expectation_version"`
	NonceSHA256        string       `json:"nonce_sha256"`
	ExpectedTool       string       `json:"expected_tool"`
	Verdict            string       `json:"verdict"`
	NonceMatched       *bool        `json:"nonce_matched"`
	ToolMatched        *bool        `json:"tool_matched"`
	InputUsagePresent  bool         `json:"input_usage_present"`
	OutputUsagePresent bool         `json:"output_usage_present"`
	EvidenceHash       string       `json:"evidence_hash"`
}

type CanaryCostDaily struct {
	DayUTC               string       `json:"day_utc"`
	Source               CanarySource `json:"source"`
	Endpoint             EndpointKind `json:"endpoint"`
	RouteID              int64        `json:"route_id"`
	UpstreamID           int64        `json:"upstream_id"`
	Executions           int64        `json:"executions"`
	Requests             int64        `json:"requests"`
	Passed               int64        `json:"passed"`
	Violated             int64        `json:"violated"`
	Incomplete           int64        `json:"incomplete"`
	Canceled             int64        `json:"canceled"`
	ExecutionFailed      int64        `json:"execution_failed"`
	NotSent              int64        `json:"not_sent"`
	EstimatedInputTokens int64        `json:"estimated_input_tokens"`
	ObservedOutputTokens int64        `json:"observed_output_tokens"`
	UnknownInputRows     int64        `json:"unknown_input_rows"`
	UnknownOutputRows    int64        `json:"unknown_output_rows"`
}
