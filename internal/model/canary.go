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
