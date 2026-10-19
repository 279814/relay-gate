package model

// AttemptMetadata contains bounded facts captured for an actual send. Version 0
// means these facts were not recorded; zero revisions never mean today's config.
type AttemptMetadata struct {
	Version                    int         `json:"version"`
	ExecutionID                string      `json:"execution_id"`
	Attempt                    int         `json:"attempt"`
	Attempts                   int         `json:"attempts"`
	ConfigGeneration           uint64      `json:"config_generation"`
	SettingsRevision           int64       `json:"settings_revision"`
	EndpointID                 int64       `json:"endpoint_id"`
	EndpointRevision           int64       `json:"endpoint_revision"`
	AuthProfileRevision        int64       `json:"auth_profile_revision"`
	UpstreamNetworkRevision    int64       `json:"upstream_network_revision"`
	UpstreamCredentialRevision int64       `json:"upstream_credential_revision"`
	RouteRevision              int64       `json:"route_revision"`
	RouteCapabilityRevision    int64       `json:"route_capability_revision"`
	ModelRevision              int64       `json:"model_revision"`
	ModelCapabilityRevision    int64       `json:"model_capability_revision"`
	TransformVersionID         int64       `json:"transform_version_id"`
	RequestTransformRevision   int64       `json:"request_transform_revision"`
	ResponseHeaderAtMS         int64       `json:"response_header_at_ms"`
	FirstEventAtMS             int64       `json:"first_event_at_ms"`
	FirstSemanticAtMS          int64       `json:"first_semantic_at_ms"`
	RetryPolicy                RetryPolicy `json:"retry_policy"`
	RetryReason                string      `json:"retry_reason"`
	RequestWriteState          string      `json:"request_write_state"`
	CapabilityEffect           string      `json:"capability_effect"`
	ErrorClass                 ErrorClass  `json:"error_class"`
	Retried                    bool        `json:"retried"`
	HalfOpen                   bool        `json:"half_open"`
	DuplicateRisk              bool        `json:"duplicate_risk"`
	SyntheticCompletion        bool        `json:"synthetic_completion"`
	RequestInputHash           string      `json:"request_input_hash"`
	RequestOutputHash          string      `json:"request_output_hash"`
	RequestBodyChanged         bool        `json:"request_body_changed"`
	RequestHeadersChanged      bool        `json:"request_headers_changed"`
	RequestDiffReason          string      `json:"request_diff_reason"`
	ResponseInputHash          string      `json:"response_input_hash"`
	ResponseOutputHash         string      `json:"response_output_hash"`
	ResponseBodyChanged        bool        `json:"response_body_changed"`
	ResponseHeadersChanged     bool        `json:"response_headers_changed"`
	ResponseDiffReason         string      `json:"response_diff_reason"`
	ExecutionStored            bool        `json:"execution_stored"`
}

// UnknownAttemptMetadata does not infer historical data from current settings.
func UnknownAttemptMetadata() AttemptMetadata {
	return AttemptMetadata{RetryPolicy: "unknown", RequestWriteState: "unknown",
		CapabilityEffect: "unknown", ErrorClass: "unknown", RequestDiffReason: "unknown", ResponseDiffReason: "unknown"}
}
