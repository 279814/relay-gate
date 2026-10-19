package model

// SampleMetadata deliberately has no headers, URLs, diagnostic text or bodies.
// It remains readable when an encrypted body is damaged or cannot be opened.
type SampleMetadata struct {
	ID             int64                   `json:"id"`
	ReqID          string                  `json:"req_id"`
	LegacySampleID int64                   `json:"legacy_sample_id,omitempty"`
	Endpoint       string                  `json:"endpoint"`
	ModelIn        string                  `json:"model_in"`
	TSRecv         int64                   `json:"ts_recv"`
	AttemptCount   int                     `json:"attempt_count"`
	Attempts       []SampleAttemptMetadata `json:"attempts"`
}

type SampleAttemptMetadata struct {
	ID          int64           `json:"id"`
	TSRecv      int64           `json:"ts_recv"`
	TSSent      int64           `json:"ts_sent"`
	TSFirstByte int64           `json:"ts_first_byte"`
	TSDone      int64           `json:"ts_done"`
	RouteID     int64           `json:"route_id"`
	UpstreamID  int64           `json:"upstream_id"`
	ModelNameID int64           `json:"model_name_id"`
	ModelOut    string          `json:"model_out"`
	RespStatus  int             `json:"resp_status"`
	Outcome     Outcome         `json:"outcome"`
	Metadata    AttemptMetadata `json:"metadata"`
}
