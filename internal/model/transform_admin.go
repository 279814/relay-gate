package model

type TransformPage[T any] struct {
	Items      []T    `json:"items"`
	Total      int64  `json:"total"`
	NextCursor string `json:"next_cursor"`
	Limit      int    `json:"limit"`
}
type TransformSetFilter struct {
	PageRequest
	State, Name string
}
type TransformVersionFilter struct {
	PageRequest
	SetID int64
	Mode  string
}
type TransformBindingFilter struct {
	PageRequest
	SetID, RouteID, EndpointID, VersionID int64
	State                                 string
}
type TransformSetSummary struct {
	ID             int64  `json:"id"`
	Name           string `json:"name"`
	CreatedAt      int64  `json:"created_at"`
	Revision       int64  `json:"revision"`
	State          string `json:"state"`
	DraftVersionID int64  `json:"draft_version_id"`
	DraftRevision  int64  `json:"draft_revision"`
	HistoryCount   int64  `json:"history_count"`
}
type TransformVersionSummary struct {
	ID            int64  `json:"id"`
	SetID         int64  `json:"set_id"`
	Revision      int64  `json:"revision"`
	CreatedAt     int64  `json:"created_at"`
	Note          string `json:"note"`
	NoteTruncated bool   `json:"note_truncated"`
	Published     bool   `json:"published"`
	Shadow        bool   `json:"shadow"`
}
type TransformBindingSummary struct {
	RouteID     int64  `json:"route_id"`
	EndpointID  int64  `json:"endpoint_id"`
	SetID       int64  `json:"set_id"`
	Revision    int64  `json:"revision"`
	PublishedID int64  `json:"published_id"`
	ShadowID    int64  `json:"shadow_id"`
	State       string `json:"state"`
}
