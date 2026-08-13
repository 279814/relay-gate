package model

type PageRequest struct {
	Cursor string
	Limit  int
}

type Page[T any] struct {
	Items      []T
	NextCursor string
}

type UpstreamFilter struct {
	PageRequest
	Enabled   *bool
	ProbeMode ProbeMode
}

type ModelNameFilter struct {
	PageRequest
	Enabled  *bool
	Protocol Protocol
}

type RouteFilter struct {
	PageRequest
	ModelNameID int64
	UpstreamID  int64
	Enabled     *bool
}

type EndpointFilter struct {
	PageRequest
	UpstreamID  int64
	Endpoint    EndpointKind
	NeedsReview *bool
}

type ProbeSecretFilter struct {
	PageRequest
	NamePrefix string
}

type RecipeFilter struct {
	PageRequest
	UpstreamID int64
	RouteID    int64
	Endpoint   EndpointKind
	Status     RecipeStatus
}

type RecipeVersionFilter struct {
	PageRequest
	RecipeID int64
	Origin   RecipeSource
}

type ProbeExecutionFilter struct {
	PageRequest
	UpstreamID      int64
	RouteID         int64
	Endpoint        EndpointKind
	ErrorClass      ErrorClass
	Trigger         ProbeTrigger
	CapabilityState CapabilityState
}

type CapabilityFilter struct {
	PageRequest
	UpstreamID int64
	RouteID    int64
	Endpoint   EndpointKind
	State      CapabilityState
	Expired    *bool
}

type ReachabilityFilter struct {
	PageRequest
	UpstreamID int64
	State      ReachabilityState
	Current    *bool
}

type ClientProfileFilter struct {
	PageRequest
	UpstreamID   int64
	Endpoint     EndpointKind
	Status       ProbeProfileStatus
	ClientFamily string
}

type CalibrationFilter struct {
	PageRequest
	RouteID  int64
	Endpoint EndpointKind
	State    CalibrationState
}

type ProbeCostFilter struct {
	PageRequest
	DayFrom    string
	DayTo      string
	Trigger    ProbeTrigger
	Origin     RecipeSource
	Endpoint   EndpointKind
	RouteID    int64
	UpstreamID int64
}
