package model

type ProbeStatisticsFilter struct {
	CanarySource CanarySource
	PageRequest
	Basis, Scope                                     string
	DayFrom, DayTo                                   string
	RouteID, UpstreamID                              int64
	Endpoint                                         EndpointKind
	Trigger                                          ProbeTrigger
	Origin                                           RecipeSource
	Storage                                          RecipeStorageKind
	RecipeID, VersionID, ProfileID, IdentityRevision int64
	TemplateID                                       string
}

type ProbeStatistic struct {
	CanarySource            CanarySource      `json:"canary_source,omitempty"`
	DayUTC                  string            `json:"day_utc"`
	ScopeID                 int64             `json:"scope_id"`
	UpstreamID              int64             `json:"upstream_id"`
	Endpoint                EndpointKind      `json:"endpoint"`
	Trigger                 ProbeTrigger      `json:"trigger"`
	Origin                  RecipeSource      `json:"origin"`
	BindingUse              string            `json:"binding_use"`
	Storage                 RecipeStorageKind `json:"storage"`
	RecipeID                int64             `json:"recipe_id"`
	VersionID               int64             `json:"version_id"`
	ProfileID               int64             `json:"profile_id"`
	TemplateID              string            `json:"template_id"`
	IdentityRevision        int64             `json:"identity_revision"`
	Executions              *int64            `json:"executions"`
	Requests                int64             `json:"requests"`
	ModelsRequests          int64             `json:"models_requests"`
	L2Requests              int64             `json:"l2_requests"`
	Succeeded               int64             `json:"succeeded"`
	Failed                  int64             `json:"failed"`
	Canceled                int64             `json:"canceled"`
	Incomplete              *int64            `json:"incomplete"`
	NotSent                 *int64            `json:"not_sent"`
	CanceledAfterSemantic   int64             `json:"canceled_after_semantic"`
	EstimatedInputTokens    *int64            `json:"estimated_input_tokens"`
	ObservedOutputTokens    *int64            `json:"observed_output_tokens"`
	UnknownInputRows        *int64            `json:"unknown_input_rows"`
	UnknownOutputRows       *int64            `json:"unknown_output_rows"`
	PiggybackL2Saved        *int64            `json:"piggyback_l2_saved"`
	CreatedTimeFallbackRows *int64            `json:"created_time_fallback_rows"`
	RecipeDenominator       *int64            `json:"recipe_denominator"`
	RecipeSuccessRate       *float64          `json:"recipe_success_rate"`
}

type ProbeStatisticsCoverage struct {
	CanarySource           string `json:"canary_source"`
	TokenPresence          string `json:"token_presence"`
	PiggybackRecipe        string `json:"piggyback_recipe"`
	RetainedExecutionsOnly bool   `json:"retained_executions_only"`
	DailyCountsLive        bool   `json:"daily_counts_live"`
	FirstDay               string `json:"first_day"`
	LastDay                string `json:"last_day"`
	CostClosedThroughDay   string `json:"cost_closed_through_day"`
	RetentionNote          string `json:"retention_note"`
	OutcomeNote            string `json:"outcome_note"`
}

type ProbeStatisticsPage struct {
	Basis          string                  `json:"basis"`
	Scope          string                  `json:"scope"`
	DayFrom        string                  `json:"day_from"`
	DayTo          string                  `json:"day_to"`
	EvaluatedAtMS  int64                   `json:"evaluated_at_ms"`
	Items          []ProbeStatistic        `json:"items"`
	TotalRows      int64                   `json:"total_rows"`
	NextCursor     string                  `json:"next_cursor"`
	PreviousCursor string                  `json:"previous_cursor"`
	Coverage       ProbeStatisticsCoverage `json:"coverage"`
}
