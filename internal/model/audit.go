package model

type AuditEvent struct {
	ID           int64  `json:"id"`
	OperationID  string `json:"operation_id"`
	AtMS         int64  `json:"at_ms"`
	FinishedAtMS int64  `json:"finished_at_ms"`
	Category     string `json:"category"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	ActorHash    string `json:"actor_hash"`
	Outcome      string `json:"outcome"`
	ReasonCode   string `json:"reason_code"`
}

type AuditEventFilter struct {
	PageRequest
	Category     string
	Action       string
	Outcome      string
	ResourceType string
	ResourceID   string
	AfterMS      int64
	BeforeMS     int64
}

type AuditAction struct{ Category, ResourceType string }

// Action codes are server-owned vocabulary. Never derive them from error text,
// request bodies, administrator names, paths or credential values.
var auditActions = map[string]AuditAction{
	"master_reveal": {"credential", "master"}, "master_rotate": {"credential", "master"},
	"master_recovery":        {"credential", "master"},
	"master_rotation_backup": {"backup", "master"}, "master_rotation_rollback": {"credential", "master"},
	"relay_reveal": {"credential", "relay"}, "relay_rotate": {"credential", "relay"},
	"relay_revoke_grace": {"credential", "relay"}, "admin_reset": {"credential", "admin"},
	"sample_view": {"sample", "sample"}, "sample_pin": {"sample", "sample"},
	"sample_unpin": {"sample", "sample"}, "sample_bulk_delete": {"sample", "sample"},
	"upstream_create": {"configuration", "upstream"}, "upstream_update": {"configuration", "upstream"}, "upstream_delete": {"configuration", "upstream"},
	"model_create": {"configuration", "model_name"}, "model_update": {"configuration", "model_name"}, "model_delete": {"configuration", "model_name"},
	"route_create": {"route", "route"}, "route_update": {"route", "route"}, "route_disable": {"route", "route"}, "route_delete": {"route", "route"},
	"route_probe":     {"probe", "route"},
	"endpoint_create": {"configuration", "endpoint"}, "endpoint_update": {"configuration", "endpoint"}, "endpoint_delete": {"configuration", "endpoint"}, "endpoint_confirm_review": {"configuration", "endpoint"},
	"secret_create": {"credential", "probe_secret"}, "secret_update": {"credential", "probe_secret"}, "secret_delete": {"credential", "probe_secret"},
	"recipe_create": {"probe", "recipe"}, "recipe_version_create": {"probe", "recipe"}, "recipe_test": {"probe", "recipe_version"},
	"recipe_publish": {"probe", "recipe"}, "recipe_force_publish": {"probe", "recipe"}, "recipe_disable": {"probe", "recipe"}, "recipe_archive": {"probe", "recipe"},
	"profile_test_activate": {"probe", "client_profile"}, "profile_disable": {"probe", "client_profile"},
	"calibration_create": {"probe", "calibration"}, "calibration_start": {"probe", "calibration"}, "calibration_cancel": {"probe", "calibration"},
	"calibration_publish": {"probe", "calibration"},
	"settings_update":     {"configuration", "settings"}, "state_change": {"configuration", "state"}, "request_logs_clear": {"configuration", "request_log"},
	"security_scan": {"security", "security_scan"}, "security_canary": {"security", "security_scan"}, "security_evidence_view": {"security", "security_finding"},
	"smtp_update": {"configuration", "smtp"}, "smtp_test": {"configuration", "smtp"},
	"transform_create": {"transform", "transform"}, "transform_draft_update": {"transform", "transform"}, "transform_publish": {"transform", "transform"},
	"transform_disable": {"transform", "transform"}, "transform_enable": {"transform", "transform"}, "transform_archive": {"transform", "transform"},
	"transform_shadow": {"transform", "transform"}, "transform_rollback": {"transform", "transform"}, "transform_budget_update": {"transform", "transform"},
	"session_login": {"session", "session"}, "session_logout": {"session", "session"},
}

func AuditActionSpec(action string) (AuditAction, bool) {
	spec, ok := auditActions[action]
	return spec, ok
}

func AuditCategoryKnown(category string) bool {
	for _, spec := range auditActions {
		if spec.Category == category {
			return true
		}
	}
	return false
}

func AuditResourceKnown(resource string) bool {
	for _, spec := range auditActions {
		if spec.ResourceType == resource {
			return true
		}
	}
	return false
}

func AuditOutcomeKnown(outcome string) bool {
	return outcome == "pending" || outcome == "succeeded" || outcome == "failed" || outcome == "unknown"
}
