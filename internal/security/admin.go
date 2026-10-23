package security

import (
	"unicode/utf8"

	"github.com/279814/relay-gate/internal/model"
)

const MaximumIgnoreRules = 1024

type FindingReview struct {
	FindingID   string `json:"finding_id"`
	Status      string `json:"status"`
	Revision    int64  `json:"revision"`
	UpdatedAtMS int64  `json:"updated_at_ms"`
}

type IgnoreRule struct {
	ID          int64  `json:"id"`
	Scope       string `json:"scope"`
	RuleID      string `json:"rule_id"`
	RouteID     int64  `json:"route_id"`
	ExpiresAtMS int64  `json:"expires_at_ms"`
	Enabled     bool   `json:"enabled"`
	Revision    int64  `json:"revision"`
	CreatedAtMS int64  `json:"created_at_ms"`
	UpdatedAtMS int64  `json:"updated_at_ms"`
}

func (r IgnoreRule) Validate(nowMS int64) error {
	if r.ExpiresAtMS < 0 || r.ExpiresAtMS > 0 && r.ExpiresAtMS <= nowMS ||
		!(r.Scope == "rule" && r.RouteID == 0 && KnownRuleIdentity(r.RuleID) || r.Scope == "route" && r.RuleID == "" && r.RouteID > 0) {
		return model.WrapValidation("忽略规则必须指定单一规则或 Route；到期时间须为未来时刻或0（不过期）")
	}
	return nil
}

func KnownRuleIdentity(value string) bool {
	if !utf8.ValidString(value) || len(value) > 128 {
		return false
	}
	for _, prefix := range []string{"builtin:", "custom:"} {
		if len(value) > len(prefix) && len(value)-len(prefix) <= 64 && value[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
