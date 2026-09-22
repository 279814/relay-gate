package model

// RetryPolicy 是全局请求内重试策略（§11.2）。
type RetryPolicy string

const (
	RetryPolicySafe       RetryPolicy = "safe"
	RetryPolicyBalanced   RetryPolicy = "balanced"
	RetryPolicyAggressive RetryPolicy = "aggressive"
)

// Valid reports whether p is a known policy.
func (p RetryPolicy) Valid() bool {
	switch p {
	case RetryPolicySafe, RetryPolicyBalanced, RetryPolicyAggressive:
		return true
	default:
		return false
	}
}

// Normalize returns Balanced for empty values; otherwise p unchanged.
func (p RetryPolicy) Normalize() RetryPolicy {
	if p == "" {
		return RetryPolicyBalanced
	}
	return p
}
