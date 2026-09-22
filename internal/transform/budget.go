package transform

import (
	"fmt"
	"time"
)

// Budgets returns the current execution time limits.
func (r *Registry) Budgets() BudgetLimits {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return BudgetLimits{RequestMs: r.requestMs, SSEEventMs: r.sseMs}
}

// BudgetAudits returns newest-first budget change records.
func (r *Registry) BudgetAudits(limit int) []BudgetAudit {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 || limit > len(r.budgetLog) {
		limit = len(r.budgetLog)
	}
	out := make([]BudgetAudit, limit)
	copy(out, r.budgetLog[:limit])
	return out
}

// SetBudgets updates execution budgets. Raising either limit above the current
// value requires confirmRaise=true and records a raise_budget audit (§15.3).
// Lowering never requires confirmation. Values must be positive.
func (r *Registry) SetBudgets(requestMs, sseMs int, confirmRaise bool) (BudgetLimits, error) {
	if requestMs < 1 || sseMs < 1 {
		return BudgetLimits{}, fmt.Errorf("budgets must be >= 1 ms")
	}
	// Hard ceiling prevents accidental multi-second script-like budgets.
	const maxMs = 5000
	if requestMs > maxMs || sseMs > maxMs {
		return BudgetLimits{}, fmt.Errorf("budgets must be <= %d ms", maxMs)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	raising := requestMs > r.requestMs || sseMs > r.sseMs
	if raising && !confirmRaise {
		return BudgetLimits{}, fmt.Errorf("raising transform execution budget requires confirm_raise=true")
	}
	prevReq, prevSSE := r.requestMs, r.sseMs
	r.requestMs = requestMs
	r.sseMs = sseMs
	action := "set_budget"
	if raising {
		action = "raise_budget"
	}
	ev := BudgetAudit{
		At:         time.Now().UTC(),
		Action:     action,
		Detail:     fmt.Sprintf("request_ms %d→%d sse_event_ms %d→%d", prevReq, requestMs, prevSSE, sseMs),
		RequestMs:  requestMs,
		SSEEventMs: sseMs,
		Confirmed:  raising && confirmRaise,
	}
	r.budgetLog = append([]BudgetAudit{ev}, r.budgetLog...)
	if len(r.budgetLog) > r.budgetCap {
		r.budgetLog = r.budgetLog[:r.budgetCap]
	}
	return BudgetLimits{RequestMs: r.requestMs, SSEEventMs: r.sseMs}, nil
}

func (r *Registry) requestBudget() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ms := r.requestMs
	if ms < 1 {
		ms = DefaultRequestBudgetMs
	}
	return time.Duration(ms) * time.Millisecond
}

func (r *Registry) sseBudget() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ms := r.sseMs
	if ms < 1 {
		ms = DefaultSSEBudgetMs
	}
	return time.Duration(ms) * time.Millisecond
}

// ErrBudgetExceeded is returned when apply exceeds the configured wall-clock budget.
var ErrBudgetExceeded = fmt.Errorf("transform execution budget exceeded")

func checkBudget(deadline time.Time) error {
	if time.Now().After(deadline) {
		return ErrBudgetExceeded
	}
	return nil
}
