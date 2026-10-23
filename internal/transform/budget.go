package transform

import (
	"errors"
	"fmt"
	"time"
)

// Budgets returns the current execution time limits.
func (r *Registry) Budgets() BudgetLimits { limits, _ := r.BudgetSnapshot(); return limits }

func (r *Registry) BudgetSnapshot() (BudgetLimits, int64) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return BudgetLimits{RequestMs: r.requestMs, SSEEventMs: r.sseMs}, r.budgetRevision
}

// BudgetPersistSink uses the existing setting table revision for one fixed key.
type BudgetPersistSink interface {
	LoadTransformBudgets() (BudgetLimits, int64, error)
	SaveTransformBudgets(BudgetLimits, int64) (int64, error)
}

func (limits BudgetLimits) Validate() error {
	if limits.RequestMs < 1 || limits.SSEEventMs < 1 {
		return fmt.Errorf("budgets must be >= 1 ms")
	}
	if limits.RequestMs > 5000 || limits.SSEEventMs > 5000 {
		return fmt.Errorf("budgets must be <= 5000 ms")
	}
	return nil
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
	limits, _, err := r.setBudgets(requestMs, sseMs, confirmRaise, nil)
	return limits, err
}
func (r *Registry) SetBudgetsAtRevision(requestMs, sseMs int, confirmRaise bool, expectedRevision int64) (BudgetLimits, int64, error) {
	if expectedRevision < 1 {
		return BudgetLimits{}, 0, fmt.Errorf("expected_revision must be positive")
	}
	return r.setBudgets(requestMs, sseMs, confirmRaise, &expectedRevision)
}
func (r *Registry) setBudgets(requestMs, sseMs int, confirmRaise bool, expected *int64) (BudgetLimits, int64, error) {
	limits := BudgetLimits{RequestMs: requestMs, SSEEventMs: sseMs}
	if err := limits.Validate(); err != nil {
		return BudgetLimits{}, 0, err
	}
	r.writerMu.Lock()
	defer r.writerMu.Unlock()
	previous, revision := r.BudgetSnapshot()
	if expected != nil && *expected != revision {
		return BudgetLimits{}, 0, ErrRevisionConflict
	}
	raising := requestMs > previous.RequestMs || sseMs > previous.SSEEventMs
	if raising && !confirmRaise {
		return BudgetLimits{}, 0, fmt.Errorf("raising transform execution budget requires confirm_raise=true")
	}
	nextRevision := revision + 1
	if sink, ok := r.persist.(BudgetPersistSink); ok {
		var err error
		nextRevision, err = sink.SaveTransformBudgets(limits, revision)
		if err != nil {
			if errors.Is(err, ErrRevisionConflict) {
				return BudgetLimits{}, 0, ErrRevisionConflict
			}
			return BudgetLimits{}, 0, fmt.Errorf("%w: %w", ErrPersist, err)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requestMs, r.sseMs, r.budgetRevision = requestMs, sseMs, nextRevision
	action := "set_budget"
	if raising {
		action = "raise_budget"
	}
	event := BudgetAudit{At: time.Now().UTC(), Action: action, Detail: fmt.Sprintf("request_ms %d→%d sse_event_ms %d→%d", previous.RequestMs, requestMs, previous.SSEEventMs, sseMs), RequestMs: requestMs, SSEEventMs: sseMs, Confirmed: raising && confirmRaise}
	r.budgetLog = append([]BudgetAudit{event}, r.budgetLog...)
	if len(r.budgetLog) > r.budgetCap {
		r.budgetLog = r.budgetLog[:r.budgetCap]
	}
	return limits, nextRevision, nil
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

var budgetNow = time.Now

func checkBudget(deadline time.Time) error {
	if budgetNow().After(deadline) {
		return ErrBudgetExceeded
	}
	return nil
}
