package proxy

import (
	"net/http"
	"time"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/router"
)

// nextPreparedAttempt retains the current upstream response while local
// candidates fail. beforeSend releases it only when a replacement is ready;
// no extra network Attempt or concurrency lease is held for local failures.
func (h *Handler) nextPreparedAttempt(r *http.Request, pre *preambleResult,
	proto model.Protocol, plan *retryPlan, current *liveAttempt, reqID string,
	attempt int, beforeSend func()) *liveAttempt {

	candidate := h.nextCandidate(r, pre, proto, plan, current, attempt)
	var held *router.Candidate
	defer func() {
		if held != nil {
			held.Release()
		}
	}()
	for candidate != nil {
		held = candidate
		if r.Context().Err() != nil || time.Until(plan.deadline) < plan.connectCost {
			return nil
		}
		plan.tried[candidate.Route.ID] = true
		next, status := h.dispatch(r, proto, pre, candidate, reqID, attempt+1,
			time.Until(plan.deadline), beforeSend)
		if status == dispatchSent {
			held = nil // caller owns the successfully sent Attempt
			return next
		}
		held.Release()
		held = nil
		if status == dispatchFatal {
			return nil
		}
		plan.localSkips++
		if plan.localSkips >= plan.maxLocalSkips {
			return nil
		}
		var err error
		candidate, _, err = h.selectFor(pre, proto, plan.tried, false)
		if err != nil {
			return nil
		}
	}
	return nil
}
