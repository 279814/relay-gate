package proxy

import (
	"errors"
	"fmt"
	"time"
)

// Commit can follow a bounded Peek or local transform work. Check the original
// absolute stages synchronously; a newly started watcher may not have run yet.
func (at *Attempt) failBeforeCommit() bool {
	if at.res.HeadersSent {
		return false
	}
	var cause error
	if at.clientCtx.Err() != nil || at.ctx.Err() != nil || at.stageTimeout.Load() != 0 {
		cause = at.readFailure(nil, 0)
	} else {
		var first, last, semantic time.Time
		incomplete := false
		if at.wire != nil {
			if value := at.wire.firstByte.Load(); value != 0 {
				first = time.Unix(0, value)
			}
			if value := at.wire.lastByte.Load(); value != 0 {
				last = time.Unix(0, value)
			}
			state := at.wire.snapshot()
			semantic = state.FirstSemanticAt
			incomplete = state.Incomplete != ""
		}
		deadline, kind := at.f.Timeouts.pendingDeadline(at.res.SentAt, true, first, semantic, last, incomplete, at.resp.StatusCode)
		if !time.Now().Before(deadline) {
			at.stageTimeout.CompareAndSwap(0, kind)
			cause = at.readFailure(nil, 0)
		}
	}
	if cause == nil {
		return false
	}
	at.res.Err = cause
	at.res.DoneAt = time.Now()
	return true
}

// Local transform errors are distinct from forwarding/caller failures even
// when both return before the first client header.
func isForwardError(err error) bool {
	return errors.Is(err, ErrConnect) || errors.Is(err, ErrFirstTokenTimeout) || errors.Is(err, ErrStreamStalled) ||
		errors.Is(err, ErrTotalTimeout) || errors.Is(err, ErrUpstreamBroke) || errors.Is(err, ErrStreamBroke) ||
		errors.Is(err, ErrCanceled) || errors.Is(err, ErrClientGone)
}

const (
	responseByteTimeout int32 = iota + 1
	responseIdleTimeout
	responseSemanticTimeout
	responseHeaderTimeout
	responseTotalTimeout
)

func responseStageError(kind int32) error {
	switch kind {
	case responseIdleTimeout:
		return ErrStreamStalled
	case responseTotalTimeout:
		return ErrTotalTimeout
	case responseHeaderTimeout:
		return fmt.Errorf("%w: response_header_timeout", ErrFirstTokenTimeout)
	case responseByteTimeout:
		return fmt.Errorf("%w: first_byte_timeout", ErrFirstTokenTimeout)
	default:
		return fmt.Errorf("%w: semantic_timeout", ErrFirstTokenTimeout)
	}
}

func (to Timeouts) pendingDeadline(sentAt time.Time, headerSeen bool, firstByte, semantic, lastByte time.Time, incomplete bool, status int) (time.Time, int32) {
	deadline, kind := sentAt.Add(to.Total), responseTotalTimeout
	consider := func(enabled bool, at time.Time, cause int32) {
		if enabled && at.Before(deadline) {
			deadline, kind = at, cause
		}
	}
	consider(!headerSeen && to.ResponseHead > 0, sentAt.Add(to.ResponseHead), responseHeaderTimeout)
	consider(firstByte.IsZero() && to.FirstByte > 0, sentAt.Add(to.FirstByte), responseByteTimeout)
	if firstByte.IsZero() || !incomplete {
		consider(semantic.IsZero() && (firstByte.IsZero() || status < 400) && to.FirstSemantic > 0, sentAt.Add(to.FirstSemantic), responseSemanticTimeout)
		consider(!lastByte.IsZero() && (status >= 400 || !semantic.IsZero()) && to.Idle > 0, lastByte.Add(to.Idle), responseIdleTimeout)
	}
	return deadline, kind
}
