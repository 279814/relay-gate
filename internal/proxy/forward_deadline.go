package proxy

import (
	"fmt"
	"time"
)

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
